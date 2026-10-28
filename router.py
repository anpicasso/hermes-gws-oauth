"""Run gws using exactly one account under the current Hermes profile."""
from __future__ import annotations
import json
import os
import re
import subprocess
import tempfile
from contextlib import suppress
from pathlib import Path
from contextlib import contextmanager
import threading

try:  # POSIX
    import fcntl
except ImportError:  # pragma: no cover - Windows
    fcntl = None
try:  # Windows
    import msvcrt
except ImportError:  # pragma: no cover - POSIX
    msvcrt = None

_COMMIT_THREAD_LOCK = threading.Lock()

@contextmanager
def _commit_lock(accounts):
    """Serialize native calls and account swaps across threads and processes.

    ponytail: profile file lock plus global thread lock; use per-account locks
    if contention is measurable. Native calls hold the lock until completion.
    """
    accounts.mkdir(mode=0o700, parents=True, exist_ok=True)
    fd = os.open(accounts / ".lock", os.O_CREAT | os.O_RDWR, 0o600)
    with _COMMIT_THREAD_LOCK:
        try:
            if fcntl is not None:
                fcntl.flock(fd, fcntl.LOCK_EX)
            elif msvcrt is not None:  # pragma: no cover - Windows
                os.lseek(fd, 0, os.SEEK_SET)
                if os.fstat(fd).st_size == 0:
                    os.write(fd, b"\0")
                msvcrt.locking(fd, msvcrt.LK_LOCK, 1)  # type: ignore[attr-defined]
            yield
        finally:
            if fcntl is not None:
                fcntl.flock(fd, fcntl.LOCK_UN)
            elif msvcrt is not None:  # pragma: no cover - Windows
                os.lseek(fd, 0, os.SEEK_SET)
                msvcrt.locking(fd, msvcrt.LK_UNLCK, 1)  # type: ignore[attr-defined]
            os.close(fd)


_ACCOUNT = re.compile(r"[A-Za-z0-9][A-Za-z0-9@._+-]{0,127}\Z")
_HTTP_STATUS = re.compile(r'"code"\s*:\s*(\d{3})')
_HEALTH_TIMEOUT = 20

# ponytail: fixed allowlist of native signals; never echo gws output, which may
# contain request bodies, paths, or token fragments.
_PERMISSION_MARKERS = (
    "permission_denied", "insufficientpermissions", "insufficient_permissions",
    "access_token_scope_insufficient", "accessnotconfigured", "service_disabled",
    "api is not enabled", "has not been used in project",
)


def account_dir(root, account):
    if not isinstance(account, str) or not _ACCOUNT.fullmatch(account) or account in (".", ".."):
        raise ValueError("Invalid account name")
    base = Path(root).resolve() / "accounts"
    path = base / account
    if path.is_symlink() or not path.is_dir() or path.resolve().parent != base.resolve():
        raise ValueError("Account is not registered in this profile")
    if not any((path / name).is_file() for name in ("credentials.enc", "credentials.json")):
        raise ValueError("Account is not registered in this profile")
    return path


def list_accounts(root):
    base = Path(root).resolve() / "accounts"
    if not base.is_dir():
        return []
    names = []
    for path in base.iterdir():
        try:
            account_dir(root, path.name)
        except ValueError:
            continue
        names.append(path.name)
    return sorted(names)


def _account_env(path):
    env = {key: val for key, val in os.environ.items()
           if not key.startswith("GOOGLE_WORKSPACE_CLI_") and key != "GOOGLE_APPLICATION_CREDENTIALS"}
    env["GOOGLE_WORKSPACE_CLI_CONFIG_DIR"] = str(path)
    env["GOOGLE_WORKSPACE_CLI_KEYRING_BACKEND"] = "file"
    return env


def _failure(code, message, action, *, category, reauth_required, returncode):
    return {
        "error_code": code,
        "category": category,
        "error": message,
        "action": action,
        "reauth_required": reauth_required,
        "exit_code": returncode,
    }


def classify_gws_failure(returncode, stdout="", stderr=""):
    """Map a native gws failure to a fixed, actionable message.

    Raw stdout/stderr are inspected only for known signals and are never
    returned: they can contain request bodies, file paths, or token fragments.
    """
    text = (stdout + "\n" + stderr).lower()
    if returncode == 3:
        return _failure(
            "invalid_arguments",
            "gws rechazó los argumentos (sintaxis o validación); revisa el comando y sus opciones.",
            "check_args", category="syntax", reauth_required=False, returncode=returncode,
        )
    if re.search(r"\binvalid_rapt\b", text):
        return _failure(
            "invalid_rapt",
            "Google exige reautenticar la cuenta (invalid_rapt); usa gws_login con reauthorize=true.",
            "reauthorize", category="auth", reauth_required=True, returncode=returncode,
        )
    if re.search(r"\binvalid_grant\b", text):
        return _failure(
            "invalid_grant",
            "La autorización de Google ya no es válida (invalid_grant); usa gws_login con reauthorize=true.",
            "reauthorize", category="auth", reauth_required=True, returncode=returncode,
        )
    if any(marker in text for marker in _PERMISSION_MARKERS):
        return _failure(
            "permission_denied",
            "Google denegó el permiso; revisa los scopes concedidos y que la API necesaria esté habilitada.",
            "check_scopes_or_api", category="permission", reauth_required=False, returncode=returncode,
        )
    status_match = _HTTP_STATUS.search(stdout)
    status = int(status_match.group(1)) if status_match else None
    if status == 401:
        return _failure(
            "unauthenticated",
            "Google rechazó la autenticación (HTTP 401); reautoriza la cuenta.",
            "reauthorize", category="auth", reauth_required=True, returncode=returncode,
        )
    if status == 403:
        return _failure(
            "permission_denied",
            "Google denegó el permiso (HTTP 403); revisa los scopes concedidos y que la API necesaria esté habilitada.",
            "check_scopes_or_api", category="permission", reauth_required=False, returncode=returncode,
        )
    if returncode == 2:
        return _failure(
            "auth_unavailable",
            "gws no pudo autenticar; comprueba el estado de la cuenta y la conectividad antes de reautorizar.",
            "check_account_health", category="auth", reauth_required=False, returncode=returncode,
        )
    if returncode == 1:
        suffix = f" (HTTP {status})" if status else ""
        return _failure(
            "api_error",
            f"gws devolvió un error de API{suffix}; revisa los argumentos y el recurso solicitado.",
            "check_request", category="api", reauth_required=False, returncode=returncode,
        )
    if returncode == 4:
        return _failure(
            "discovery_error",
            "No se pudo cargar el esquema de la API de Google; revisa la red o reintenta.",
            "retry_or_check_network", category="discovery", reauth_required=False, returncode=returncode,
        )
    if returncode == 5:
        return _failure(
            "internal_error",
            "gws falló internamente; reintenta la operación.",
            "retry", category="internal", reauth_required=False, returncode=returncode,
        )
    return _failure(
        "gws_error",
        f"gws terminó con estado {returncode}; no se pudo clasificar el error.",
        "inspect_native_gws", category="unknown", reauth_required=False, returncode=returncode,
    )


def account_health(root, account, *, gws_bin="gws", timeout=_HEALTH_TIMEOUT):
    """Ask native gws whether stored credentials still authenticate.

    The plugin never decrypts credentials and never refreshes tokens itself;
    gws owns that behavior. Output is reduced to fixed states and messages.
    """
    try:
        with _commit_lock(Path(root).resolve() / "accounts"):
            path = account_dir(root, account)
            result = subprocess.run(
                [gws_bin, "auth", "status"], env=_account_env(path),
                capture_output=True, text=True, timeout=timeout,
            )
    except subprocess.TimeoutExpired:
        return {"stored": True, "valid": None, "state": "stored", "reauth_required": False,
                "detail": "gws auth status tardó demasiado; la sesión no se validó en vivo."}
    except OSError:
        return {"stored": True, "valid": None, "state": "stored", "reauth_required": False,
                "detail": "No se pudo ejecutar gws auth status; la sesión no se validó en vivo."}
    if result.returncode:
        failure = classify_gws_failure(result.returncode, result.stdout, result.stderr)
        invalid = bool(failure["reauth_required"])
        return {"stored": True, "valid": False if invalid else None,
                "state": "invalid" if invalid else "stored",
                "reauth_required": invalid,
                "detail": failure["error"], "error_code": failure["error_code"],
                "action": failure["action"]}
    try:
        status = json.loads(result.stdout)
    except (json.JSONDecodeError, TypeError):
        status = None
    if not isinstance(status, dict):
        return {"stored": True, "valid": None, "state": "stored", "reauth_required": False,
                "detail": "gws auth status no devolvió un estado legible; la sesión no se validó en vivo."}
    email = status.get("email")
    if isinstance(email, str) and email and email.lower() != account.lower():
        return {"stored": True, "valid": False, "state": "invalid", "reauth_required": True,
                "detail": "gws tiene credenciales de otra identidad; reautoriza esta cuenta.",
                "error_code": "identity_mismatch", "action": "reauthorize"}
    if status.get("credentials_readable") is False:
        return {"stored": True, "valid": False, "state": "unreadable", "reauth_required": True,
                "detail": "Las credenciales guardadas no se pueden leer; reautoriza esta cuenta.",
                "error_code": "credentials_unreadable", "action": "reauthorize"}
    token_valid = status.get("token_valid")
    if token_valid is True:
        return {"stored": True, "valid": True, "state": "valid", "reauth_required": False,
                "detail": "gws confirmó una sesión válida."}
    if status.get("token_error"):
        failure = classify_gws_failure(2, json.dumps(status["token_error"]))
        invalid = failure["reauth_required"]
        return {"stored": True, "valid": False if invalid else None,
                "state": "invalid" if invalid else "stored", "reauth_required": invalid,
                "detail": failure["error"], "error_code": failure["error_code"],
                "action": failure["action"]}
    if token_valid is False:
        return {"stored": True, "valid": False, "state": "invalid", "reauth_required": True,
                "detail": "gws informó que la sesión no es válida; reautoriza esta cuenta.",
                "error_code": "token_invalid", "action": "reauthorize"}
    if status.get("auth_method") == "none":
        return {"stored": True, "valid": False, "state": "invalid", "reauth_required": True,
                "detail": "gws no reconoce una sesión en esta cuenta; reautoriza esta cuenta.",
                "error_code": "auth_missing", "action": "reauthorize"}
    return {"stored": True, "valid": None, "state": "stored", "reauth_required": False,
            "detail": "Credenciales presentes; gws auth status no confirmó una sesión válida."}


def execute_gws(root, account, args, *, gws_bin="gws"):
    if not isinstance(args, list) or not all(isinstance(x, str) for x in args):
        raise ValueError("args must be a list of strings")
    try:
        with _commit_lock(Path(root).resolve() / "accounts"):
            path = account_dir(root, account)
            result = subprocess.run(
                [gws_bin, *args], env=_account_env(path),
                capture_output=True, text=True, timeout=90,
            )
    except (OSError, subprocess.TimeoutExpired):
        return {"ok": False, "error": "gws no está disponible o tardó demasiado"}
    if result.returncode:
        return {"ok": False, **classify_gws_failure(result.returncode, result.stdout, result.stderr)}
    if len(result.stdout) > 200_000:
        # ponytail: spill only large successes; native stdout is still buffered in memory.
        directory = output = None
        try:
            directory = Path(tempfile.mkdtemp(prefix="response-", dir=Path(root).resolve()))
            output = directory / "stdout.txt"
            with output.open("x", encoding="utf-8") as handle:
                os.chmod(output, 0o600)
                handle.write(result.stdout)
            return {"ok": True, "account": account, "output_file": str(output),
                    "output_bytes": output.stat().st_size, "output_encoding": "utf-8",
                    "detail": "Salida completa guardada localmente; léela con código. Si es un adjunto Gmail, decodifica el campo JSON data como base64url. Elimina el archivo y su directorio al terminar."}
        except OSError:
            if output is not None:
                with suppress(OSError):
                    output.unlink()
            if directory is not None:
                with suppress(OSError):
                    directory.rmdir()
            return {"ok": False, "error_code": "output_write_failed",
                    "error": "gws terminó correctamente, pero no se pudo guardar la salida grande. Revisa el espacio y permisos locales; no repitas una escritura remota sin comprobarla."}
    try:
        data = json.loads(result.stdout)
    except json.JSONDecodeError:
        data = result.stdout.strip()
    return {"ok": True, "account": account, "data": data}
