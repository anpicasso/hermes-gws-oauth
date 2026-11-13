"""Supervise one gws Desktop OAuth login per profile/chat/sender.

The gateway hook is leased only while a child waits on its loopback callback.
Explicit callbacks pass through the model; neither path puts codes in CLI argv.

Two completion paths exist:
- Remote browser: the redirect to ``http://localhost:<port>`` fails in the
  user's browser; the user pastes that URL and the plugin forwards only the
  code to the live ``gws`` loopback server.
- Local browser (same host as Hermes): the redirect reaches the ``gws``
  loopback directly, ``gws`` exchanges the code and exits by itself. A watcher
  thread validates and commits that result; a later paste of the same URL is
  still intercepted and answered with the stored outcome.
"""
from __future__ import annotations

import asyncio
import http.client
import json
import os
import re
import secrets
import select
import shutil
import subprocess
import threading
import time
from dataclasses import dataclass, field
from pathlib import Path
from urllib.parse import parse_qs, urlsplit

if __package__:
    from .router import _commit_lock
else:  # Direct module use by the standalone test suite.
    from router import _commit_lock

_EMAIL = re.compile(r"[A-Za-z0-9][A-Za-z0-9._+%-]*@[A-Za-z0-9][A-Za-z0-9.-]*\.[A-Za-z]{2,}\Z")
_URL = re.compile(r"https://accounts\.google\.com/[^\s]+")


def _login_command(gws_bin, scope_mode, scopes):
    if scope_mode not in {"default", "readonly", "full", "custom"}:
        raise ValueError("scope_mode debe ser default, readonly, full o custom")
    if scopes is None:
        scopes = []
    if not isinstance(scopes, list) or not all(isinstance(scope, str) for scope in scopes):
        raise ValueError("scopes debe ser una lista de strings")
    if scope_mode != "custom" and scopes:
        raise ValueError("scopes solo se usa con scope_mode=custom")
    if scope_mode == "custom" and (not scopes or len(scopes) > 100 or any(
            not scope or len(scope) > 512 or "," in scope or any(char.isspace() for char in scope)
            for scope in scopes)):
        raise ValueError("scopes custom no válido")
    command = [gws_bin, "auth", "login"]
    if scope_mode in {"readonly", "full"}:
        command.append("--" + scope_mode)
    elif scope_mode == "custom":
        command.extend(("--scopes", ",".join(scopes)))
    return command


def _native_client_path(gws_bin, env):
    """Ask gws for its native client path, with the documented path as fallback."""
    fallback = Path.home() / ".config" / "gws" / "client_secret.json"
    try:
        result = subprocess.run(
            [gws_bin, "auth", "status"], env=env,
            stdout=subprocess.PIPE, stderr=subprocess.DEVNULL, timeout=10, check=False,
        )
        status = json.loads(result.stdout) if result.returncode == 0 else {}
        candidate = Path(status.get("client_config", "") if isinstance(status, dict) else "").expanduser()
        return candidate if candidate.is_absolute() else fallback
    except (OSError, ValueError, TypeError, subprocess.TimeoutExpired):
        return fallback


def _select_client(root, gws_bin, env, global_client=None):
    profile = root / "client_secret.json"
    if profile.is_symlink():
        raise ValueError(f"El cliente OAuth del perfil no puede ser un enlace simbólico: {profile}")
    if profile.exists():
        if not profile.is_file():
            raise ValueError(f"El cliente OAuth del perfil no es un archivo regular: {profile}")
        return profile

    shared = Path(global_client).expanduser() if global_client else _native_client_path(gws_bin, env)
    if shared.is_symlink():
        raise ValueError(f"El cliente OAuth global de gws no puede ser un enlace simbólico: {shared}")
    if shared.is_file():
        return shared
    raise ValueError(
        f"Falta client_secret.json Desktop: instala el override del perfil en {profile} "
        f"o configura el cliente global de gws en {shared}."
    )



def _remove_path(path):
    if path.is_symlink() or path.is_file():
        path.unlink(missing_ok=True)
    else:
        shutil.rmtree(path, ignore_errors=True)


class LoginError(RuntimeError):
    """Login failure with a stable, secret-free reason code."""

    def __init__(self, reason, message=""):
        super().__init__(message or reason)
        self.reason = reason


_REASON_HINTS = {
    "invalid_callback": "la URL pegada no es el callback localhost de este login",
    "expired": "el plazo del login venció",
    "callback_rejected": "gws no aceptó el callback local",
    "gws_failed": "gws terminó sin guardar credenciales (código rechazado o consentimiento cancelado)",
    "identity_unconfirmed": "gws no devolvió la identidad de la cuenta",
    "identity_mismatch": "la cuenta Google autorizada no es la solicitada",
    "account_exists": "la cuenta ya estaba registrada; usa reauthorize=true",
    "commit_failed": "no se pudieron guardar las credenciales en el perfil",
}


def _failure_message(reason):
    hint = _REASON_HINTS.get(reason, "error interno")
    return f"no se pudo completar el login ({reason}: {hint}). Inicia uno nuevo; no repitas el enlace."


def _install_attempt(attempt, destination, accounts):
    """Install validated credentials, replacing the old account only on success."""
    with _commit_lock(accounts):
        if time.monotonic() >= attempt.deadline:
            raise LoginError("expired", "El login venció antes de guardar las credenciales")
        if destination.exists() or destination.is_symlink():
            if destination.is_symlink() or not destination.is_dir():
                raise LoginError("commit_failed", "La ruta de la cuenta existente no es un directorio válido")
            if not attempt.reauthorize:
                raise LoginError("account_exists", "La cuenta ya estaba registrada")
            backup = accounts / f".{destination.name}.backup-{secrets.token_hex(6)}"
            os.rename(destination, backup)
            try:
                os.rename(attempt.directory, destination)
            except BaseException:
                os.rename(backup, destination)
                raise
            _remove_path(backup)
        else:
            os.rename(attempt.directory, destination)


@dataclass
class _Attempt:
    process: subprocess.Popen
    directory: Path
    redirect: str
    account: str
    deadline: float
    reauthorize: bool = False
    timer: threading.Timer | None = None
    watcher: threading.Thread | None = None
    processing: bool = False
    expired: bool = False
    finished: bool = False
    result: dict | None = None
    done: threading.Event = field(default_factory=threading.Event)
    lock: threading.RLock = field(default_factory=threading.RLock)


class LoginManager:
    def __init__(self):
        self._lock = threading.RLock()
        self._attempts: dict[tuple[str, str, str, str, str], _Attempt] = {}
        self._hook = None

    @staticmethod
    def _key(root, platform, chat_id, user_id, profile=""):
        return (str(Path(root).resolve()), str(platform), str(chat_id), str(user_id), str(profile or ""))

    def has_pending(self, root, platform, chat_id, user_id):
        with self._lock:
            return self._key(root, platform, chat_id, user_id) in self._attempts

    @staticmethod
    def _authorization_url(proc, timeout=25):
        end = time.monotonic() + timeout
        data = bytearray()
        while time.monotonic() < end and len(data) < 16384:
            if proc.poll() is not None:
                break
            ready, _, _ = select.select([proc.stdout], [], [], min(0.2, end - time.monotonic()))
            if ready:
                chunk = os.read(proc.stdout.fileno(), 4096)
                if not chunk:
                    break
                data.extend(chunk)
                decoded = data.decode("utf-8", "replace")
                if match := _URL.search(decoded):
                    if match.end() < len(decoded) and decoded[match.end()].isspace():
                        return match.group(0).rstrip(".,)")
        raise RuntimeError("gws no produjo una URL OAuth")

    def start(self, root, platform, chat_id, user_id, account, gws_bin, register_hook, *,
              timeout: float = 300, profile="", scope_mode="full", scopes=None, global_client=None,
              reauthorize=False):
        root = Path(root).expanduser().resolve()
        if not isinstance(reauthorize, bool):
            return {"ok": False, "error": "reauthorize debe ser un booleano."}
        key = self._key(root, platform, chat_id, user_id, profile)
        if not platform or not chat_id or not user_id:
            return {"ok": False, "error": "Esta sesión necesita una identidad estable para completar OAuth."}
        if not _EMAIL.fullmatch(account or ""):
            return {"ok": False, "error": "Indica el correo exacto de la cuenta Google."}
        if not 0 < timeout <= 900:
            return {"ok": False, "error": "Plazo de OAuth no válido."}
        with self._lock:
            existing = self._attempts.get(key)
            if existing is not None and existing.finished:
                # Outcome of a login that gws completed by itself (local browser)
                # or that failed without a paste: hand it over exactly once.
                self._remove(key, existing)
                if existing.account == account.lower() and existing.result is not None:
                    return dict(existing.result, consumed=True)
            elif existing is not None:
                return {"ok": False, "pending": True, "account": existing.account,
                        "error": "Ya hay un login pendiente en este chat. Si el navegador ya mostró "
                                 "'Success', vuelve a llamar gws_login con el mismo account (sin callback_url) "
                                 "para leer el resultado; si no, pega la URL localhost o espera a que venza."}
        try:
            command = _login_command(gws_bin, scope_mode, scopes)
        except ValueError as exc:
            return {"ok": False, "error": str(exc)}
        env = {k: v for k, v in os.environ.items()
               if not k.startswith("GOOGLE_WORKSPACE_CLI_") and k != "GOOGLE_APPLICATION_CREDENTIALS"}
        try:
            client = _select_client(root, gws_bin, env, global_client)
        except ValueError as exc:
            return {"ok": False, "error": str(exc)}
        destination = root / "accounts" / account.lower()
        if destination.exists() or destination.is_symlink():
            if destination.is_symlink() or not destination.is_dir():
                return {"ok": False, "error": "La ruta de la cuenta existente no es un directorio válido."}
            if not reauthorize:
                return {"ok": False, "error": "La cuenta ya está configurada en este perfil. Usa reauthorize=true para renovarla sin tocar las credenciales actuales hasta confirmar la nueva identidad."}
        with self._lock:
            if key in self._attempts:
                return {"ok": False, "pending": True, "error": "Ya hay un login pendiente en este chat."}
            pending_root = root / ".pending"
            pending_root.mkdir(parents=True, exist_ok=True, mode=0o700)
            directory = pending_root / secrets.token_hex(12)
            directory.mkdir(mode=0o700)
            target = directory / "client_secret.json"
            target.write_bytes(client.read_bytes())
            target.chmod(0o600)
            env["GOOGLE_WORKSPACE_CLI_CONFIG_DIR"] = str(directory)
            env["GOOGLE_WORKSPACE_CLI_KEYRING_BACKEND"] = "file"
            try:
                proc = subprocess.Popen(
                    command,
                    env=env, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, bufsize=0,
                )
                url = self._authorization_url(proc)
                redirect = parse_qs(urlsplit(url).query).get("redirect_uri", [""])[0]
                parsed = urlsplit(redirect)
                if parsed.scheme != "http" or parsed.hostname != "localhost" or not parsed.port or parsed.path not in ("", "/"):
                    raise ValueError("gws devolvió un redirect inesperado")
                attempt = _Attempt(
                    proc, directory, redirect, account.lower(), time.monotonic() + timeout,
                    reauthorize=reauthorize,
                )
                self._attempts[key] = attempt
                if register_hook is not None and (self._hook is None or not self._hook.active):
                    self._hook = register_hook(self.on_message)
                timer = threading.Timer(timeout, self._expire, args=(key, attempt))
                timer.daemon = True
                attempt.timer = timer
                timer.start()
                watcher = threading.Thread(target=self._watch_process, args=(key, attempt), daemon=True)
                attempt.watcher = watcher
                watcher.start()
                return {"ok": True, "url": url, "account": account.lower(), "timeout_seconds": timeout,
                        "instructions": (
                            "Abre el enlace y acepta los permisos con esa cuenta. "
                            "Si el navegador corre en la misma máquina que Hermes verás 'Success' y la cuenta "
                            "queda registrada sola: confírmalo con gws_accounts o llamando gws_login de nuevo "
                            "con el mismo account. Si el navegador muestra un error de conexión en localhost, "
                            "pega aquí la URL localhost completa de la barra de direcciones (con o sin http://)."
                        )}
            except (OSError, ValueError, RuntimeError, TypeError):
                self._attempts.pop(key, None)
                if not self._attempts and self._hook is not None:
                    self._hook.dispose()
                    self._hook = None
                if "proc" in locals():
                    self._terminate(proc)
                shutil.rmtree(directory, ignore_errors=True)
                return {"ok": False, "error": "No se pudo iniciar gws auth login; revisa el binario y el cliente OAuth."}

    @staticmethod
    def _terminate(proc):
        if proc.poll() is None:
            proc.terminate()
            try:
                proc.wait(timeout=2)
            except subprocess.TimeoutExpired:
                proc.kill()
                proc.wait(timeout=2)
        if proc.stdout is not None:
            proc.stdout.close()

    def _remove(self, key, attempt):
        with self._lock:
            if self._attempts.get(key) is not attempt:
                return
            self._attempts.pop(key)
            if attempt.timer:
                attempt.timer.cancel()
            if not self._attempts and self._hook is not None:
                self._hook.dispose()
                self._hook = None

    def _expire(self, key, attempt, *, finished=False):
        """Deadline/unload/completion cleanup; an exchange in flight owns its own cleanup."""
        with attempt.lock:
            attempt.expired = True
            in_flight = attempt.processing and not attempt.finished and not finished
        if in_flight and attempt.process.poll() is not None:
            # The exchange thread is reading the output of a process that already
            # exited (local browser); closing its stdout here would corrupt that read.
            return
        self._terminate(attempt.process)
        if in_flight:
            return
        self._remove(key, attempt)
        shutil.rmtree(attempt.directory, ignore_errors=True)

    def close(self):
        with self._lock:
            pending = list(self._attempts.items())
        for key, attempt in pending:
            self._expire(key, attempt)
            self._remove(key, attempt)

    def _watch_process(self, key, attempt):
        """Commit a login that gws completed by itself (browser on the Hermes host)."""
        try:
            attempt.process.wait()
        except Exception:
            return
        with attempt.lock:
            if attempt.expired or attempt.processing or attempt.finished:
                return  # terminated by the plugin, or a pasted callback drives the exchange
            attempt.processing = True
        result = self._run_exchange(key, attempt, None, local=True)
        if not result["ok"]:
            shutil.rmtree(attempt.directory, ignore_errors=True)
        with attempt.lock:
            attempt.finished = True
            attempt.result = result
            attempt.done.set()
            expired = attempt.expired
        if expired:
            self._remove(key, attempt)
        # Otherwise stay registered until the deadline, a pasted callback or a
        # gws_login status call hands the stored outcome over exactly once.

    @staticmethod
    def _fetch_and_commit(attempt, code, root):
        """Forward the code (if the loopback is still up), then validate and commit."""
        process = attempt.process
        if code is not None and process.poll() is None:
            port = urlsplit(attempt.redirect).port
            status = None
            try:
                conn = http.client.HTTPConnection("127.0.0.1", port, timeout=3)
                try:
                    conn.request("GET", "/?code=" + code)
                    response = conn.getresponse()
                    response.read()
                    status = response.status
                finally:
                    conn.close()
            except OSError:
                status = None
            if status != 200:
                # The loopback may be gone because the browser already reached it;
                # accept that only if gws then finishes on its own.
                try:
                    process.wait(timeout=5)
                except subprocess.TimeoutExpired:
                    raise LoginError("callback_rejected") from None
        remaining = max(0.1, attempt.deadline - time.monotonic())
        try:
            out, _ = process.communicate(timeout=remaining)
        except subprocess.TimeoutExpired:
            raise LoginError("expired") from None
        if process.returncode != 0 or not (attempt.directory / "credentials.enc").is_file():
            raise LoginError("gws_failed")
        text = out.decode("utf-8", "replace")
        try:
            result, _ = json.JSONDecoder().raw_decode(text[text.index("{"):])
        except (ValueError, KeyError):
            raise LoginError("identity_unconfirmed") from None
        if not isinstance(result, dict) or str(result.get("account", "")).lower() != attempt.account:
            raise LoginError("identity_mismatch")
        accounts = root / "accounts"
        accounts.mkdir(mode=0o700, parents=True, exist_ok=True)
        destination = accounts / attempt.account
        with attempt.lock:
            if attempt.expired or time.monotonic() >= attempt.deadline:
                raise LoginError("expired")
            try:
                _install_attempt(attempt, destination, accounts)
            except LoginError:
                raise
            except OSError as exc:
                raise LoginError("commit_failed") from exc
        return attempt.account

    def _run_exchange(self, key, attempt, code, *, local=False):
        """Run the exchange for one attempt; never raises, never echoes the code."""
        try:
            if time.monotonic() >= attempt.deadline:
                raise LoginError("expired")
            account = self._fetch_and_commit(attempt, code, Path(key[0]))
            via = " (completado desde el navegador local)" if local else ""
            return {"ok": True, "account": account, "local_browser": local,
                    "message": f"[Google Workspace: {account} autorizada en este perfil; credenciales guardadas{via}. Verifica con gws_accounts y gws_api.]"}
        except LoginError as exc:
            return {"ok": False, "reason": exc.reason, "local_browser": local, "error": _failure_message(exc.reason)}
        except Exception:
            return {"ok": False, "reason": "internal", "local_browser": local, "error": _failure_message("internal")}

    def finish(self, root, platform, chat_id, user_id, account, callback_url, *, profile=""):
        """Complete a login explicitly on any surface, bound to its original identity."""
        key = self._key(root, platform, chat_id, user_id, profile)
        with self._lock:
            attempt = self._attempts.get(key)
        if attempt is None or not isinstance(account, str) or account.lower() != attempt.account:
            return {"ok": False, "error": "No hay un login pendiente para esta cuenta en esta sesión."}
        try:
            if not isinstance(callback_url, str) or len(callback_url) > 8192:
                raise ValueError("Callback inválido")
            text = callback_url.strip()
            if text.startswith("localhost:"):
                text = "http://" + text
            parsed = urlsplit(text)
            redirect = urlsplit(attempt.redirect)
            if (parsed.scheme != "http" or parsed.hostname != "localhost" or
                    parsed.port != redirect.port or (parsed.path or "/") != (redirect.path or "/")):
                raise ValueError("Callback inválido")
        except ValueError:
            return {"ok": False, "reason": "invalid_callback",
                    "error": "URL de callback inválida; copia la URL localhost completa de este login."}
        # ponytail: explicit completion uses normal tool arguments, not another ingress hook.
        return self._complete_callback(key, attempt, parsed)

    def _take_result(self, key, attempt):
        """Hand a locally completed outcome over once and release the attempt."""
        with self._lock, attempt.lock:
            if not attempt.finished or attempt.result is None:
                return None
            self._remove(key, attempt)
            return dict(attempt.result)

    def _complete_callback(self, key, attempt, parsed):
        with self._lock, attempt.lock:
            if attempt.finished:
                return self._take_result(key, attempt) or {"ok": False, "reason": "in_progress",
                                                           "error": "La autorización ya se está procesando."}
            waiting = attempt.processing
            if not waiting:
                attempt.processing = True
        if waiting:
            # The watcher is validating a login that the local browser already
            # completed; report its outcome instead of racing it.
            attempt.done.wait(timeout=max(0.1, attempt.deadline - time.monotonic()) + 5)
            return self._take_result(key, attempt) or {"ok": False, "reason": "in_progress",
                                                       "error": "La autorización ya se está procesando."}
        try:
            try:
                query = parse_qs(parsed.query, strict_parsing=True)
            except ValueError:
                raise LoginError("invalid_callback") from None
            code = query.get("code", [])
            if parsed.username or parsed.password or parsed.fragment or len(code) != 1 or not code[0] or not re.fullmatch(r"[A-Za-z0-9_./~-]{1,2048}", code[0]):
                raise LoginError("invalid_callback")
        except LoginError as exc:
            result = {"ok": False, "reason": exc.reason, "error": _failure_message(exc.reason)}
        else:
            result = self._run_exchange(key, attempt, code[0])
        with attempt.lock:
            attempt.finished = True
            attempt.result = result
            attempt.done.set()
        self._expire(key, attempt, finished=True)
        return result

    async def on_message(self, event, **kwargs):
        source = event.source
        platform = getattr(getattr(source, "platform", None), "value", None)
        with self._lock:
            matching = [(key, attempt) for key, attempt in self._attempts.items()
                        if key[1:4] == (str(platform), str(source.chat_id), str(source.user_id))]
        if not matching:
            return None
        text = str(event.text or "").strip()
        if text.startswith("localhost:"):
            text = "http://" + text
        elif not text.startswith("http://localhost:"):
            return None
        if len(text) > 8192:
            return {"action": "rewrite", "text": "[Google Workspace: URL de callback demasiado larga; inicia un nuevo login.]"}
        try:
            parsed = urlsplit(text)
            port = parsed.port
        except ValueError:
            return {"action": "rewrite", "text": "[Google Workspace: URL de callback inválida; vuelve a copiarla.]"}
        with self._lock:
            own_port = [(key, a) for key, a in matching if
                        key[4] == str(getattr(source, "profile", "") or "") and
                        parsed.scheme == "http" and parsed.hostname == "localhost" and
                        port == urlsplit(a.redirect).port]
            if not own_port:
                return None
            matches = [(key, a) for key, a in own_port if
                       (parsed.path or "/") == (urlsplit(a.redirect).path or "/")]
            if not matches:
                return {"action": "rewrite", "text": "[Google Workspace: ruta de callback incorrecta; vuelve a copiarla.]"}
            key, attempt = matches[0]
        # Every recognised callback is rewritten, including all errors. Never log the URL.
        try:
            result = await asyncio.to_thread(self._complete_callback, key, attempt, parsed)
            message = result.get("message") or f"[Google Workspace: {result['error']}]"
        except (Exception, asyncio.CancelledError):
            message = f"[Google Workspace: {_failure_message('internal')}]"
        gateway = kwargs.get("gateway")
        message_id = str(getattr(source, "message_id", "") or getattr(event, "message_id", "") or "")
        if gateway is not None and message_id:
            try:
                adapter = gateway._delivery_adapter_for(source)
                if adapter is not None:
                    await asyncio.wait_for(adapter.delete_message(str(source.chat_id), message_id), timeout=2)
            except (Exception, asyncio.CancelledError):
                pass  # Best-effort platform deletion, not a security guarantee.
        return {"action": "rewrite", "text": message}
