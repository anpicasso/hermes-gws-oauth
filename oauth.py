"""Supervise one gws Desktop OAuth login per profile/chat/sender.

The gateway hook is leased only while a child waits on its loopback callback.
Explicit callbacks pass through the model; neither path puts codes in CLI argv.
"""
from __future__ import annotations

import asyncio
import http.client
import json
import os
import re
import select
import shutil
import subprocess
import threading
import time
from dataclasses import dataclass, field
from pathlib import Path
from urllib.parse import parse_qs, urlsplit

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


@dataclass
class _Attempt:
    process: subprocess.Popen
    directory: Path
    redirect: str
    account: str
    deadline: float
    timer: threading.Timer | None = None
    processing: bool = False
    expired: bool = False
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
              timeout=300, profile="", scope_mode="full", scopes=None, global_client=None):
        root = Path(root).expanduser().resolve()
        key = self._key(root, platform, chat_id, user_id, profile)
        if not platform or not chat_id or not user_id:
            return {"ok": False, "error": "Esta sesión necesita una identidad estable para completar OAuth."}
        if not _EMAIL.fullmatch(account or ""):
            return {"ok": False, "error": "Indica el correo exacto de la cuenta Google."}
        if not 0 < timeout <= 900:
            return {"ok": False, "error": "Plazo de OAuth no válido."}
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
        if (root / "accounts" / account.lower()).exists():
            return {"ok": False, "error": "La cuenta ya está configurada en este perfil."}
        with self._lock:
            if key in self._attempts:
                return {"ok": False, "error": "Ya hay un login pendiente en este chat."}
            pending_root = root / ".pending"
            pending_root.mkdir(parents=True, exist_ok=True, mode=0o700)
            import secrets
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
                attempt = _Attempt(proc, directory, redirect, account.lower(), time.monotonic() + timeout)
                self._attempts[key] = attempt
                if register_hook is not None and (self._hook is None or not self._hook.active):
                    self._hook = register_hook(self.on_message)
                timer = threading.Timer(timeout, self._expire, args=(key, attempt))
                timer.daemon = True
                attempt.timer = timer
                timer.start()
                return {"ok": True, "url": url, "account": account.lower(), "timeout_seconds": timeout,
                        "instructions": "Abre el enlace, acepta los permisos y pega aquí la URL localhost completa que aparezca tras el error del navegador; puede venir con o sin http://."}
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
        with attempt.lock:
            attempt.expired = True
            processing = attempt.processing and not finished
        self._terminate(attempt.process)
        if not processing:
            self._remove(key, attempt)
            shutil.rmtree(attempt.directory, ignore_errors=True)

    def close(self):
        with self._lock:
            pending = list(self._attempts.items())
        for key, attempt in pending:
            self._expire(key, attempt)

    @staticmethod
    def _fetch_and_commit(attempt, code, root):
        port = urlsplit(attempt.redirect).port
        conn = http.client.HTTPConnection("127.0.0.1", port, timeout=3)
        try:
            conn.request("GET", "/?code=" + code)
            response = conn.getresponse()
            response.read()
            if response.status != 200:
                raise RuntimeError("El callback local fue rechazado")
        finally:
            conn.close()
        remaining = max(0.1, attempt.deadline - time.monotonic())
        out, _ = attempt.process.communicate(timeout=remaining)
        if attempt.process.returncode != 0 or not (attempt.directory / "credentials.enc").is_file():
            raise RuntimeError("gws no guardó credenciales")
        text = out.decode("utf-8", "replace")
        try:
            result = json.loads(text[text.index("{"):])
        except (ValueError, KeyError):
            raise RuntimeError("gws no confirmó la identidad") from None
        if str(result.get("account", "")).lower() != attempt.account:
            raise RuntimeError("La cuenta autorizada no coincide con la solicitada")
        accounts = root / "accounts"
        accounts.mkdir(mode=0o700, parents=True, exist_ok=True)
        destination = accounts / attempt.account
        with attempt.lock:
            if attempt.expired or time.monotonic() >= attempt.deadline:
                raise RuntimeError("El login venció antes de guardar las credenciales")
            if destination.exists():
                raise RuntimeError("La cuenta ya estaba registrada")
            attempt.directory.rename(destination)
        return attempt.account

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
            return {"ok": False, "error": "URL de callback inválida; copia la URL localhost completa de este login."}
        # ponytail: explicit completion uses normal tool arguments, not another ingress hook.
        return self._complete_callback(key, attempt, parsed)

    def _complete_callback(self, key, attempt, parsed):
        with self._lock, attempt.lock:
            if attempt.processing:
                return {"ok": False, "error": "La autorización ya se está procesando."}
            attempt.processing = True
        try:
            query = parse_qs(parsed.query, strict_parsing=True)
            code = query.get("code", [])
            if parsed.username or parsed.password or parsed.fragment or len(code) != 1 or not code[0] or not re.fullmatch(r"[A-Za-z0-9_./~-]{1,2048}", code[0]):
                raise ValueError("Callback inválido")
            if time.monotonic() >= attempt.deadline or attempt.process.poll() is not None:
                raise RuntimeError("Intento vencido")
            account = self._fetch_and_commit(attempt, code[0], Path(key[0]))
            return {"ok": True, "account": account,
                    "message": f"[Google Workspace: {account} autorizada en este perfil; credenciales guardadas. Verifica con gws_accounts y gws_api.]"}
        except Exception:
            return {"ok": False, "error": "no se pudo completar el login. Inicia uno nuevo; no repitas el enlace."}
        finally:
            self._expire(key, attempt, finished=True)

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
            message = "[Google Workspace: no se pudo completar el login. Inicia uno nuevo; no repitas el enlace.]"
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
