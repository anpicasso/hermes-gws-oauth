"""Run gws using exactly one account under the current Hermes profile."""
from __future__ import annotations
import json
import os
import re
import subprocess
from pathlib import Path

_ACCOUNT = re.compile(r"[A-Za-z0-9][A-Za-z0-9@._+-]{0,127}\Z")


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


def execute_gws(root, account, args, *, gws_bin="gws"):
    if not isinstance(args, list) or not all(isinstance(x, str) for x in args):
        raise ValueError("args must be a list of strings")
    path = account_dir(root, account)
    env = {key: val for key, val in os.environ.items()
           if not key.startswith("GOOGLE_WORKSPACE_CLI_") and key != "GOOGLE_APPLICATION_CREDENTIALS"}
    env["GOOGLE_WORKSPACE_CLI_CONFIG_DIR"] = str(path)
    env["GOOGLE_WORKSPACE_CLI_KEYRING_BACKEND"] = "file"
    try:
        result = subprocess.run([gws_bin, *args], env=env, capture_output=True, text=True, timeout=90)
    except (OSError, subprocess.TimeoutExpired):
        return {"ok": False, "error": "gws no está disponible o tardó demasiado"}
    if result.returncode:
        return {"ok": False, "error": f"gws terminó con estado {result.returncode}; comprueba autenticación y sintaxis"}
    if len(result.stdout) > 200_000:
        return {"ok": False, "error": "Salida demasiado larga; acota la solicitud"}
    try:
        data = json.loads(result.stdout)
    except json.JSONDecodeError:
        data = result.stdout.strip()
    return {"ok": True, "account": account, "data": data}
