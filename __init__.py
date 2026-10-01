"""Hermes plugin: per-profile Google Workspace CLI accounts and temporary OAuth hook."""
import json

from .oauth import LoginManager
from .router import execute_gws, list_accounts


def register(ctx):
    from hermes_constants import get_hermes_home
    from gateway.session_context import get_session_env

    install_root = get_hermes_home() / "gws-oauth"
    if install_root.is_symlink():
        raise RuntimeError(f"Refusing symlinked gws-oauth directory: {install_root}")
    install_root.mkdir(parents=True, exist_ok=True, mode=0o700)
    install_root.chmod(0o700)

    manager = LoginManager()
    ctx.on_unload(manager.close)

    def root():
        return get_hermes_home() / "gws-oauth"

    def login(args, **kwargs):
        platform = get_session_env("HERMES_SESSION_PLATFORM") or get_session_env("HERMES_SESSION_SOURCE") or "cli"
        chat = get_session_env("HERMES_SESSION_CHAT_ID")
        user = get_session_env("HERMES_SESSION_USER_ID")
        profile = get_session_env("HERMES_SESSION_PROFILE")
        gateway_chat = bool(chat)
        if not gateway_chat:
            chat = kwargs.get("session_id") or get_session_env("HERMES_SESSION_ID")
            user = user or "local"
        if args.get("callback_url") is not None:
            return json.dumps(manager.finish(
                root(), platform, chat, user, args.get("account"), args["callback_url"],
                profile=profile,
            ))
        result = manager.start(
            root(), platform, chat, user, args.get("account"),
            ctx.get_config("gws_bin", default="gws"),
            (lambda callback: ctx.register_hook("pre_gateway_dispatch", callback)) if gateway_chat else None,
            profile=profile,
            scope_mode=args.get("scope_mode", "full"),
            scopes=args.get("scopes"),
        )
        return json.dumps(result)

    def accounts(args, **kwargs):
        return json.dumps({"ok": True, "accounts": list_accounts(root())})

    def api(args, **kwargs):
        try:
            result = execute_gws(
                root(), args.get("account"), args.get("args"),
                gws_bin=ctx.get_config("gws_bin", default="gws"),
            )
        except (OSError, ValueError) as exc:
            result = {"ok": False, "error": str(exc)}
        return json.dumps(result)

    ctx.register_tool(
        name="gws_login", toolset="gws_oauth", handler=login,
        schema={"name": "gws_login", "description": "Inicia OAuth de gws para una cuenta Google en el perfil actual desde cualquier plataforma, incluyendo CLI, TUI, Desktop, API server y gateway. Úsalo tras recibir el correo y los permisos deseados. Devuelve una URL de Google; pide pegar en la misma sesión la URL localhost completa del navegador, con o sin http://. El gateway la intercepta automáticamente. Si llega al agente, completa con esta misma herramienta, el mismo account y callback_url; el callback pasa por el modelo y queda en el historial. Nunca solicites passwords, tokens ni códigos sueltos.",
                "parameters": {"type": "object", "properties": {
                    "account": {"type": "string", "description": "Correo Google exacto a autorizar"},
                    "callback_url": {"type": "string", "description": "URL localhost completa pegada por el usuario para finalizar el login pendiente en esta misma sesión; disponible en cualquier plataforma"},
                    "scope_mode": {"type": "string", "enum": ["default", "readonly", "full", "custom"], "default": "full", "description": "Modo nativo de permisos de gws; full permite todos los servicios compatibles"},
                    "scopes": {"type": "array", "items": {"type": "string"}, "description": "Scopes OAuth exactos; requerido solo con scope_mode=custom"}},
                    "required": ["account"]}},
    )
    ctx.register_tool(
        name="gws_accounts", toolset="gws_oauth", handler=accounts,
        schema={"name": "gws_accounts", "description": "Lista las cuentas autorizadas en el perfil actual, sin revelar credenciales.",
                "parameters": {"type": "object", "properties": {}, "required": []}},
    )
    ctx.register_tool(
        name="gws_api", toolset="gws_oauth", handler=api,
        schema={"name": "gws_api", "description": "Ejecuta gws tal cual para una cuenta explícita del perfil. Los argumentos se pasan sin limitar comandos, opciones ni acceso a archivos locales.",
                "parameters": {"type": "object", "properties": {
                    "account": {"type": "string", "description": "Correo exacto de una cuenta autorizada"},
                    "args": {"type": "array", "items": {"type": "string"}, "description": "Argumentos exactos posteriores al ejecutable gws, por ejemplo [\"drive\",\"files\",\"list\"]"}},
                    "required": ["account", "args"]}},
    )
