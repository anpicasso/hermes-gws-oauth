"""Hermes plugin: per-profile Google Workspace CLI accounts and temporary OAuth hook."""
import json

from .oauth import LoginManager
from .router import account_health, execute_gws, list_accounts


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
            reauthorize=args.get("reauthorize", False),
        )
        return json.dumps(result)

    def accounts(args, **kwargs):
        names = list_accounts(root())
        payload = {"ok": True, "accounts": names}
        if args.get("check_health"):
            health = {}
            for name in names:
                try:
                    health[name] = account_health(
                        root(), name, gws_bin=ctx.get_config("gws_bin", default="gws"),
                    )
                except (OSError, ValueError):
                    health[name] = {"stored": True, "valid": None, "state": "stored",
                                    "reauth_required": False, "detail": "No se pudo comprobar esta cuenta."}
            payload["health"] = health
        return json.dumps(payload)

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
        schema={"name": "gws_login", "description": "Inicia OAuth de gws para una cuenta Google en el perfil actual desde cualquier plataforma, incluyendo CLI, TUI, Desktop, API server y gateway. Úsalo tras recibir el correo y los permisos deseados. Devuelve una URL de Google; pide pegar en la misma sesión la URL localhost completa del navegador, con o sin http://. El gateway la intercepta automáticamente. Si llega al agente, completa con esta misma herramienta, el mismo account y callback_url; el callback pasa por el modelo y queda en el historial. Para una cuenta ya configurada, usa reauthorize=true: las credenciales anteriores se conservan hasta validar la nueva identidad y solo entonces se sustituyen. Nunca solicites passwords, tokens ni códigos sueltos.",
                "parameters": {"type": "object", "properties": {
                    "account": {"type": "string", "description": "Correo Google exacto a autorizar"},
                    "callback_url": {"type": "string", "description": "URL localhost completa pegada por el usuario para finalizar el login pendiente en esta misma sesión; disponible en cualquier plataforma"},
                    "scope_mode": {"type": "string", "enum": ["default", "readonly", "full", "custom"], "default": "full", "description": "Modo nativo de permisos de gws; full permite todos los servicios compatibles"},
                    "scopes": {"type": "array", "items": {"type": "string"}, "description": "Scopes OAuth exactos; requerido solo con scope_mode=custom"},
                    "reauthorize": {"type": "boolean", "default": False, "description": "Renueva una cuenta ya configurada. Es explícito: sin este flag se rechaza. Las credenciales anteriores siguen intactas hasta que la nueva identidad coincida y el commit tenga éxito; cancelar, vencer o rechazar la identidad las conserva; un fallo de reemplazo intenta restaurarlas."}},
                    "required": ["account"]}},
    )
    ctx.register_tool(
        name="gws_accounts", toolset="gws_oauth", handler=accounts,
        schema={"name": "gws_accounts", "description": "Lista las cuentas autorizadas en el perfil actual, sin revelar credenciales. Con check_health=true consulta gws auth status por cuenta y distingue credenciales guardadas de una sesión válida; gws sigue siendo el único responsable de refrescar tokens.",
                "parameters": {"type": "object", "properties": {
                    "check_health": {"type": "boolean", "default": False, "description": "Comprobación en vivo opcional (hasta 20 s por cuenta). Devuelve state=valid|invalid|stored|unreadable, stored y valid por separado, y reauth_required. No expone stdout/stderr ni tokens."}},
                    "required": []}},
    )
    ctx.register_tool(
        name="gws_api", toolset="gws_oauth", handler=api,
        schema={"name": "gws_api", "description": "Ejecuta gws tal cual para una cuenta explícita del perfil. Los argumentos se pasan sin limitar comandos, opciones ni acceso a archivos locales. Las respuestas exitosas mayores a 200000 caracteres devuelven output_file (archivo local UTF-8 completo) y output_bytes en vez de data; procesa ese archivo con código y elimínalo después. Para adjuntos Gmail decodifica el campo data del JSON como base64url. Si gws falla, devuelve error_code, category, action, reauth_required y exit_code con un mensaje saneado; nunca incluye stdout/stderr crudos.",
                "parameters": {"type": "object", "properties": {
                    "account": {"type": "string", "description": "Correo exacto de una cuenta autorizada"},
                    "args": {"type": "array", "items": {"type": "string"}, "description": "Argumentos exactos posteriores al ejecutable gws, por ejemplo [\"drive\",\"files\",\"list\"]"}},
                    "required": ["account", "args"]}},
    )
