"""The distributed package registers all three agent tools."""
import importlib.util
import json
import sys
import tempfile
import unittest
from pathlib import Path
from types import ModuleType, SimpleNamespace
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[1]
spec = importlib.util.spec_from_file_location("gws_oauth_test", ROOT / "__init__.py", submodule_search_locations=[str(ROOT)])
plugin = importlib.util.module_from_spec(spec)
sys.modules[spec.name] = plugin
spec.loader.exec_module(plugin)


class RegistrationTests(unittest.TestCase):
    def test_plugin_exposes_login_and_profile_tools(self):
        tools = {}
        starts = []
        finishes = []
        manager = SimpleNamespace(
            close=lambda: None,
            start=lambda *args, **kwargs: starts.append((args, kwargs)) or {"ok": True},
            finish=lambda *args, **kwargs: finishes.append((args, kwargs)) or {"ok": True},
        )
        ctx = SimpleNamespace(
            get_config=lambda key, default=None: default,
            register_tool=lambda **kwargs: tools.setdefault(kwargs["name"], kwargs),
            register_hook=lambda name, callback: None,
            on_unload=lambda callback: None,
        )
        with tempfile.TemporaryDirectory() as tmp:
            home = Path(tmp)
            hermes_constants = ModuleType("hermes_constants")
            setattr(hermes_constants, "get_hermes_home", lambda: home)
            gateway = ModuleType("gateway")
            setattr(gateway, "__path__", [])
            session_context = ModuleType("gateway.session_context")
            session = {
                "HERMES_SESSION_PLATFORM": "discord",
                "HERMES_SESSION_CHAT_ID": "thread-1",
                "HERMES_SESSION_USER_ID": "user-1",
                "HERMES_SESSION_CHAT_TYPE": "thread",
                "HERMES_SESSION_PROFILE": "default",
            }
            setattr(session_context, "get_session_env", session.get)
            with patch.object(plugin, "LoginManager", return_value=manager):
                with patch.dict(sys.modules, {
                    "hermes_constants": hermes_constants,
                    "gateway": gateway,
                    "gateway.session_context": session_context,
                }):
                    plugin.register(ctx)
            state_dir = home / "gws-oauth"
            self.assertTrue(state_dir.is_dir())
            self.assertEqual(state_dir.stat().st_mode & 0o777, 0o700)
            self.assertFalse((state_dir / "client_secret.json").exists())
            self.assertEqual(set(tools), {"gws_login", "gws_accounts", "gws_api"})
            result = json.loads(tools["gws_login"]["handler"]({"account": "user@example.com"}))
            self.assertTrue(result["ok"])
            self.assertEqual(starts[0][0][1:5], ("discord", "thread-1", "user-1", "user@example.com"))
            for platform in ("cli", "tui"):
                session.clear()
                session.update(HERMES_SESSION_SOURCE=platform, HERMES_SESSION_ID="terminal-1")
                handler = tools["gws_login"]["handler"]
                self.assertTrue(json.loads(handler({"account": "user@example.com"}))["ok"])
                self.assertEqual(starts[-1][0][1:5], (platform, "terminal-1", "local", "user@example.com"))
                callback = "localhost:1234/?code=fixture"
                self.assertTrue(json.loads(handler({"account": "user@example.com", "callback_url": callback}))["ok"])
                self.assertEqual(finishes[-1][0][1:], (platform, "terminal-1", "local", "user@example.com", callback))
                self.assertTrue(json.loads(handler({"account": "user@example.com"}, session_id="terminal-2"))["ok"])
                self.assertEqual(starts[-1][0][2], "terminal-2")
                self.assertTrue(json.loads(handler({"account": "user@example.com", "callback_url": None}))["ok"])
                self.assertEqual(starts[-1][0][2], "terminal-1")
            self.assertIn("callback_url", tools["gws_login"]["schema"]["parameters"]["properties"])


if __name__ == "__main__":
    unittest.main()
