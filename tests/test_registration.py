"""The distributed package registers all three agent tools."""
import importlib.util
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
            setattr(session_context, "get_session_env", lambda key: None)
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
            result = tools["gws_login"]["handler"]({"account": "user@example.com"})
            self.assertIn("chat privado", result)


if __name__ == "__main__":
    unittest.main()
