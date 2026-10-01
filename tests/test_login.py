"""Offline login flow: fake gws speaks the same localhost protocol."""
import asyncio
import json
import os
import sys
import tempfile
import unittest
from pathlib import Path
from types import SimpleNamespace
from unittest import mock

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from oauth import LoginManager


FAKE_GWS = '''#!{python}
import json, os, socket, sys
from pathlib import Path
if sys.argv[1:3] == ["auth", "status"]:
    print(json.dumps({"client_config": os.environ.get("FAKE_GLOBAL_CLIENT", "")}))
    sys.exit(0)
if sys.argv[1:3] != ["auth", "login"]:
    sys.exit(2)
dir = Path(os.environ["GOOGLE_WORKSPACE_CLI_CONFIG_DIR"])
(dir / "argv.json").write_text(json.dumps(sys.argv[1:]))
sock = socket.socket()
sock.bind(("127.0.0.1", 0))
sock.listen(1)
port = sock.getsockname()[1]
print("Open this URL in your browser to authenticate:", flush=True)
sys.stdout.write("https://accounts.google.com/o/oauth2/auth?client_id=fake&redirect_uri=http%3A%2F%2Flocalhost%3A")
sys.stdout.flush()
import time
time.sleep(0.05)
print(str(port) + "&scope=openid", flush=True)
conn, _ = sock.accept()
request = conn.recv(4096).decode()
conn.sendall(b"HTTP/1.1 200 OK\\r\\nContent-Length: 2\\r\\n\\r\\nOK")
conn.close()
sock.close()
if "code=good" not in request:
    sys.exit(1)
(dir / "credentials.enc").write_text("fixture-value")
print(json.dumps({"status": "success", "account": "user@example.com"}), flush=True)
'''


class LoginTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.home = Path(self.tmp.name)
        (self.home / "client_secret.json").write_text('{"installed":{"client_id":"fake"}}')
        self.fake = self.home / "fake-gws"
        self.fake.write_text(FAKE_GWS.replace("{python}", sys.executable))
        self.fake.chmod(0o700)
        self.manager = LoginManager()
        self.addCleanup(self.manager.close)
        self.handles = []

    def register(self, callback):
        handle = SimpleNamespace(active=True)
        def dispose():
            handle.active = False
        handle.dispose = dispose
        self.handles.append((handle, callback))
        return handle

    def start(self, user="42", timeout=10):
        return self.manager.start(
            self.home, "telegram", "100", user, "user@example.com", str(self.fake),
            self.register, timeout=timeout,
        )

    def event(self, text, user="42"):
        return SimpleNamespace(text=text, source=SimpleNamespace(
            platform=SimpleNamespace(value="telegram"), chat_id="100", user_id=user,
            chat_type="dm", profile="", message_id="321"))

    def test_login_rewrites_only_matching_callback_and_registers_account(self):
        result = self.start()
        self.assertTrue(result["ok"])
        attempt = next(iter(self.manager._attempts.values()))
        self.assertEqual(json.loads((attempt.directory / "argv.json").read_text()),
                         ["auth", "login", "--full"])
        from urllib.parse import parse_qs, urlsplit
        redirect = parse_qs(urlsplit(result["url"]).query)["redirect_uri"][0]
        self.assertEqual(len(self.handles), 1)
        callback = self.handles[0][1]
        self.assertIsNone(asyncio.run(callback(event=self.event("hello"))))
        self.assertIsNone(asyncio.run(callback(event=self.event(redirect + "?code=good", user="other"))))
        deletes = []
        async def delete_message(chat_id, message_id):
            deletes.append((chat_id, message_id))
            return True
        gateway = SimpleNamespace(_delivery_adapter_for_source=None,
                                  _delivery_adapter_for=lambda source: SimpleNamespace(delete_message=delete_message))
        response = asyncio.run(callback(event=self.event(redirect + "?code=good"), gateway=gateway))
        self.assertEqual(deletes, [("100", "321")])
        self.assertEqual(response["action"], "rewrite")
        self.assertIn("user@example.com", response["text"])
        self.assertNotIn("code=", response["text"])
        self.assertTrue((self.home / "accounts" / "user@example.com" / "credentials.enc").exists())
        self.assertFalse(self.handles[0][0].active)

    def test_callback_without_scheme_is_accepted(self):
        result = self.start()
        from urllib.parse import parse_qs, urlsplit
        redirect = parse_qs(urlsplit(result["url"]).query)["redirect_uri"][0]
        callback = self.handles[0][1]

        response = asyncio.run(callback(event=self.event(
            (redirect + "?code=good").removeprefix("http://")
        )))

        self.assertEqual(response["action"], "rewrite")
        self.assertIn("user@example.com", response["text"])
        self.assertNotIn("code=", response["text"])
        self.assertTrue((self.home / "accounts" / "user@example.com" / "credentials.enc").exists())

    def test_login_requires_precreated_root_and_client(self):
        root = self.home / "fresh-profile" / "gws-oauth"
        result = self.manager.start(
            root, "telegram", "100", "42", "user@example.com", str(self.fake),
            self.register, timeout=10, global_client=root / "missing-global.json",
        )
        self.assertFalse(result["ok"])
        self.assertFalse(root.exists())
        self.assertIn("client_secret.json", result["error"])

    def test_global_gws_client_is_fallback_and_profile_client_overrides_it(self):
        profile = self.home / "client_secret.json"
        shared = self.home / "global-client.json"
        shared.write_text('{"installed":{"client_id":"global"}}')
        profile.unlink()

        with mock.patch.dict(os.environ, {"FAKE_GLOBAL_CLIENT": str(shared)}):
            result = self.manager.start(
                self.home, "telegram", "100", "42", "user@example.com", str(self.fake),
                self.register, timeout=10,
            )
        self.assertTrue(result["ok"])
        attempt = next(iter(self.manager._attempts.values()))
        self.assertEqual((attempt.directory / "client_secret.json").read_bytes(), shared.read_bytes())
        self.manager.close()

        profile.write_text('{"installed":{"client_id":"profile"}}')
        result = self.manager.start(
            self.home, "telegram", "100", "42", "user@example.com", str(self.fake),
            self.register, timeout=10, global_client=shared,
        )
        self.assertTrue(result["ok"])
        attempt = next(iter(self.manager._attempts.values()))
        self.assertEqual((attempt.directory / "client_secret.json").read_bytes(), profile.read_bytes())

    def test_custom_scopes_are_forwarded_to_gws(self):
        scopes = ["openid", "https://www.googleapis.com/auth/drive.readonly"]
        result = self.manager.start(
            self.home, "telegram", "100", "42", "user@example.com", str(self.fake),
            self.register, timeout=10, scope_mode="custom", scopes=scopes,
        )
        self.assertTrue(result["ok"])
        attempt = next(iter(self.manager._attempts.values()))
        self.assertEqual(json.loads((attempt.directory / "argv.json").read_text()),
                         ["auth", "login", "--scopes", ",".join(scopes)])

    def test_timeout_stops_process_and_unhooks(self):
        result = self.start(timeout=0.3)
        self.assertTrue(result["ok"])
        from time import sleep
        sleep(0.7)
        self.assertFalse(self.handles[0][0].active)
        self.assertFalse(self.manager.has_pending(self.home, "telegram", "100", "42"))

    def test_malformed_owned_callback_never_reaches_agent(self):
        self.start()
        callback = self.handles[0][1]
        response = asyncio.run(callback(event=self.event("http://localhost:invalid/?code=should-not-leak")))
        self.assertEqual(response["action"], "rewrite")
        self.assertNotIn("should-not-leak", response["text"])
        oversized = asyncio.run(callback(event=self.event("http://localhost:" + "x" * 9000 + "?code=secret")))
        self.assertEqual(oversized["action"], "rewrite")
        self.assertNotIn("secret", oversized["text"])

    def test_callback_for_another_profile_cannot_finish_login(self):
        result = self.start()
        from urllib.parse import parse_qs, urlsplit
        redirect = parse_qs(urlsplit(result["url"]).query)["redirect_uri"][0]
        callback = self.handles[0][1]
        other_profile = self.event(redirect + "?code=good")
        other_profile.source.profile = "other"
        self.assertIsNone(asyncio.run(callback(event=other_profile)))
        self.assertTrue(self.manager.has_pending(self.home, "telegram", "100", "42"))

    def test_timeout_does_not_delete_files_under_active_exchange(self):
        import threading
        from time import sleep
        self.start(timeout=0.3)
        from urllib.parse import parse_qs, urlsplit
        attempt = next(iter(self.manager._attempts.values()))
        redirect = attempt.redirect
        entered, proceed = threading.Event(), threading.Event()
        original = self.manager._fetch_and_commit
        def delayed(attempt, code, root):
            entered.set()
            proceed.wait(2)
            return original(attempt, code, root)
        self.manager._fetch_and_commit = delayed
        result = []
        worker = threading.Thread(target=lambda: result.append(asyncio.run(
            self.handles[0][1](event=self.event(redirect + "?code=good")))))
        worker.start()
        self.assertTrue(entered.wait(2))
        sleep(0.45)
        self.assertTrue(attempt.directory.exists(), "timeout must not delete a directory being committed")
        proceed.set()
        worker.join(3)
        self.assertFalse(worker.is_alive())
        self.assertIn("no se pudo", result[0]["text"])
        self.assertFalse((self.home / "accounts" / "user@example.com").exists())

    def test_hook_registration_failure_does_not_leave_attempt(self):
        def broken(_callback):
            raise RuntimeError("registration failed")
        result = self.manager.start(self.home, "telegram", "100", "42", "user@example.com",
                                    str(self.fake), broken, timeout=1)
        self.assertFalse(result["ok"])
        self.assertFalse(self.manager.has_pending(self.home, "telegram", "100", "42"))

    def test_wrong_google_identity_cannot_become_registered_account(self):
        result = self.manager.start(self.home, "telegram", "100", "42", "other@example.com",
                                    str(self.fake), self.register, timeout=10)
        from urllib.parse import parse_qs, urlsplit
        redirect = parse_qs(urlsplit(result["url"]).query)["redirect_uri"][0]
        response = asyncio.run(self.handles[0][1](event=self.event(redirect + "?code=good")))
        self.assertEqual(response["action"], "rewrite")
        self.assertIn("no se pudo", response["text"])
        self.assertFalse((self.home / "accounts" / "other@example.com").exists())

    def test_any_surface_finishes_without_hook_and_is_session_bound(self):
        for platform in ("cli", "tui", "desktop", "api_server", "custom_ui", "telegram"):
            with self.subTest(platform=platform):
                root = self.home / platform
                root.mkdir()
                (root / "client_secret.json").write_bytes((self.home / "client_secret.json").read_bytes())
                result = self.manager.start(root, platform, "session-1", "local", "user@example.com",
                                            str(self.fake), None, timeout=10, profile="default")
                self.assertTrue(result["ok"])
                self.assertEqual(self.handles, [], "terminal chat must not register an interception hook")
                attempt = next(iter(self.manager._attempts.values()))
                callback = (attempt.redirect + "?code=good").removeprefix("http://")
                for target, session, profile, account in (
                    (root, "session-2", "default", "user@example.com"),
                    (root, "session-1", "other", "user@example.com"),
                    (self.home, "session-1", "default", "user@example.com"),
                    (root, "session-1", "default", "other@example.com"),
                ):
                    self.assertFalse(self.manager.finish(target, platform, session, "local", account,
                                                         callback, profile=profile)["ok"])
                self.assertFalse(self.manager.finish(root, "other_surface", "session-1", "local",
                                                     "user@example.com", callback, profile="default")["ok"])
                self.assertFalse(self.manager.finish(root, platform, "session-1", "another-user",
                                                     "user@example.com", callback, profile="default")["ok"])
                for invalid in ("https://example.com/?code=good", "http://localhost:invalid/?code=good",
                                attempt.redirect + "/wrong?code=good", "x" * 8193, None):
                    self.assertFalse(self.manager.finish(root, platform, "session-1", "local", "user@example.com",
                                                         invalid, profile="default")["ok"])
                response = self.manager.finish(root, platform, "session-1", "local", "user@example.com",
                                               callback, profile="default")
                self.assertTrue(response["ok"], response)
                self.assertNotIn("code=", json.dumps(response))
                self.assertTrue((root / "accounts" / "user@example.com" / "credentials.enc").is_file())
                self.assertFalse(self.manager._attempts)
                self.assertFalse(self.manager.finish(root, platform, "session-1", "local", "user@example.com",
                                                     callback, profile="default")["ok"])

    def test_terminal_chat_rejects_invalid_codes_and_wrong_google_identity(self):
        for account, query in (("user@example.com", "?code=good&code=bad"),
                               ("user@example.com", "?code=bad"),
                               ("other@example.com", "?code=good")):
            with self.subTest(account=account, query=query):
                result = self.manager.start(self.home, "cli", "session-1", "local", account,
                                            str(self.fake), None, timeout=10)
                self.assertTrue(result["ok"])
                attempt = next(iter(self.manager._attempts.values()))
                response = self.manager.finish(self.home, "cli", "session-1", "local", account,
                                               attempt.redirect + query)
                self.assertFalse(response["ok"])
                self.assertFalse((self.home / "accounts" / account).exists())
                self.assertFalse(attempt.directory.exists())
                self.assertIsNotNone(attempt.process.poll())
                self.assertFalse(self.manager._attempts)

    def test_same_port_different_path_is_rejected_and_expired_attempt_not_reused(self):
        result = self.start()
        from urllib.parse import parse_qs, urlsplit
        redirect = parse_qs(urlsplit(result["url"]).query)["redirect_uri"][0]
        callback = self.handles[0][1]
        wrong_path = asyncio.run(callback(event=self.event(redirect + "/other?code=good")))
        self.assertEqual(wrong_path["action"], "rewrite")
        self.assertNotIn("code=", wrong_path["text"])
        failure = asyncio.run(callback(event=self.event(redirect + "?code=bad")))
        self.assertEqual(failure["action"], "rewrite")
        self.assertNotIn("code=", failure["text"])
        self.assertFalse(self.manager.has_pending(self.home, "telegram", "100", "42"))


if __name__ == "__main__":
    unittest.main()
