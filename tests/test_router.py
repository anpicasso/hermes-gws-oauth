import json
import os
import sys
import tempfile
import unittest
from pathlib import Path
sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from router import list_accounts, execute_gws


class RouterTests(unittest.TestCase):
    def test_only_current_profile_account_is_exposed_to_gws(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp) / "profile"
            other = Path(tmp) / "other"
            for base in (root, other):
                account = base / "accounts" / "person@example.com"
                account.mkdir(parents=True)
                (account / "credentials.enc").write_text("fake")
            fake = Path(tmp) / "gws"
            fake.write_text("#!" + sys.executable + "\nimport json,os,sys\nprint(json.dumps({'config':os.getenv('GOOGLE_WORKSPACE_CLI_CONFIG_DIR'),'token':os.getenv('GOOGLE_WORKSPACE_CLI_TOKEN'),'args':sys.argv[1:]}))\n")
            fake.chmod(0o700)
            previous = os.environ.get("GOOGLE_WORKSPACE_CLI_TOKEN")
            os.environ["GOOGLE_WORKSPACE_CLI_TOKEN"] = "fixture-value"
            try:
                self.assertEqual(list_accounts(root), ["person@example.com"])
                raw_args = ["drive", "+upload", "/tmp/report.pdf", "--output", "out.bin"]
                result = execute_gws(root, "person@example.com", raw_args, gws_bin=str(fake))
            finally:
                if previous is None:
                    os.environ.pop("GOOGLE_WORKSPACE_CLI_TOKEN", None)
                else:
                    os.environ["GOOGLE_WORKSPACE_CLI_TOKEN"] = previous
            self.assertTrue(result["ok"])
            self.assertEqual(result["data"]["config"], str(root / "accounts" / "person@example.com"))
            self.assertIsNone(result["data"]["token"])
            self.assertEqual(result["data"]["args"], raw_args)
            with self.assertRaises(ValueError):
                execute_gws(root, "../other", ["drive", "files", "list"], gws_bin=str(fake))


if __name__ == "__main__":
    unittest.main()
