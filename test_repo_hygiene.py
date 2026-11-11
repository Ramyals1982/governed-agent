import shutil
import sys
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parent
sys.path.insert(0, str(ROOT / "scripts"))

import check_repo_hygiene as hyg  # noqa: E402


class TestRepoHygiene(unittest.TestCase):
    def setUp(self):
        self.tmp = Path(tempfile.mkdtemp())

    def tearDown(self):
        shutil.rmtree(self.tmp, ignore_errors=True)

    def labels(self):
        return sorted(label for _, label in hyg.scan(self.tmp))

    def test_clean_folder_passes(self):
        (self.tmp / "a.py").write_text("print('hi')\n")
        (self.tmp / "mas_2lod_public.pem").write_text("public")
        self.assertEqual(self.labels(), [])

    def test_private_key_file_is_flagged(self):
        (self.tmp / "ccor_private.pem").write_text("x")
        self.assertIn("key file", self.labels())

    def test_private_key_block_inside_another_file_is_flagged(self):
        (self.tmp / "notes.txt").write_text("-----" + "BEGIN PRIVATE KEY-----\nabc\n")
        self.assertEqual(self.labels(), ["private key block"])

    def test_database_and_env_are_flagged(self):
        (self.tmp / "audit.db").write_text("x")
        (self.tmp / ".env").write_text("K=1")
        self.assertEqual(self.labels(), sorted(["local database", ".env file"]))

    def test_api_key_shape_is_flagged_but_aws_example_is_allowed(self):
        (self.tmp / "a.txt").write_text("key sk-or-v1-" + "a" * 40)
        (self.tmp / "b.txt").write_text("AKIAIOSFODNN7EXAMPLE")
        self.assertEqual(self.labels(), ["OpenRouter API key"])

    def test_this_repository_is_clean(self):
        # scans the checked-out tree; untracked local keys are ignored when git is available
        findings = hyg.scan(ROOT) if (ROOT / ".git").exists() else []
        self.assertEqual(findings, [])


if __name__ == "__main__":
    unittest.main()
