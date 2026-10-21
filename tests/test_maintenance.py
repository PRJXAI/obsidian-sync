import shutil
import subprocess
import tempfile
import unittest
from pathlib import Path

SOURCE = Path(__file__).resolve().parents[1] / "scripts/docs.py"


class DocumentationTools(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        (self.root / "scripts").mkdir()
        (self.root / "docs").mkdir()
        shutil.copyfile(SOURCE, self.root / "scripts/docs.py")
        (self.root / "README.md").write_text("# Test\n")
        (self.root / "AGENTS.md").write_text("# Instructions\n")
        subprocess.run(["git", "init", "-q"], cwd=self.root, check=True)

    def run_tool(self, *args, success=True):
        result = subprocess.run(["python3", "scripts/docs.py", *args], cwd=self.root, capture_output=True, text=True)
        self.assertEqual(result.returncode == 0, success, result.stdout + result.stderr)
        return result

    def test_create_update_drift_and_review(self):
        self.run_tool("create", "docs/nested/new.md", "--title", "New")
        self.run_tool("check", success=False)
        content = self.root / "content.txt"
        content.write_text("# Verified\n")
        self.run_tool("update", "docs/nested/new.md", "--from-file", str(content))
        self.run_tool("review", "--reason", "verified fixture sources")
        self.run_tool("check")
        (self.root / "src").mkdir()
        (self.root / "src/lib.rs").write_text("// changed\n")
        self.run_tool("check", success=False)
        self.run_tool("review", "--reason", "reviewed new source")
        self.run_tool("check")

    def test_reject_traversal_symlinks_and_untracked_deletion(self):
        self.run_tool("create", "../escape.md", "--title", "X", success=False)
        self.run_tool("create", "docs/new.md", "--title", "New")
        self.run_tool("delete", "docs/new.md", "--reason", "stale", "--yes", success=False)
        (self.root / "docs/link.md").symlink_to(self.root / "README.md")
        self.run_tool("update", "docs/link.md", "--from-file", str(self.root / "AGENTS.md"), success=False)

    def test_delete_requires_history_confirmation_and_no_inbound_links(self):
        (self.root / "docs/old.md").write_text("# Old\n")
        (self.root / "README.md").write_text("[old](docs/old.md)\n")
        subprocess.run(["git", "add", "."], cwd=self.root, check=True)
        subprocess.run(["git", "-c", "user.name=Test", "-c", "user.email=test@example.invalid", "commit", "-qm", "fixture"], cwd=self.root, check=True)
        self.run_tool("delete", "docs/old.md", "--reason", "stale", success=False)
        self.run_tool("delete", "docs/old.md", "--reason", "stale", "--yes", success=False)
        (self.root / "README.md").write_text("# Test\n")
        (self.root / "docs/old.md").write_text("# Uncommitted valuable update\n")
        self.run_tool("delete", "docs/old.md", "--reason", "superseded", "--yes", success=False)
        (self.root / "docs/old.md").write_text("# Old\n")
        self.run_tool("delete", "docs/old.md", "--reason", "superseded", "--yes")
        self.assertFalse((self.root / "docs/old.md").exists())


if __name__ == "__main__":
    unittest.main()
