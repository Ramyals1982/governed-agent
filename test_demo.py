"""The demo is part of the evidence: it must keep telling the truth about the gate."""
import contextlib
import io
import sys
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))

import demo  # noqa: E402


class TestDemo(unittest.TestCase):
    def test_demo_story_holds(self):
        buf = io.StringIO()
        with contextlib.redirect_stdout(buf):
            demo.main()
        out = buf.getvalue()
        self.assertEqual(out.count("AGENT STARTS"), 2)       # after the 2LoD signs, and after fresh evidence
        self.assertEqual(out.count("AGENT REFUSES TO START"), 3)   # under-declared, unsigned, stale evidence
        self.assertIn("effective challenge failed", out.replace("\n", " "))
        self.assertIn("NEEDS_REVIEW", out)
        self.assertIn("INTACT", out)


if __name__ == "__main__":
    unittest.main()
