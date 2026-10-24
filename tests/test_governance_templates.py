"""Scrub check for the governance templates. The files are empty placeholders."""

from __future__ import annotations

import importlib.util
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
KIT = ROOT / "kits" / "governance-templates"
SYNTHETIC_PHRASES = ("crimson widget", "orbit lantern")
EXPECTED = {
    "README.md",
    "decision-record.md",
    "autonomy-ladder.md",
    "agent-role-card.md",
    "extend-never-duplicate.md",
}


def load_scrubber():
    path = ROOT / "kits" / "safe-helpers" / "export_scrub.py"
    spec = importlib.util.spec_from_file_location("export_scrub", path)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


class GovernanceTemplateScrubTests(unittest.TestCase):
    def test_kit_text_has_no_generic_hits(self):
        scrubber = load_scrubber()
        names = {path.name for path in KIT.iterdir() if path.is_file()}
        self.assertEqual(names, EXPECTED)
        hits = []
        for path in sorted(KIT.rglob("*")):
            if not path.is_file():
                continue
            text = path.read_text(encoding="utf-8")
            found = scrubber.hits(text)
            lowered = text.lower()
            for phrase in SYNTHETIC_PHRASES:
                if phrase in lowered:
                    found.append(f"phrase:{phrase}")
            if found or scrubber.scrub(text) != text:
                hits.append(f"{path.relative_to(ROOT)} {found}")
        self.assertEqual(hits, [])


if __name__ == "__main__":
    unittest.main()
