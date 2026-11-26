"""The skill is scanned with its own scanner, and the repository is checked for hygiene.

Known limitation recorded here on purpose: the scanner's rule tables (lists of bad patterns)
match themselves, exactly like an antivirus signature file. Those findings are confined to the
modules listed in SIGNATURE_FILES; everything an agent reads as instructions must stay clean.
"""
import os
import re
import unittest

from _support import ROOT, SKILL_DIR, describe, scan

# phrases.py joined the list with the reviewer-steering rules, whose literal words ("already vetted ... skip")
# read like the attack they describe, exactly as the code-behaviour tables do.
SIGNATURE_FILES = {"scripts/vetscan/coderules.py", "scripts/vetscan/configs.py", "scripts/vetscan/textutil.py",
                   "scripts/vetscan/framing.py", "scripts/vetscan/phrases.py"}
TEXT_EXT = (".py", ".md", ".json", ".yml", ".yaml", ".txt", ".toml", ".cfg", "")
SKIP_DIRS = {".git", "__pycache__", ".scratch"}
CYRILLIC_OK = {os.path.join("skills", "vet-agent-security", "scripts", "vetscan", "phrases.py"),
               os.path.join("skills", "vet-agent-security", "SKILL.md"),
               os.path.join("tests", "_support.py"), os.path.join("tests", "corpus_benign.py"),
               os.path.join("tests", "test_robustness.py")}
INVISIBLE = re.compile("[" + "".join((
    "\x00-\x08\x0b\x0c\x0e-\x1f\x7f-" + chr(0x9F), chr(0xAD), chr(0x200B) + "-" + chr(0x200F),
    chr(0x2028) + "-" + chr(0x202E), chr(0x2060) + "-" + chr(0x206F), chr(0xFE00) + "-" + chr(0xFE0F), chr(0xFEFF),
    chr(0xE000) + "-" + chr(0xF8FF), chr(0xE0000) + "-" + chr(0xE0FFF))) + "]")
# Machine-specific paths and e-mail addresses have no place in a public repository.
PERSONAL = re.compile(
    r"(?i)\b[a-z]:[\\/]{1,2}users[\\/]{1,2}[a-z0-9._-]+|/users/[a-z0-9._-]+/|/home/[a-z0-9._-]+/|"
    r"[a-z0-9._%+-]+@(?!example\.|[a-z0-9.-]*\.invalid)[a-z0-9-]+(?:\.[a-z0-9-]+)*\.[a-z]{2,}\b")
# Fixture strings that merely look like the above.
PERSONAL_OK = re.compile(r"(?i)/home/u/|/home/\[|/users/\[")


def repo_files():
    for dirpath, dirnames, filenames in os.walk(ROOT):
        dirnames[:] = sorted(d for d in dirnames if d not in SKIP_DIRS)
        for name in sorted(filenames):
            if os.path.splitext(name)[1].lower() in TEXT_EXT:
                yield os.path.join(dirpath, name)


class SelfScan(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.s = scan(SKILL_DIR, kind="skill")
        cls.findings = [f for f in cls.s.findings if "__pycache__" not in f.file]

    def test_instruction_files_are_clean(self):
        bad = [f for f in self.findings if f.file.endswith(".md") and f.sev in ("HIGH", "MED")]
        self.assertEqual([], [(f.sev, f.rule, f.file, f.line, f.snippet[:60]) for f in bad],
                         "SKILL.md and references/ must not trip the scanner they describe")

    def test_high_findings_only_in_signature_tables(self):
        outside = sorted({f.file for f in self.findings if f.sev == "HIGH"} - SIGNATURE_FILES)
        self.assertEqual([], outside, "HIGH findings outside the rule-table modules:\n" + describe(self.s))

    def test_scan_is_complete_and_auto_detects_a_skill(self):
        self.assertFalse(any(f.rule in ("scan-incomplete", "scan-truncated") for f in self.findings))
        self.assertEqual("skill", scan(SKILL_DIR, kind="auto").kind)

    def test_skill_md_frontmatter_and_size(self):
        with open(os.path.join(SKILL_DIR, "SKILL.md"), encoding="utf-8") as fh:
            text = fh.read()
        self.assertTrue(text.startswith("---\nname: vet-agent-security\ndescription: "))
        self.assertLessEqual(text.count("\n"), 260, "SKILL.md must stay lean; details belong in references/")
        for rel in re.findall(r"\]\((references/[a-z-]+\.md)\)", text):
            self.assertTrue(os.path.isfile(os.path.join(SKILL_DIR, *rel.split("/"))), rel)
        for needed in ("threat-model", "vetting-checklist", "article-vetting", "browsing-agent-hardening",
                       "canary-testing", "report-templates"):
            self.assertIn("references/%s.md" % needed, text)


class RepositoryHygiene(unittest.TestCase):
    def test_no_raw_invisible_or_control_characters_in_committed_files(self):
        bad = []
        for path in repo_files():
            with open(path, encoding="utf-8") as fh:
                text = fh.read()
            m = INVISIBLE.search(text)
            if m:
                bad.append("%s: U+%04X" % (os.path.relpath(path, ROOT), ord(m.group(0))))
        self.assertEqual([], bad, "write special characters with chr(), never raw")

    def test_non_ascii_is_limited_to_declared_files(self):
        bad = []
        for path in repo_files():
            rel = os.path.relpath(path, ROOT)
            with open(path, encoding="utf-8") as fh:
                text = fh.read()
            if not text.isascii() and rel not in CYRILLIC_OK:
                bad.append(rel)
            elif rel in CYRILLIC_OK:
                guillemets = {chr(0xAB), chr(0xBB)}
                extra = {c for c in text if ord(c) > 127 and not (0x0400 <= ord(c) <= 0x04FF)} - guillemets
                if extra:
                    bad.append("%s: %s" % (rel, sorted(hex(ord(c)) for c in extra)[:5]))
        self.assertEqual([], bad)

    def test_no_personal_data_or_machine_paths(self):
        bad = []
        for path in repo_files():
            rel = os.path.relpath(path, ROOT)
            with open(path, encoding="utf-8") as fh:
                for n, line in enumerate(fh, 1):
                    for m in PERSONAL.finditer(line):
                        ctx = line[max(0, m.start() - 30):m.end() + 30]
                        if not PERSONAL_OK.search(ctx):
                            bad.append("%s:%d: %s" % (rel, n, m.group(0)))
        self.assertEqual([], bad)

    def test_text_files_use_lf_line_endings(self):
        bad = []
        for path in repo_files():
            with open(path, "rb") as fh:
                if b"\r\n" in fh.read():
                    bad.append(os.path.relpath(path, ROOT))
        self.assertEqual([], bad)


if __name__ == "__main__":
    unittest.main()
