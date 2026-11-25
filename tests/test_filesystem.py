"""Filesystem handling: links, special names, binaries, archives. Nothing is ever followed or extracted."""
import io
import os
import subprocess
import sys
import tarfile
import unittest
import zipfile

from _support import OVERRIDE, PAYLOAD, RLO, TempCase, describe, rules, scan

SKILL = "---\nname: demo\ndescription: demo skill\n---\n\nBody.\n"


class Links(TempCase):
    def test_symlink_is_reported_and_never_followed(self):
        outside = self.sub("outside")
        self.w("outside/secret.md", "# outside\n\n" + PAYLOAD + "\n")
        self.w("demo/SKILL.md", SKILL)
        link = os.path.join(self.tmp, "demo", "notes.md")
        dlink = os.path.join(self.tmp, "demo", "more")
        try:
            os.symlink(os.path.join(outside, "secret.md"), link)
            os.symlink(outside, dlink, target_is_directory=True)
        except (OSError, NotImplementedError) as exc:
            self.skipTest("cannot create symlinks here (%s); on Windows this needs Developer Mode" % type(exc).__name__)
        s = scan(self.sub("demo"), kind="skill")
        links = [f for f in s.findings if f.rule == "fs-symlink"]
        self.assertEqual(2, len(links), describe(s, "MED"))
        self.assertTrue(all(f.sev == "HIGH" for f in links), "absolute link targets must be HIGH")
        self.assertNotIn("inj-override", rules(s), "content behind a link must not be read")
        self.assertEqual(1, s.stats["files"])

    @unittest.skipUnless(sys.platform == "win32", "junctions exist only on Windows")
    def test_windows_junction_is_not_followed(self):
        outside = self.sub("outside")
        self.w("outside/secret.md", "# outside\n\n" + PAYLOAD + "\n")
        self.w("demo/SKILL.md", SKILL)
        junction = os.path.join(self.tmp, "demo", "linked")
        proc = subprocess.run(["cmd", "/c", "mklink", "/J", junction, outside], capture_output=True)
        if proc.returncode != 0:
            self.skipTest("mklink /J failed")
        try:
            s = scan(self.sub("demo"), kind="skill")
            self.assertIn("fs-symlink", rules(s))
            self.assertNotIn("inj-override", rules(s))
        finally:
            os.rmdir(junction)

    def test_scanning_a_symlink_directly(self):
        self.w("real.md", "# x\n" + OVERRIDE + "\n")
        link = os.path.join(self.tmp, "link.md")
        try:
            os.symlink(os.path.join(self.tmp, "real.md"), link)
        except (OSError, NotImplementedError):
            self.skipTest("cannot create symlinks here")
        s = scan(link, kind="article")
        self.assertIn("fs-symlink", rules(s))
        self.assertNotIn("inj-override", rules(s))


class Names(TempCase):
    def test_deceptive_names(self):
        self.w("demo/SKILL.md", SKILL)
        self.w("demo/invoice.pdf.exe", b"MZ\x90\x00" + b"\x00" * 64)
        self.w("demo/report" + RLO + "fdp.txt", "x\n")
        self.w("demo/" + chr(0x0421) + "LAUDE.md", "# notes\n")          # Cyrillic ES instead of Latin C
        s = scan(self.sub("demo"), kind="skill")
        tricks = [f for f in s.findings if f.rule == "fs-name-trick"]
        self.assertGreaterEqual(len(tricks), 3, describe(s, "MED"))
        self.assertIn("HIGH", {f.sev for f in tricks})
        for f in s.findings:
            self.assertNotIn(RLO, f.file)
            self.assertNotIn(RLO, f.snippet)


class Binaries(TempCase):
    def test_executables_and_mismatches(self):
        self.w("demo/SKILL.md", SKILL)
        self.w("demo/bin/tool.exe", b"MZ\x90\x00" + bytes(200))
        self.w("demo/bin/helper", b"\x7fELF\x02\x01\x01" + bytes(200))
        self.w("demo/assets/logo.png", b"MZ\x90\x00" + bytes(200))
        self.w("demo/assets/real.png", b"\x89PNG\r\n\x1a\n" + bytes(200))
        self.w("demo/model.pkl", b"\x80\x04\x95" + bytes(100))
        self.w("demo/blob.dat", bytes(range(256)) * 4)
        s = scan(self.sub("demo"), kind="skill")
        self.assertHigh(s, "bin-executable")
        self.assertHigh(s, "bin-type-mismatch")
        self.assertIn("bin-pickle", rules(s, "MED"))
        self.assertIn("bin-nontext", rules(s, "MED"))
        self.assertFalse([f for f in s.findings if f.file.endswith("real.png")])

    def test_strings_inside_binaries_are_scanned(self):
        self.w("demo/SKILL.md", SKILL)
        self.w("demo/data.bin", bytes(64) + PAYLOAD.encode() + bytes(64) + OVERRIDE.encode("utf-16-le") + bytes(8))
        s = scan(self.sub("demo"), kind="skill")
        self.assertHigh(s, "inj-override")

    def test_bytecode_handling(self):
        self.w("demo/SKILL.md", SKILL)
        self.w("demo/scripts/__pycache__/a.cpython-312.pyc", b"\xcb\x0d\x0d\x0a" + (0).to_bytes(4, "little") + bytes(64))
        self.w("demo/scripts/__pycache__/b.cpython-312.pyc", b"\xcb\x0d\x0d\x0a" + (1).to_bytes(4, "little") + bytes(64))
        self.w("demo/scripts/sourceless.pyc", b"\xcb\x0d\x0d\x0a" + (0).to_bytes(4, "little") + bytes(64))
        s = scan(self.sub("demo"), kind="skill")
        by = {f.file.split("/")[-1]: f.sev for f in s.findings if f.rule == "bin-executable"}
        self.assertEqual({"a.cpython-312.pyc": "MED", "b.cpython-312.pyc": "HIGH", "sourceless.pyc": "HIGH"}, by)

    def test_pdf_active_content_markers(self):
        self.w("d/doc.pdf", b"%PDF-1.7\n1 0 obj << /OpenAction 2 0 R /JavaScript (app.alert) >> endobj\n" + bytes(64))
        self.assertIn("bin-pdf-active", rules(scan(self.sub("d"), kind="article"), "MED"))


class Archives(TempCase):
    def zip_bytes(self, members):
        buf = io.BytesIO()
        with zipfile.ZipFile(buf, "w", zipfile.ZIP_DEFLATED) as zf:
            for name, data in members:
                zf.writestr(name, data)
        return buf.getvalue()

    def test_zip_traversal_executables_and_member_content(self):
        self.w("demo/SKILL.md", SKILL)
        self.w("demo/bundle.zip", self.zip_bytes([
            ("../../outside.txt", "x"), ("/abs/path.txt", "x"), ("C:\\Windows\\evil.txt", "x"),
            ("tools/run.exe", b"MZ\x90\x00"), ("docs/notes.md", "# n\n<!-- %s -->\n" % PAYLOAD),
            ("inner.zip", b"PK\x03\x04")]))
        before = set(os.listdir(os.path.join(self.tmp, "demo")))
        s = scan(self.sub("demo"), kind="skill")
        self.assertHigh(s, "archive-traversal")
        self.assertIn("archive-executable", rules(s, "MED"))
        self.assertIn("archive-nested", rules(s, "MED"))
        self.assertHigh(s, "inj-override")
        self.assertTrue(any("bundle.zip!/docs/notes.md" in f.file for f in s.findings))
        self.assertEqual(before, set(os.listdir(os.path.join(self.tmp, "demo"))), "nothing may be extracted")
        self.assertFalse(os.path.exists(os.path.join(self.tmp, "outside.txt")))

    def test_tar_traversal_links_and_devices(self):
        buf = io.BytesIO()
        with tarfile.open(fileobj=buf, mode="w:gz") as tf:
            def add(name, data=b"x", **kw):
                ti = tarfile.TarInfo(name)
                for k, v in kw.items():
                    setattr(ti, k, v)
                if ti.isreg():
                    ti.size = len(data)
                    tf.addfile(ti, io.BytesIO(data))
                else:
                    tf.addfile(ti)
            add("pkg/README.md", b"# pkg\n")
            add("../escape.txt")
            add("pkg/link", type=tarfile.SYMTYPE, linkname="/etc/passwd")
            add("pkg/dev", type=tarfile.CHRTYPE)
            add("pkg/SKILL.md", ("---\nname: pkg\ndescription: x\n---\n" + OVERRIDE + "\n").encode())
        self.w("demo/SKILL.md", SKILL)
        self.w("demo/pkg.tar.gz", buf.getvalue())
        s = scan(self.sub("demo"), kind="skill")
        self.assertHigh(s, "archive-traversal")
        self.assertIn("archive-link", rules(s, "MED"))
        self.assertHigh(s, "inj-override")

    def test_skill_file_extension_is_treated_as_zip(self):
        self.w("d/thing.skill", self.zip_bytes([("thing/SKILL.md", "---\nname: thing\ndescription: x\nhooks:\n"
                                                 "  Stop:\n    - hooks:\n      - type: command\n"
                                                 "        command: id\n---\nok\n")]))
        s = scan(self.sub("d"), kind="skill")
        self.assertHigh(s, "skill-frontmatter-hooks")

    def test_corrupt_and_opaque_archives(self):
        self.w("demo/SKILL.md", SKILL)
        self.w("demo/broken.zip", b"PK\x03\x04" + b"garbage" * 20)
        self.w("demo/data.7z", b"7z\xbc\xaf\x27\x1c" + bytes(64))
        s = scan(self.sub("demo"), kind="skill")
        self.assertIn("archive-error", rules(s, "MED"))
        self.assertIn("archive-opaque", rules(s, "MED"))

    def test_zip_bomb_is_not_expanded(self):
        buf = io.BytesIO()
        with zipfile.ZipFile(buf, "w", zipfile.ZIP_DEFLATED) as zf:
            zf.writestr("big.txt", b"\x00" * 80_000_000)
        self.w("demo/SKILL.md", SKILL)
        self.w("demo/bomb.zip", buf.getvalue())
        s = scan(self.sub("demo"), kind="skill")
        self.assertHigh(s, "archive-bomb")

    def test_archives_can_be_disabled(self):
        self.w("demo/SKILL.md", SKILL)
        self.w("demo/b.zip", self.zip_bytes([("../x", "x")]))
        s = scan(self.sub("demo"), kind="skill", scan_archives=False)
        self.assertNotIn("archive-traversal", rules(s))


if __name__ == "__main__":
    unittest.main()
