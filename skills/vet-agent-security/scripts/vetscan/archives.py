"""Archive inspection without extraction.

Members are listed (and small text members read into memory) straight from the
archive; nothing is ever written to disk. Flags path traversal, absolute paths,
links, device nodes, executables, encrypted entries and implausible expansion.
"""
import re
import stat
import tarfile
import zipfile

from .model import rule

rule("archive-traversal", "archive", "archive member path escapes the extraction directory")
rule("archive-link", "archive", "archive contains a symlink/hardlink/device member")
rule("archive-executable", "archive", "archive contains executables or scripts")
rule("archive-bomb", "archive", "archive expands implausibly (decompression bomb) or has too many members")
rule("archive-encrypted", "archive", "archive has encrypted members that cannot be inspected")
rule("archive-nested", "archive", "archive contains another archive (not opened)")
rule("archive-opaque", "archive", "compressed/archive format that this scanner cannot list")
rule("archive-error", "archive", "archive could not be read")

MAX_MEMBERS = 5000
MAX_SCAN_MEMBERS = 200
MAX_MEMBER_BYTES = 1_000_000
MAX_SCAN_TOTAL = 16_000_000
MAX_DECLARED = 2_000_000_000

EXEC_EXT = frozenset(
    ".exe .dll .so .dylib .msi .scr .com .jar .class .pyc .pyd .node .wasm .lnk .bat .cmd .ps1 .psm1 .vbs .vbe "
    ".js .jse .wsf .hta .sh .bash .command .app .pkg .deb .rpm .apk .dmg .iso .cpl .sys .drv".split())
ARCHIVE_EXT = frozenset(
    ".zip .jar .war .whl .egg .tar .tgz .gz .bz2 .tbz2 .xz .txz .7z .rar .zst .cab .skill .mcpb .dxt".split())
TAR_SUFFIXES = (".tar", ".tgz", ".tar.gz", ".tbz2", ".tar.bz2", ".txz", ".tar.xz")
OPAQUE_SUFFIXES = (".gz", ".bz2", ".xz", ".7z", ".rar", ".zst", ".cab", ".lz4", ".lzma")
_DRIVE = re.compile(r"^[A-Za-z]:")


def kind_of(name_lower, head):
    if head[:4] in (b"PK\x03\x04", b"PK\x05\x06", b"PK\x07\x08"):
        return "zip"
    if name_lower.endswith(TAR_SUFFIXES) or head[257:262] == b"ustar":
        return "tar"
    if name_lower.endswith(OPAQUE_SUFFIXES) or head[:6] in (b"7z\xbc\xaf\x27\x1c", b"Rar!\x1a\x07") \
            or head[:2] == b"\x1f\x8b" or head[:3] == b"BZh" or head[:6] == b"\xfd7zXZ\x00" \
            or head[:4] == b"\x28\xb5\x2f\xfd":
        return "opaque"
    return None


def _bad_path(name):
    norm = name.replace("\\", "/")
    parts = norm.split("/")
    if ".." in parts:
        return "contains .."
    if norm.startswith("/") or name.startswith("\\"):
        return "absolute path"
    if _DRIVE.match(norm):
        return "drive-letter path"
    return None


def _ext(name):
    base = name.replace("\\", "/").rsplit("/", 1)[-1].lower()
    return "." + base.rsplit(".", 1)[-1] if "." in base else ""


def scan(S, fc, path, kind, budget):
    """Inspect one archive. S is the engine Scan; member text goes back through S.scan_member()."""
    add = lambda sev, rid, snip, note: S.add(sev, rid, fc, 0, snip, note)   # noqa: E731
    if kind == "opaque":
        add("MED", "archive-opaque", "", "compressed container not listed or opened by this scanner; "
            "inspect it separately in an isolated directory")
        return
    names, trav, links, execs, nested, enc = [], [], [], [], [], 0
    declared = scanned_total = scanned_members = 0
    stopped = ""
    try:
        if kind == "zip":
            with zipfile.ZipFile(path) as zf:
                infos = zf.infolist()
                for zi in infos[:MAX_MEMBERS]:
                    name = zi.filename
                    names.append(name)
                    declared += zi.file_size
                    bad = _bad_path(name)
                    if bad:
                        trav.append("%s (%s)" % (name, bad))
                    mode = (zi.external_attr >> 16) & 0xFFFF
                    if stat.S_ISLNK(mode):
                        links.append(name)
                    if zi.flag_bits & 0x1:
                        enc += 1
                    ext = _ext(name)
                    if ext in EXEC_EXT:
                        execs.append(name)
                    if ext in ARCHIVE_EXT:
                        nested.append(name)
                    if zi.compress_size and zi.file_size / max(1, zi.compress_size) > 200 and zi.file_size > 50_000_000:
                        stopped = "member %s expands %dx" % (name, zi.file_size // max(1, zi.compress_size))
                    if (not zi.is_dir() and not (zi.flag_bits & 0x1) and not stat.S_ISLNK(mode)
                            and zi.file_size <= MAX_MEMBER_BYTES and scanned_members < MAX_SCAN_MEMBERS
                            and scanned_total < MAX_SCAN_TOTAL and not bad and ext not in ARCHIVE_EXT):
                        try:
                            with zf.open(zi) as fh:
                                data = fh.read(MAX_MEMBER_BYTES + 1)
                        except Exception:
                            data = None
                        if data is not None and len(data) <= MAX_MEMBER_BYTES:
                            scanned_members += 1
                            scanned_total += len(data)
                            S.scan_member(fc, name, data)
                    if budget.expired():
                        stopped = stopped or "time budget"
                        break
                if len(infos) > MAX_MEMBERS:
                    stopped = stopped or "%d members (only first %d listed)" % (len(infos), MAX_MEMBERS)
        else:
            with tarfile.open(path, "r:*") as tf:
                count = 0
                for m in tf:
                    count += 1
                    name = m.name
                    names.append(name)
                    declared += max(0, m.size)
                    bad = _bad_path(name)
                    if bad:
                        trav.append("%s (%s)" % (name, bad))
                    if m.issym() or m.islnk():
                        target = m.linkname or ""
                        links.append("%s -> %s" % (name, target))
                        if _bad_path(target):
                            trav.append("%s -> %s (link target escapes)" % (name, target))
                    elif m.ischr() or m.isblk() or m.isfifo():
                        links.append("%s (device/fifo)" % name)
                    ext = _ext(name)
                    if ext in EXEC_EXT or (m.isreg() and m.mode & 0o6000):
                        execs.append(name + (" (setuid/setgid)" if m.mode & 0o6000 else ""))
                    if ext in ARCHIVE_EXT:
                        nested.append(name)
                    if declared > MAX_DECLARED:
                        stopped = "declared size exceeds %d bytes" % MAX_DECLARED
                        break
                    if count >= MAX_MEMBERS:
                        stopped = "more than %d members" % MAX_MEMBERS
                        break
                    if (m.isreg() and 0 < m.size <= MAX_MEMBER_BYTES and scanned_members < MAX_SCAN_MEMBERS
                            and scanned_total < MAX_SCAN_TOTAL and not bad and ext not in ARCHIVE_EXT):
                        try:
                            fh = tf.extractfile(m)
                            data = fh.read(MAX_MEMBER_BYTES + 1) if fh else None
                        except Exception:
                            data = None
                        if data is not None and len(data) <= MAX_MEMBER_BYTES:
                            scanned_members += 1
                            scanned_total += len(data)
                            S.scan_member(fc, name, data)
                    if budget.expired():
                        stopped = "time budget"
                        break
    except (zipfile.BadZipFile, tarfile.TarError, OSError, EOFError, ValueError, RuntimeError,
            NotImplementedError, MemoryError) as exc:
        add("MED", "archive-error", "", "archive could not be read (%s); treat as uninspected" % type(exc).__name__)
        return
    S.inv("archive %s: %d member(s) listed, %d text member(s) scanned in memory, %d bytes declared" % (
        S.safe(fc.rel, 100), len(names), scanned_members, declared))
    if trav:
        add("HIGH", "archive-traversal", "; ".join(sorted(trav)[:4]),
            "%d member path(s) would be written outside the extraction directory" % len(trav))
    if links:
        add("MED", "archive-link", "; ".join(sorted(links)[:4]), "%d link/device member(s)" % len(links))
    if execs:
        add("MED", "archive-executable", "; ".join(sorted(execs)[:6]),
            "%d executable/script member(s) inside the archive" % len(execs))
    if nested:
        add("MED", "archive-nested", "; ".join(sorted(nested)[:4]), "%d nested archive(s) not opened" % len(nested))
    if enc:
        add("MED", "archive-encrypted", "", "%d encrypted member(s) cannot be inspected" % enc)
    if stopped:
        add("HIGH" if "expands" in stopped or "declared size" in stopped else "MED", "archive-bomb", stopped,
            "archive listing stopped early: %s" % stopped)
