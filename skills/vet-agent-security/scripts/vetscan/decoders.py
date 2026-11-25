"""Decode-and-rescan layer: finds encoded blobs and returns their decoded text.

Layers: base64 (standard, url-safe, MIME-wrapped, same-line string concatenation),
base32, base85 (RFC 1924 / Python), Ascii85, Z85, quoted-printable, 8-bit binary digits,
hex (contiguous or byte-separated),
\\x, \\u and octal escapes, UTF-7, percent-encoding, HTML numeric entities,
character-code lists (comma- or space-separated), plus gzip/zlib/bz2/xz inside a decoded blob.
Decoding is bounded by size and count; nothing decoded is ever executed. Every limit that
leaves content undecoded is counted and reported.  (ROT13 and reversed text are handled in phrases.)
"""
import base64
import binascii
import bz2
import codecs
import html
import lzma
import math
import re
import urllib.parse
import zlib

from . import textutil as T

MAX_CANDIDATES = 4000          # per text
MAX_DECODED_CHARS = 3_000_000  # per text
MAX_BLOB_INPUT = 87_400        # base64 characters decoded per blob (64 KiB)
MAX_INFLATE = 262_144
BLOB_MIN = 512                 # opaque blob size worth reporting

_B64 = re.compile(r"(?<![A-Za-z0-9+/=_-])[A-Za-z0-9+/_-]{24,}={0,2}(?![A-Za-z0-9+/_-])")
_B64_WRAPPED = re.compile(
    r"(?m)^[ \t]{0,8}[A-Za-z0-9+/]{16,}[ \t]{0,4}\n(?:[ \t]{0,8}[A-Za-z0-9+/]{16,}[ \t]{0,4}\n){1,}"
    r"[ \t]{0,8}[A-Za-z0-9+/]{0,200}={0,2}")
_QP_RUN = re.compile(r"(?:=[0-9A-F]{2}){6,}|(?:=[0-9a-f]{2}){6,}")
_BIN_RUN = re.compile(r"(?<![01])[01]{8}(?:[ \t,]{0,2}[01]{8}){7,}(?![01])")
_CONCAT = re.compile(r"[\"'][ \t]{0,4}\+[ \t]{0,4}[\"']")
_HEX = re.compile(r"(?<![0-9A-Fa-f])(?:[0-9A-Fa-f]{2}){16,}(?![0-9A-Fa-f])")
# Hex bytes separated by spaces, tabs, newlines, ':' ',' ';' or '-' ("49 67 6e ...", "49:67:6e").
_HEX_SEP = re.compile(r"(?<![0-9A-Za-z])[0-9A-Fa-f]{2}(?:(?:[ \t]{1,3}|[ \t]{0,2}[:,;-][ \t]{0,2}|[ \t]{0,2}\n[ \t]{0,2})"
                      r"[0-9A-Fa-f]{2}){11,}(?![0-9A-Za-z])")
_OCT_ESC = re.compile(r"(?:\\[0-3][0-7]{2}){8,}")
_UTF7 = re.compile(r"\+[A-Za-z0-9+/]{8,4000}-?")
_B32 = re.compile(r"(?<![A-Za-z0-9+/=_-])(?:[A-Z2-7]{16,}|[a-z2-7]{16,})={0,6}(?![A-Za-z0-9+/=_-])")
B85_ALPHABET = "0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz!#$%&()*+-;<=>?@^_`{|}~"
Z85_ALPHABET = "0123456789abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ.-:+=^!/*?&<>()[]{}@%$#"
_B85_RUN = re.compile("[" + re.escape(B85_ALPHABET) + "]{20,}")
_Z85_RUN = re.compile("[" + re.escape(Z85_ALPHABET) + "]{20,}")
_A85_RUN = re.compile(r"[!-uz]{20,}")
_B85_TABLE = {c: i for i, c in enumerate(B85_ALPHABET)}
_Z85_TABLE = {c: i for i, c in enumerate(Z85_ALPHABET)}
_A85_TABLE = {chr(33 + i): i for i in range(85)}
MAX_B85_TRIES = 200_000        # cheap prefix checks per text (each looks at 10 characters)
_HEX_ESC = re.compile(r"(?:\\x[0-9A-Fa-f]{2}){8,}")
_UNI_ESC = re.compile(r"(?:\\u[0-9A-Fa-f]{4}){6,}|(?:\\u\{[0-9A-Fa-f]{1,6}\}){6,}")
_PCT_RUN = re.compile(r"(?:%[0-9A-Fa-f]{2}){6,}")
_PCT_ONE = re.compile(r"%[0-9A-Fa-f]{2}")
_TOKEN = re.compile(r"[^\s\"'<>()\[\]{}]{12,4000}")
_ENT_RUN = re.compile(r"(?:&#[xX]?[0-9A-Fa-f]{1,7};){6,}")
_ENT_NUM = re.compile(r"&#([xX]?)([0-9A-Fa-f]{1,7});")
_ENT_NAMED = re.compile(r"&[A-Za-z][A-Za-z0-9]{1,30};")
_ENT_LETTER = re.compile(
    r"&#(?:[xX](?:4[1-9A-Fa-f]|5[0-9Aa]|6[1-9A-Fa-f]|7[0-9Aa]|4[1-4][0-9A-Fa-f])|"
    r"(?:6[5-9]|[78][0-9]|90|9[7-9]|1[01][0-9]|12[0-2]|10[4-9][0-9]|110[0-3]));")
_CHARCODES = re.compile(
    r"(?:\b\d{2,3}(?:[ \t]{0,2}[,;][ \t]{0,2}|[ \t]{1,3}|[ \t]{0,2}\n[ \t]{0,2})){11,}\d{2,3}\b")
_HEXCODES = re.compile(r"(?:0x[0-9A-Fa-f]{2}[ \t]{0,2},[ \t]{0,2}){11,}0x[0-9A-Fa-f]{2}")
_WORD = re.compile("[A-Za-z" + T.cls((0x0400, 0x04FF)) + "]{3,}")
_BLOB_OK_PREFIX = re.compile(
    r"(?i)(?:data:(?:image|font|audio|video)/[a-z0-9.+-]{1,30};base64,|data:application/(?:font[a-z0-9-]{0,12}|"
    r"x-font[a-z0-9-]{0,12}|pdf|octet-stream);base64,|integrity\s{0,2}=\s{0,2}[\"']?sha\d{3}-|sha\d{3}-|"
    r"\"image/(?:png|jpe?g|gif|webp)\"\s{0,2}:\s{0,2}\")$")


def entropy(s):
    """Shannon entropy in bits per character."""
    if not s:
        return 0.0
    n = len(s)
    counts = {}
    for ch in s:
        counts[ch] = counts.get(ch, 0) + 1
    return -sum(c / n * math.log2(c / n) for c in counts.values())


class Candidate:
    __slots__ = ("kind", "line", "text", "prefix")

    def __init__(self, kind, line, text, prefix=""):
        self.kind = kind
        self.line = line
        self.text = text
        self.prefix = prefix


def as_text(data):
    """Return decoded text if the bytes look like human-readable text, else None."""
    if len(data) < 8:
        return None
    if data[:2] == b"\x1f\x8b" or (data[0] == 0x78 and data[1] in (0x01, 0x5E, 0x9C, 0xDA)):
        try:
            wbits = 16 + zlib.MAX_WBITS if data[:2] == b"\x1f\x8b" else zlib.MAX_WBITS
            data = zlib.decompressobj(wbits).decompress(data, MAX_INFLATE)
        except zlib.error:
            return None
        if len(data) < 8:
            return None
    elif data[:3] == b"BZh" or data[:6] == b"\xfd7zXZ\x00":
        try:
            dec = bz2.BZ2Decompressor() if data[:3] == b"BZh" else lzma.LZMADecompressor()
            data = dec.decompress(data, MAX_INFLATE)
        except (OSError, EOFError, ValueError, lzma.LZMAError):
            return None
        if len(data) < 8:
            return None
    s = None
    if len(data) >= 16 and data[1:16:2].count(0) >= 6 and data[0:16:2].count(0) == 0:
        try:
            s = data.decode("utf-16-le")
        except UnicodeDecodeError:
            s = None
    elif len(data) >= 16 and data[0:16:2].count(0) >= 6 and data[1:16:2].count(0) == 0:
        try:
            s = data.decode("utf-16-be")
        except UnicodeDecodeError:
            s = None
    if s is None:
        # A few undecodable bytes (a junk prefix, a stray byte) do not hide the text: they count as bad
        # characters below instead of rejecting the whole blob.
        s = data.decode("utf-8", "replace")
    n = len(s)
    good = sum(1 for ch in s if (ch.isprintable() and ch != "\ufffd") or ch in "\n\r\t")
    if good < n * 0.92:
        return None
    letters = sum(1 for ch in s if ch.isalpha() or ch == " ")
    if not _WORD.search(s) or (letters < n * 0.55 and len(_WORD.findall(s, 0, 4000)) < 6):
        return None
    return s


def _b64_bytes(tok):
    tok = tok[:MAX_BLOB_INPUT].rstrip("=")
    if "-" in tok or "_" in tok:
        tok = tok.replace("-", "+").replace("_", "/")
    rem = len(tok) % 4
    if rem == 1:
        tok = tok[:-1]
        rem = 0
    if rem:
        tok += "=" * (4 - rem)
    try:
        return binascii.a2b_base64(tok)
    except (binascii.Error, ValueError):
        return None


def _base85_bytes(tok, table, zero_z=False):
    """Decode a base-85 string (RFC 1924, Z85 or Ascii85 alphabet via `table`). A short final group
    is padded the way Ascii85 does. Returns None on an invalid group."""
    out = bytearray()
    group = []
    for ch in tok[:MAX_BLOB_INPUT]:
        if zero_z and ch == "z" and not group:
            out += b"\0\0\0\0"
            continue
        v = table.get(ch)
        if v is None:
            return None
        group.append(v)
        if len(group) == 5:
            acc = 0
            for x in group:
                acc = acc * 85 + x
            if acc > 0xFFFFFFFF:
                return None
            out += acc.to_bytes(4, "big")
            group = []
    if len(group) >= 2:
        n = len(group)
        acc = 0
        for x in group + [84] * (5 - n):
            acc = acc * 85 + x
        if acc > 0xFFFFFFFF:
            return None
        out += acc.to_bytes(4, "big")[:n - 1]
    return bytes(out)


def _mostly_printable(raw):
    """At most one byte of the sample is outside printable ASCII / UTF-8 lead bytes."""
    return raw is not None and len(raw) >= 4 and sum(
        1 for b in raw if 32 <= b < 127 or b in (9, 10, 13) or b >= 0xC2) >= len(raw) - 1


_B85_START_AFTER = frozenset("\"'>:(=,;[{}|")


def _base85_family(text, state, room, push, partial):
    """base85 / Ascii85 / Z85 runs. Their alphabets contain markup characters, so a run may begin
    with a tag or attribute tail ('">', 'content:"'): besides the run start, every position up to
    32 characters in that follows such a delimiter is tried. Each start is checked cheaply (its first
    two groups must decode to printable bytes); up to 5 trailing characters are dropped (markup glued
    to the end of a run)."""
    for rx, table, kind, zero_z in ((_B85_RUN, _B85_TABLE, "base85", False),
                                    (_A85_RUN, _A85_TABLE, "ascii85", True),
                                    (_Z85_RUN, _Z85_TABLE, "z85", False)):
        for m in rx.finditer(text):
            run = m.group(0)
            if run.startswith("<~"):
                run = run[2:]
            starts = [0] + [i for i in range(1, min(33, len(run) - 19)) if run[i - 1] in _B85_START_AFTER]
            for start in starts:
                if state["tries"] >= MAX_B85_TRIES:
                    state["skipped"] += 1
                    return
                state["tries"] += 1
                tok = run[start:]
                if not _mostly_printable(_base85_bytes(tok[:10], table, zero_z)):
                    continue
                if not room():
                    return
                tok = tok.split("~>", 1)[0]
                found = False
                for cut in range(6):
                    raw = _base85_bytes(tok[:len(tok) - cut] if cut else tok, table, zero_z)
                    dec = as_text(raw) if raw else None
                    if dec:
                        partial(len(tok), MAX_BLOB_INPUT)
                        push(kind, m.start() + start, text, dec)
                        found = True
                        break
                if found:
                    break


def _unescape_numeric(text, letters):
    """Decode numeric character references; when letters=False keep the ones that encode letters/digits."""
    def repl(m):
        try:
            cp = int(m.group(2), 16 if m.group(1) else 10)
            ch = chr(cp)
        except (ValueError, OverflowError):
            return m.group(0)
        if not letters and ch.isalnum():
            return m.group(0)
        return ch if ch != "\n" else " "
    return _ENT_NUM.sub(repl, text)


def entity_variants(text):
    """If letters are written as numeric character references, return
    (text_with_only_punctuation_decoded, text_fully_decoded); else None."""
    if "&#" not in text:
        return None
    n = len(_ENT_LETTER.findall(text))
    if n < 3 or text.count("&#") > 200_000:
        return None
    named = lambda t: _ENT_NAMED.sub(lambda m: html.unescape(m.group(0)), t)   # noqa: E731
    return named(_unescape_numeric(text, False)), named(_unescape_numeric(text, True))


def find(text, budget=None, stats=None, only=None):
    """Return (candidates, blobs, exhausted). only="base85" runs the base85 family alone (used on
    entity-decoded markup text, where only that family can contain escaped characters).

    candidates: list[Candidate] with decoded text
    blobs:      list[(line, length, kind)] opaque encoded blobs that are not text
    exhausted:  number of encoded blobs skipped because a limit was hit
    stats:      optional dict; stats["partial"] counts blobs decoded only up to the size limit"""
    cands, blobs = [], []
    state = {"n": 0, "chars": 0, "skipped": 0, "partial": 0, "tries": 0}

    def room():
        if state["n"] >= MAX_CANDIDATES or state["chars"] >= MAX_DECODED_CHARS:
            state["skipped"] += 1
            return False
        return not (budget and budget.expired())

    lines = {}     # id(source text) -> [last position, last line]: matches arrive in order

    def line_at(src, pos):
        st = lines.setdefault(id(src), [0, 1])
        if pos < st[0]:
            st[0], st[1] = 0, 1
        st[1] += src.count("\n", st[0], pos)
        st[0] = pos
        return st[1]

    def push(kind, pos, src, decoded):
        state["n"] += 1
        state["chars"] += len(decoded)
        cands.append(Candidate(kind, line_at(src, pos), decoded, src[max(0, pos - 60):pos]))

    def partial(tok_len, limit):
        if tok_len > limit:
            state["partial"] += 1

    if only == "base85":
        _base85_family(text, state, room, push, partial)
        if stats is not None:
            stats["partial"] = stats.get("partial", 0) + state["partial"]
        return cands, blobs, state["skipped"]

    # --- base64 (optionally with same-line "a" + "b" concatenation removed)
    b64_src = text
    if "+" in text and ('"' in text or "'" in text):
        joined = _CONCAT.sub("", text)
        if len(joined) != len(text):
            b64_src = joined
    if len(b64_src) >= 24:
        for m in _B64.finditer(b64_src):
            if not room():
                break
            tok = m.group(0)
            raw = _b64_bytes(tok)
            dec = as_text(raw) if raw else None
            if dec:
                partial(len(tok), MAX_BLOB_INPUT)
                push("base64", m.start(), b64_src, dec)
            elif len(tok) >= BLOB_MIN:
                pre = b64_src[max(0, m.start() - 60):m.start()]
                if not _BLOB_OK_PREFIX.search(pre):
                    kind = "base64"
                    if raw and raw[:4] in (b"\x00asm", b"MZ\x90\x00", b"\x7fELF", b"PK\x03\x04"):
                        kind = "base64-binary-executable"
                    if kind != "base64" or entropy(tok[:4096]) >= 4.5:    # skip low-entropy filler
                        blobs.append((line_at(b64_src, m.start()), len(tok), kind))
        if "\n" in text:
            for m in _B64_WRAPPED.finditer(text):
                if not room():
                    break
                tok = "".join(m.group(0).split())
                raw = _b64_bytes(tok)
                dec = as_text(raw) if raw else None
                if dec:
                    push("base64-wrapped", m.start(), text, dec)
                elif len(tok) >= BLOB_MIN:
                    blobs.append((line_at(text, m.start()), len(tok), "base64-wrapped"))

    # --- base32 (upper- or lower-case alphabet, optional padding)
    for m in _B32.finditer(text):
        if not room():
            break
        tok = m.group(0).rstrip("=")[:MAX_BLOB_INPUT]
        if len(tok) % 8 in (1, 3, 6):
            tok = tok[:len(tok) - len(tok) % 8]
        try:
            raw = base64.b32decode(tok + "=" * (-len(tok) % 8), casefold=True)
        except (binascii.Error, ValueError):
            continue
        dec = as_text(raw)
        if dec:
            partial(len(m.group(0)), MAX_BLOB_INPUT)
            push("base32", m.start(), text, dec)

    _base85_family(text, state, room, push, partial)

    # --- hex and escapes
    for m in _HEX.finditer(text):
        if not room():
            break
        try:
            raw = bytes.fromhex(m.group(0)[:131072])
        except ValueError:
            continue
        dec = as_text(raw)
        if dec:
            push("hex", m.start(), text, dec)
    if "=" in text:
        for m in _QP_RUN.finditer(text):            # quoted-printable: =49=67=6E...
            if not room():
                break
            dec = as_text(bytes.fromhex(m.group(0)[:120000].replace("=", "")))
            if dec:
                push("quoted-printable", m.start(), text, dec)
    for m in _BIN_RUN.finditer(text):               # 8-bit binary groups: 01001001 01100111 ...
        if not room():
            break
        bits = re.sub(r"[^01]", "", m.group(0)[:400000])
        dec = as_text(bytes(int(bits[i:i + 8], 2) for i in range(0, len(bits) - 7, 8)))
        if dec:
            push("binary-digits", m.start(), text, dec)
    for m in _HEX_SEP.finditer(text):
        if not room():
            break
        digits = re.sub(r"[^0-9A-Fa-f]", "", m.group(0)[:262144])
        try:
            raw = bytes.fromhex(digits)
        except ValueError:
            continue
        dec = as_text(raw)
        if dec:
            push("hex-bytes", m.start(), text, dec)
    if "\\" in text:
        for m in _OCT_ESC.finditer(text):
            if not room():
                break
            raw = bytes(int(o, 8) for o in m.group(0)[:262144].split("\\")[1:])
            dec = as_text(raw)
            if dec:
                push("octal-escapes", m.start(), text, dec)
    if "+" in text:
        for m in _UTF7.finditer(text):
            if not room():
                break
            tok = m.group(0)
            try:
                dec = codecs.decode(tok.encode("ascii") + (b"" if tok.endswith("-") else b"-"), "utf-7")
            except (UnicodeDecodeError, ValueError):
                continue
            if dec != tok and as_text(dec.encode("utf-8", "replace")):
                push("utf-7", m.start(), text, dec)
    if "\\x" in text:
        for m in _HEX_ESC.finditer(text):
            if not room():
                break
            try:
                raw = bytes.fromhex(m.group(0)[:262144].replace("\\x", ""))
            except ValueError:
                continue
            dec = as_text(raw)
            if dec:
                push("hex-escapes", m.start(), text, dec)
    if "\\u" in text:
        for m in _UNI_ESC.finditer(text):
            if not room():
                break
            parts = re.findall(r"[0-9A-Fa-f]{1,6}", m.group(0)[:60000].replace("\\u", " "))
            try:
                dec = "".join(chr(int(p, 16)) for p in parts)
            except (ValueError, OverflowError):
                continue
            if _WORD.search(dec):
                push("unicode-escapes", m.start(), text, dec)
    for rx, base in ((_CHARCODES, 10), (_HEXCODES, 16)):
        for m in rx.finditer(text):
            if not room():
                break
            nums = re.findall(r"[0-9A-Fa-f]{1,3}" if base == 16 else r"\d{1,3}",
                              m.group(0)[:20000].replace("0x", " "))
            try:
                vals = [int(x, base) for x in nums]
            except ValueError:
                continue
            if all(9 <= v <= 126 for v in vals):
                dec = "".join(map(chr, vals))
                if _WORD.search(dec):
                    push("char-codes", m.start(), text, dec)

    # --- percent-encoding
    if text.count("%") >= 3:
        for m in _PCT_RUN.finditer(text):
            if not room():
                break
            dec = as_text(urllib.parse.unquote_to_bytes(m.group(0)[:60000]))
            if dec:
                push("url-encoded", m.start(), text, dec)
        for m in _TOKEN.finditer(text):
            tok = m.group(0)
            if tok.count("%") < 3 or len(_PCT_ONE.findall(tok)) < 3:
                continue
            if not room():
                break
            dec = urllib.parse.unquote(tok, errors="replace")
            if dec != tok and _WORD.search(dec):
                push("url-encoded", m.start(), text, dec.replace("+", " "))

    # --- HTML numeric entities (pure runs)
    if "&#" in text:
        for m in _ENT_RUN.finditer(text):
            if not room():
                break
            dec = html.unescape(m.group(0)[:60000])
            if _WORD.search(dec):
                push("html-entities", m.start(), text, dec)
    if stats is not None:
        stats["partial"] = stats.get("partial", 0) + state["partial"]
    return cands, blobs, state["skipped"]
