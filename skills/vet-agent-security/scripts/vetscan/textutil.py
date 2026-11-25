"""Text utilities: byte decoding, normalization views, sanitization, secret masking.

Every regex here is written to be linear-time on adversarial input: bounded
repeats or unambiguous ones (an inner repeat inside an outer one only where each
iteration is a forced token sequence, as in _TAG_RX), literal or look-behind anchors.

Special characters are always written as integer code points (never as raw
characters), so that this source file itself contains no invisible characters.
"""
import re
import unicodedata

# ---------------------------------------------------------------- decoding


def looks_binary(data):
    """True if the byte sample is not text in any encoding we handle."""
    sample = data[:8192]
    if not sample:
        return False
    if sample.startswith((b"\xef\xbb\xbf", b"\xff\xfe", b"\xfe\xff")):
        return False
    if b"\x00" in sample:
        return _utf16_guess(sample) is None
    ctrl = sum(1 for b in sample if b < 9 or 13 < b < 27 or 27 < b < 32)
    return ctrl > len(sample) * 0.10


def _utf16_guess(sample):
    """Guess BOM-less UTF-16 by the position of NUL bytes."""
    n = len(sample) - (len(sample) % 2)
    if n < 8:
        return None
    even = sample[0:n:2].count(0)
    odd = sample[1:n:2].count(0)
    half = n // 2
    guess = None
    if odd > half * 0.6 and even < half * 0.1:
        guess = "utf-16-le"
    elif even > half * 0.6 and odd < half * 0.1:
        guess = "utf-16-be"
    if guess is None:
        return None
    # Binary tables full of small 16-bit numbers have the same NUL pattern: require real text.
    try:
        text = sample[:n].decode(guess)
    except UnicodeDecodeError:
        return None
    printable = sum(1 for ch in text if ch.isprintable() or ch in "\r\n\t")
    return guess if printable >= len(text) * 0.9 else None


def decode_bytes(data):
    """Decode bytes to text. Returns (text, encoding_label). Never raises."""
    if data.startswith(b"\xef\xbb\xbf"):
        return data[3:].decode("utf-8", "replace"), "utf-8-bom"
    if data.startswith(b"\xff\xfe\x00\x00") or data.startswith(b"\x00\x00\xfe\xff"):
        return data.decode("utf-32", "replace"), "utf-32"
    if data.startswith(b"\xff\xfe") or data.startswith(b"\xfe\xff"):
        return data.decode("utf-16", "replace"), "utf-16"
    guess = _utf16_guess(data[:8192]) if b"\x00" in data[:8192] else None
    if guess:
        return data.decode(guess, "replace"), guess
    try:
        return data.decode("utf-8"), "utf-8"
    except UnicodeDecodeError:
        return data.decode("utf-8", "replace"), "utf-8-lossy"


def normalize_eol(text):
    """CRLF and lone CR become LF so line numbers and frontmatter parse the same everywhere."""
    if "\r" in text:
        text = text.replace("\r\n", "\n").replace("\r", "\n")
    return text


# ---------------------------------------------------------------- character classes


def cls(*items):
    """Build the inside of a regex character class from code points / (lo, hi) ranges."""
    out = []
    for it in items:
        if isinstance(it, tuple):
            out.append(chr(it[0]) + "-" + chr(it[1]))
        else:
            out.append(chr(it))
    return "".join(out)


TAG_BLOCK = cls((0xE0000, 0xE007F))                       # Unicode Tags block
VS_CHARS = cls((0xFE00, 0xFE0F), (0xE0100, 0xE01EF),      # variation selectors (+ supplement)
               (0x180B, 0x180D), 0x180F)                  # Mongolian free variation selectors
ZW_CHARS = cls((0x200B, 0x200D),                          # ZWSP, ZWNJ, ZWJ
               0x2060, 0xFEFF, 0x00AD, 0x180E, 0x034F,    # WJ, BOM/ZWNBSP, soft hyphen, MVS, CGJ
               (0x115F, 0x1160), 0x3164, 0xFFA0,          # Hangul fillers
               (0x2061, 0x2064), (0x206A, 0x206F),        # invisible operators, deprecated formats
               (0x17B4, 0x17B5))                          # Khmer invisible vowels
BIDI_CTRL = cls((0x202A, 0x202E), (0x2066, 0x2069))       # embeddings, overrides, isolates
BIDI_MARKS = cls((0x200E, 0x200F), 0x061C)                # LRM, RLM, ALM
OTHER_FMT = cls((0xFFF9, 0xFFFB), (0x1D173, 0x1D17A))     # interlinear annotation, musical formats
INLINE_MARK = "\x01"                                      # inserted by the HTML walker at inline tag joins

INVISIBLE_RX = re.compile("[" + TAG_BLOCK + VS_CHARS + ZW_CHARS + BIDI_CTRL + BIDI_MARKS + OTHER_FMT
                          + INLINE_MARK + "]")
_COMBINING_RX = re.compile("[" + cls((0x0300, 0x036F), (0x0483, 0x0489), (0x1AB0, 0x1AFF),
                                     (0x1DC0, 0x1DFF), (0x20D0, 0x20FF), (0xFE20, 0xFE2F)) + "]")
# Generic diacritics that may sit on letters of any script (an accented Latin word in NFD form).
GENERIC_MARKS = cls((0x0300, 0x036F), (0x1AB0, 0x1AFF), (0x1DC0, 0x1DFF), (0x20D0, 0x20FF), (0xFE20, 0xFE2F))
# Characters that draw nothing although Unicode does not class them as format characters.
BLANK_GLYPHS = (0x2800, 0x3164, 0x115F, 0x1160, 0xFFA0, 0xFFFC, 0x1D159, 0x17B4, 0x17B5, 0x16FE4, 0x2061, 0x2062,
                0x2063, 0x2064)


def _category_ranges():
    """Code-point ranges of format characters (Cf), non-whitespace controls (Cc) and marks (Mn, Me).

    Derived from the running Python's Unicode database (about 20 ms), so that new format characters
    are covered without a hand-kept list. Planes 2-13 and 15-16 hold no such characters."""
    fmt, marks = [], []
    for lo, hi in ((0, 0x20000), (0xE0000, 0xE1000)):
        for cp in range(lo, hi):
            cat = unicodedata.category(chr(cp))
            if cat == "Cf" or (cat == "Cc" and not chr(cp).isspace()):
                fmt.append(cp)
            elif cat in ("Mn", "Me"):
                marks.append(cp)

    def ranges(cps):
        out = []
        for cp in cps:
            if out and out[-1][1] == cp - 1:
                out[-1][1] = cp
            else:
                out.append([cp, cp])
        return "".join(chr(a) if a == b else chr(a) + "-" + chr(b) for a, b in out)
    return ranges(fmt), ranges(marks)


FORMAT_CHARS, MARK_CHARS = _category_ranges()
# Stripped from the de-obfuscated matching view: every format/control character and blank glyph.
STRIP_RX = re.compile("[" + FORMAT_CHARS + cls(*BLANK_GLYPHS) + INVISIBLE_RX.pattern[1:-1] + "]")
MARK_RX = re.compile("[" + MARK_CHARS + "]")

# ---------------------------------------------------------------- confusables
# A curated subset of look-alike letters (not the full UTS #39 confusables table).

_TO_LATIN_PAIRS = (
    # Cyrillic lower case
    (0x0430, "a"), (0x0432, "b"), (0x0433, "r"), (0x0435, "e"), (0x0451, "e"), (0x0438, "u"),
    (0x0439, "u"), (0x043A, "k"), (0x043C, "m"), (0x043D, "h"), (0x043E, "o"), (0x043F, "n"),
    (0x0440, "p"), (0x0441, "c"), (0x0442, "t"), (0x0443, "y"), (0x0445, "x"), (0x0448, "w"),
    (0x0449, "w"), (0x044C, "b"), (0x0455, "s"), (0x0456, "i"), (0x0457, "i"), (0x0458, "j"),
    (0x0501, "d"), (0x051B, "q"), (0x051D, "w"), (0x04BB, "h"), (0x04CF, "l"), (0x04BD, "e"),
    (0x0491, "r"), (0x0454, "e"), (0x0461, "w"), (0x0475, "v"), (0x04AF, "y"), (0x049D, "k"),
    (0x049B, "k"), (0x04B3, "x"), (0x050D, "g"),
    # Greek lower case
    (0x03B1, "a"), (0x03B2, "b"), (0x03B3, "y"), (0x03B4, "d"), (0x03B5, "e"), (0x03B6, "z"),
    (0x03B7, "n"), (0x03B8, "o"), (0x03B9, "i"), (0x03BA, "k"), (0x03BC, "u"), (0x03BD, "v"),
    (0x03BF, "o"), (0x03C0, "n"), (0x03C1, "p"), (0x03C3, "o"), (0x03C2, "s"), (0x03C4, "t"),
    (0x03C5, "u"), (0x03C7, "x"), (0x03C9, "w"), (0x03F2, "c"), (0x03F3, "j"), (0x03F5, "e"),
    (0x03F1, "p"),
    # Armenian, Coptic, IPA and letter-like symbols
    (0x0585, "o"), (0x0578, "n"), (0x057D, "u"), (0x0570, "h"), (0x0581, "g"), (0x0584, "p"),
    (0x0575, "j"), (0x2C9F, "o"), (0x2CA3, "p"), (0x2CA5, "c"), (0x2C81, "a"), (0x2C89, "e"),
    (0x0251, "a"), (0x0261, "g"), (0x0269, "i"), (0x026F, "w"), (0x028B, "u"), (0x1D26, "r"),
    (0x2113, "l"), (0x212F, "e"), (0x2134, "o"), (0x2139, "i"),
)
# Upper-case forms whose look-alike differs from the lower-case mapping above.
_TO_LATIN_UPPER = (
    (0x0412, "b"), (0x041D, "h"), (0x0423, "y"), (0x0413, "r"), (0x0406, "i"), (0x04C0, "i"),
    (0x0397, "h"), (0x039D, "n"), (0x039C, "m"), (0x03A5, "y"), (0x0393, "r"), (0x0399, "i"),
)
# Latin letters used to fake Cyrillic words (target code points are Cyrillic letters).
_TO_CYRILLIC_PAIRS = (
    ("a", 0x0430), ("c", 0x0441), ("e", 0x0435), ("o", 0x043E), ("p", 0x0440), ("x", 0x0445),
    ("y", 0x0443), ("k", 0x043A), ("m", 0x043C), ("t", 0x0442), ("n", 0x043F), ("u", 0x0438),
    ("r", 0x0433), ("b", 0x044C),
    ("A", 0x0430), ("C", 0x0441), ("E", 0x0435), ("O", 0x043E), ("P", 0x0440), ("X", 0x0445),
    ("Y", 0x0443), ("K", 0x043A), ("M", 0x043C), ("T", 0x0442), ("H", 0x043D), ("B", 0x0432),
    ("3", 0x0437), ("0", 0x043E), ("6", 0x0431),
)


def _build_tables():
    lat = {}
    name_rx = re.compile(
        r"^LATIN (?:(?:SMALL|CAPITAL) LETTER|LETTER SMALL CAPITAL)"
        r"(?: DOTLESS| SMALL CAPITAL| SCRIPT| OPEN| LONG| REVERSED)? ([A-Z])(?: |$)")
    for lo, hi in ((0x00C0, 0x02B0), (0x1D00, 0x1DC0), (0x1E00, 0x1F00), (0x2C60, 0x2C80),
                   (0xA720, 0xA800), (0xAB30, 0xAB70)):
        for cp in range(lo, hi):
            m = name_rx.match(unicodedata.name(chr(cp), ""))
            if m:
                lat[cp] = m.group(1).lower()
    for cp, to in _TO_LATIN_PAIRS:
        lat[cp] = to
        up = chr(cp).upper()
        if len(up) == 1 and ord(up) != cp:
            lat.setdefault(ord(up), to)
    for cp, to in _TO_LATIN_UPPER:
        lat[cp] = to
    for i in range(26):
        letter = chr(ord("a") + i)
        lat[0x1F1E6 + i] = letter   # regional indicator symbols
        lat[0x1F150 + i] = letter   # negative circled capitals
        lat[0x1F170 + i] = letter   # negative squared capitals
    cyr = {ord(a): chr(b) for a, b in _TO_CYRILLIC_PAIRS}
    return lat, cyr


TO_LATIN, TO_CYRILLIC = _build_tables()
_DEL_EMPH = {ord(c): None for c in "*~`" + INLINE_MARK}
LEET_1 = str.maketrans({"0": "o", "1": "i", "3": "e", "4": "a", "5": "s", "7": "t", "8": "b", "9": "g",
                        "@": "a", "$": "s", "!": "i", "|": "l", "+": "t"})
LEET_2 = str.maketrans({"0": "o", "1": "l", "3": "e", "4": "a", "5": "s", "7": "t", "8": "b", "9": "g",
                        "@": "a", "$": "s", "!": "l", "|": "i", "+": "t"})
ROT13 = str.maketrans("abcdefghijklmnopqrstuvwxyz", "nopqrstuvwxyzabcdefghijklm")

# ---------------------------------------------------------------- matching views
# A "view" is lower-case text where every run of non-word characters is one space,
# except that newlines survive 1:1. So: line number == newline count + 1.

# An HTML start or end tag in the CommonMark sense: attributes may span lines and have any length.
# Every part is a forced token sequence (name, '=', quoted or bare value), so matching stays linear.
_TAG_RX = re.compile(
    r"</?[A-Za-z][A-Za-z0-9:_-]{0,30}"
    r"(?:\s+[A-Za-z_:][\w.:-]*(?:\s*=\s*(?:\"[^\"]*\"|'[^']*'|[^\s\"'=<>`]+))?)*\s*/?>")
_SHORT_COMMENT_RX = re.compile(r"<!--[^\n<>]{0,200}-->")
_COLLAPSE_RX = re.compile(r"(?:[^\w\n]|_)+")
_SPACED_RX = re.compile(r"(?<![^ \n])(?:\w ){3,}\w(?![^ \n])")
# One punctuation, symbol or separator character between two letters ("ig-nore", "in.struc.tions").
_INTRA_PUNCT_RX = re.compile(r"(?<=[^\W\d_])(?:[^\w\s]|_)(?=[^\W\d_])")
LEET_HINT_RX = re.compile(r"[a-z][013457@$!|+]+[a-z]|(?<![\w.])[013457@$!|][a-z]{2}")
_CYRILLIC_RX = re.compile("[" + cls((0x0400, 0x04FF)) + "]")
_LINE_KEEP = "\x02"     # stands for a newline removed together with a multi-line tag


def _finish(t):
    t = _COLLAPSE_RX.sub(" ", t)
    return t.replace(" \n", "\n").replace("\n ", "\n")


def _strip_tags(t, repl):
    """Remove tags. A tag that spans lines keeps the line count: its newlines move to the end of
    the line on which the tag ends, so the words it split are joined and line numbers stay exact
    for every line that does not contain the tag."""
    if "<" not in t:
        return t
    t = _TAG_RX.sub(lambda m: repl + _LINE_KEEP * m.group(0).count("\n"), t)
    if _LINE_KEEP not in t:
        return t
    parts = t.split("\n")
    for i, p in enumerate(parts):
        if _LINE_KEEP in p:
            parts[i] = p.replace(_LINE_KEEP, "") + "\n" * p.count(_LINE_KEEP)
    return "\n".join(parts)


def view_plain(text):
    """What a plain reader sees: tags and punctuation are separators, nothing is repaired."""
    return _finish(_strip_tags(text.lower().replace(_LINE_KEEP, " "), " "))


def view_raw(text):
    """Like view_plain but markup is not removed: tag and attribute names stay as words."""
    return _finish(text.lower())


_ENTITY_RX = re.compile(r"&(?:(shy|zwj|zwnj|lrm|rlm|ZeroWidthSpace|NoBreak|InvisibleTimes|InvisibleComma|"
                        r"ApplyFunction|it|ic|af);|#(?:[xX]0{0,8}([0-9A-Fa-f]{1,6})|0{0,8}([0-9]{1,7}));)")


def _invisible_entity(m):
    """Delete a character reference that stands for an invisible character (&shy;, &#8203; ...)."""
    if m.group(1):
        return ""
    try:
        ch = chr(int(m.group(2), 16) if m.group(2) else int(m.group(3)))
    except (ValueError, OverflowError):
        return m.group(0)
    return "" if STRIP_RX.match(ch) or MARK_RX.match(ch) else m.group(0)


def deobf_base(text):
    """Strip format, control and blank-glyph characters (also written as character references),
    compatibility-decompose, strip all marks."""
    t = _ENTITY_RX.sub(_invisible_entity, text) if "&" in text else text
    t = STRIP_RX.sub("", t)
    if not t.isascii():
        t = unicodedata.normalize("NFKD", t)
        t = MARK_RX.sub("", t)
    return t


def deobf_pre(base, table):
    """Map look-alike letters and delete intra-word markup. Result is not yet collapsed."""
    t = base
    if table is TO_CYRILLIC or not base.isascii():
        t = base.translate(table)
    t = t.lower()
    t = _SHORT_COMMENT_RX.sub("", t)
    t = _strip_tags(t, "")
    return t.translate(_DEL_EMPH)


def join_intra_punct(pre):
    """Delete a single punctuation/symbol character that stands between two letters."""
    return _INTRA_PUNCT_RX.sub("", pre)


def view_from_pre(pre, leet=None):
    return _finish(pre.translate(leet) if leet else pre)


def squeeze_lines(view):
    """Drop blank lines when a view has a long run of them, so that a phrase split by any number of
    newlines is matched like one split by a single newline. Returns (view, linemap) where
    linemap[i] is the original line number of line i+1 of the returned view (None: unchanged)."""
    if "\n" * 16 not in view:
        return view, None
    keep = [(i + 1, ln) for i, ln in enumerate(view.split("\n")) if ln.strip()]
    if not keep:
        return "", [1]
    return "\n".join(ln for _n, ln in keep), [n for n, _l in keep]


def join_spaced(view):
    """Join runs of single-character tokens ('i g n o r e' -> 'ignore').

    Returns (new_view, runs) where runs is a list of (line, joined_text)."""
    if not _SPACED_RX.search(view):
        return view, []
    raw = []

    def repl(m):
        joined = m.group(0).replace(" ", "")
        if len(raw) < 2000:
            raw.append((m.start(), joined))
        return joined

    out = _SPACED_RX.sub(repl, view)
    located = []
    last_pos, last_line = 0, 1
    for pos, joined in raw:
        last_line += view.count("\n", last_pos, pos)
        last_pos = pos
        located.append((last_line, joined))
    return out, located


def has_cyrillic(text):
    return bool(_CYRILLIC_RX.search(text))


def line_of(text, pos):
    return text.count("\n", 0, pos) + 1


# ---------------------------------------------------------------- output sanitization

_UNSAFE_RX = re.compile("[" + cls(
    (0x00, 0x1F), (0x7F, 0x9F), 0x00AD, 0x034F, 0x061C, (0x115F, 0x1160), (0x17B4, 0x17B5),
    (0x180B, 0x180F), (0x200B, 0x200F), (0x2028, 0x202E), (0x2060, 0x206F), 0x3164,
    (0xFE00, 0xFE0F), 0xFEFF, 0xFFA0, (0xFFF0, 0xFFFF), (0xD800, 0xDFFF), (0xE000, 0xF8FF),
    (0x1D173, 0x1D17A), (0xE0000, 0xE0FFF), (0xF0000, 0x10FFFF)) + "]")
_WS_RX = re.compile(r"[ \t\r\n\f\v]+")
_SCHEME_RX = re.compile(r"\b([A-Za-z][A-Za-z0-9+.-]{1,15})://")
_JS_SCHEME_RX = re.compile(r"\b(javascript|vbscript|data):", re.I)


def _esc(m):
    return "<U+%04X>" % ord(m.group(0))


def sanitize(s, limit=180):
    """Make untrusted text safe to print: no control, format, invisible or private-use
    characters; no live URLs; no markdown code-span or link break-outs; bounded length."""
    if not isinstance(s, str):
        s = str(s)
    if len(s) > limit * 6:
        s = s[: limit * 6]
    s = _WS_RX.sub(" ", s).strip()
    s = _UNSAFE_RX.sub(_esc, s)
    if not s.isascii():
        out = []
        for ch in s:
            cat = unicodedata.category(ch)
            if cat[0] == "C" or cat in ("Zl", "Zp"):
                out.append("<U+%04X>" % ord(ch))
            else:
                out.append(ch)
        s = "".join(out)
    s = mask_secrets(s)
    s = _SCHEME_RX.sub(r"\1[:]//", s)
    s = _JS_SCHEME_RX.sub(r"\1[:]", s)
    s = s.replace("`", "'").replace("](", "] (")
    if len(s) > limit:
        s = s[:limit] + "..."
    return s


# ---------------------------------------------------------------- secrets

SECRET_PATTERNS = (
    ("anthropic-key", r"sk-ant-[A-Za-z0-9_\-]{20,}"),
    ("openai-key", r"sk-(?:proj-|svcacct-|admin-)?[A-Za-z0-9_\-]{32,}"),
    ("github-token", r"gh[pousr]_[A-Za-z0-9]{36,}"),
    ("github-pat", r"github_pat_[A-Za-z0-9_]{40,}"),
    ("aws-key-id", r"(?:AKIA|ASIA)[0-9A-Z]{16}"),
    ("slack-token", r"xox[baprs]-[A-Za-z0-9-]{10,}"),
    ("google-key", r"AIza[0-9A-Za-z_\-]{35}"),
    ("gitlab-token", r"glpat-[A-Za-z0-9_\-]{20,}"),
    ("npm-token", r"npm_[A-Za-z0-9]{36}"),
    ("hf-token", r"hf_[A-Za-z0-9]{30,}"),
    ("stripe-key", r"[sr]k_live_[A-Za-z0-9]{20,}"),
    ("sendgrid-key", r"SG\.[A-Za-z0-9_\-]{20,}\.[A-Za-z0-9_\-]{20,}"),
    ("telegram-bot-token", r"\d{8,10}:AA[A-Za-z0-9_\-]{32,}"),
    ("discord-webhook", r"discord(?:app)?\.com/api/webhooks/\d+/[A-Za-z0-9_\-]{20,}"),
    ("slack-webhook", r"hooks\.slack\.com/services/[A-Za-z0-9/]{20,}"),
    ("private-key-block", r"-----BEGIN (?:RSA |OPENSSH |EC |DSA |PGP |ENCRYPTED )?PRIVATE KEY(?: BLOCK)?-----"),
    ("jwt", r"eyJ[A-Za-z0-9_\-]{10,}\.eyJ[A-Za-z0-9_\-]{10,}\.[A-Za-z0-9_\-]{10,}"),
)
SECRET_RX = re.compile(
    r"(?<![A-Za-z0-9_\-])(?:" + "|".join("(?P<%s>%s)" % (n.replace("-", "_"), p) for n, p in SECRET_PATTERNS) + ")")
SECRET_ANCHORS = ("sk-", "ghp_", "gho_", "ghu_", "ghs_", "ghr_", "github_pat_", "akia", "asia", "xox", "aiza",
                  "glpat-", "npm_", "hf_", "k_live_", "sg.", "api/webhooks/", "hooks.slack.com",
                  "private key", ":aa", "eyj")
_ASSIGN_RX = re.compile(
    r"(?i)([A-Za-z0-9_.-]{0,40}(?:pass(?:word|wd|phrase)?|pwd|secret|token|api[_-]?key|apikey|access[_-]?key|"
    r"credential|private[_-]?key|authorization)[A-Za-z0-9_-]{0,20})(\"?'?\s{0,3}[:=]\s{0,3}[\"']?|\s+)"
    r"([^\s\"',;<>{}()\[\]$%]{8,200})")
_URL_CRED_RX = re.compile(r"(://[^/\s:@]{1,80}:)([^@\s/]{3,200})(@)")
_CLI_USER_RX = re.compile(r"(?i)((?:\s-u|--user)[ =]{1,3}[^\s:]{1,60}:)([^\s@]{3,200})")
_BEARER_RX = re.compile(r"(?i)\b((?:bearer|basic)\s{1,3})([A-Za-z0-9._~+/=-]{12,400})")
_QUERY_SECRET_RX = re.compile(
    r"(?i)([?&](?:token|key|secret|password|pass|sig|signature|auth|access_token|api_key|apikey|code|session)=)"
    r"([^&\s#]{6,300})")
PLACEHOLDER_RX = re.compile(
    r"(?i)example|sample|dummy|placeholder|redacted|your[_-]?|xxxx|\*\*\*|0000000|1234567|abcdefg|changeme|"
    r"fake|test|todo|<[a-z_ -]+>|\.\.\.")


def _mask_token(tok):
    return tok[:4] + "...[masked %d chars]" % len(tok)


def mask_secrets(s):
    """Replace anything that looks like a credential with a short masked form."""
    s = SECRET_RX.sub(lambda m: _mask_token(m.group(0)), s)
    s = _URL_CRED_RX.sub(lambda m: m.group(1) + "[masked]" + m.group(3), s)
    s = _CLI_USER_RX.sub(lambda m: m.group(1) + "[masked]", s)
    s = _BEARER_RX.sub(lambda m: m.group(1) + "[masked]", s)
    s = _QUERY_SECRET_RX.sub(lambda m: m.group(1) + "[masked]", s)

    def assign(m):
        val = m.group(3)
        if "[masked" in val or val.lower() in ("none", "null", "true", "false", "undefined"):
            return m.group(0)
        if m.group(2).strip() == "" and not re.search(r"[0-9]", val):
            return m.group(0)   # plain prose such as "token budget", not an assignment
        return m.group(1) + m.group(2) + _mask_token(val)

    return _ASSIGN_RX.sub(assign, s)


def is_placeholder_secret(tok):
    """True for obviously fake credentials (documentation examples)."""
    if PLACEHOLDER_RX.search(tok):
        return True
    body = re.sub(r"[^A-Za-z0-9]", "", tok)[8:]
    if len(body) >= 8 and len(set(body)) <= max(3, len(body) // 8):
        return True
    return False
