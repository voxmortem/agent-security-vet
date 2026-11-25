"""Invisible / format character families with severity logic.

Families: Unicode Tags (decoded), variation selectors (decoded as bytes),
zero-width characters, bidirectional controls (Trojan Source), control
characters, other format characters, mixed-script look-alike tokens.
"""
import re
import unicodedata

from . import textutil as T
from .model import rule

rule("uni-tag-chars", "hidden", "Unicode TAG characters (invisible text readable by models)")
rule("uni-variation-selectors", "hidden", "variation selectors used as a hidden data channel")
rule("uni-zero-width-run", "hidden", "long or dense run of zero-width characters (possible steganography)")
rule("uni-zero-width", "hidden", "zero-width characters")
rule("uni-bidi", "hidden", "bidirectional control characters (Trojan Source)")
rule("uni-bidi-marks", "hidden", "bidirectional marks")
rule("uni-control-chars", "hidden", "raw control characters / terminal escape sequences")
rule("uni-format-chars", "hidden", "unusual format or separator characters")
rule("uni-mixed-script", "hidden", "word mixing Latin with look-alike Cyrillic/Greek letters")
rule("uni-invisible-other", "hidden", "other invisible format or blank-glyph characters (outside the known families)")
rule("uni-foreign-mark", "hidden", "combining mark of another script inside a Latin word")

MAX_RUNS = 20000
_FAMILIES = (T.TAG_BLOCK + T.VS_CHARS + T.ZW_CHARS + T.BIDI_CTRL + T.BIDI_MARKS + T.OTHER_FMT
             + T.cls((0x2028, 0x2029)) + T.INLINE_MARK)
_FAMILY_RX = re.compile("[" + _FAMILIES + "]")
# Every format character and blank glyph that no family above covers (U+1BCA0, U+2800, U+FFFC ...).
_GENERIC = re.compile("(?:(?![" + _FAMILIES + T.cls((0x00, 0x1F), (0x7F, 0x9F)) + "])["
                      + T.FORMAT_CHARS + T.cls(*T.BLANK_GLYPHS) + "])+")
_MARK_RUN = re.compile("[" + T.MARK_CHARS + "]+")
_GENERIC_MARK = re.compile("[" + T.GENERIC_MARKS + T.VS_CHARS + "]")

_TAG_RUN = re.compile("[" + T.TAG_BLOCK + "]+")
_VS_RUN = re.compile("[" + T.VS_CHARS + "]+")
_ZW_RUN = re.compile("[" + T.ZW_CHARS + "]+")
_BIDI = re.compile("[" + T.BIDI_CTRL + "]")
_BIDI_MARK = re.compile("[" + T.BIDI_MARKS + "]")
_CTRL = re.compile("[\x00-\x08\x0b\x0e-\x1f\x7f" + T.cls((0x80, 0x9F)) + "]")
_OTHER = re.compile("[" + T.OTHER_FMT + T.cls((0x2028, 0x2029)) + "]")
_RTL = re.compile("[" + T.cls((0x0590, 0x08FF), (0xFB1D, 0xFDFF), (0xFE70, 0xFEFC)) + "]")
_FLAG_BODY = re.compile(r"[a-z0-9]{2,7}\Z")

_CONF_CYR_GREEK = "".join(chr(cp) for cp in sorted(T.TO_LATIN) if 0x0370 <= cp <= 0x052F)
# Every alternative starts at a word start (look-behind) and every run is bounded, so a long run of
# letters cannot make the search quadratic.
_MIXED_LATIN = re.compile("(?<![A-Za-z])[A-Za-z]{1,40}[" + _CONF_CYR_GREEK + "]{1,10}[A-Za-z]{1,40}|"
                          "(?<![\\w])[" + _CONF_CYR_GREEK + "]{1,3}[A-Za-z]{3,40}")
_CYR = T.cls((0x0430, 0x044F), 0x0451)
_MIXED_CYR = re.compile("(?<![" + _CYR + "])(?:[" + _CYR + "]{2,40}[aceopxyACEHKMOPTX]{1,10}[" + _CYR + "]{1,40}|"
                        "[" + _CYR + "]{1,40}[aceopxyACEHKMOPTX]{1,10}[" + _CYR + "]{2,40})")

BLACK_FLAG = 0x1F3F4
CANCEL_TAG = 0xE007F
ZWJ, ZWNJ, SHY = 0x200D, 0x200C, 0x00AD


def decode_tags(run):
    return "".join(chr(ord(c) - 0xE0000) for c in run if 0xE0020 <= ord(c) <= 0xE007E)


def _printable_ratio(s):
    if not s:
        return 0.0
    return sum(1 for ch in s if ch.isprintable() or ch in "\n\t") / len(s)


def _is_emojiish(cp):
    return (0x2190 <= cp <= 0x2BFF or 0x1F000 <= cp <= 0x1FAFF or cp in (0xFE0F, 0x20E3)
            or 0x1F3FB <= cp <= 0x1F3FF or 0x3030 <= cp <= 0x303D or cp in (0x00A9, 0x00AE, 0x2122))


def _is_joining_script(cp):
    return 0x0600 <= cp <= 0x08FF or 0x0900 <= cp <= 0x0DFF or 0xFB50 <= cp <= 0xFEFC or 0x1000 <= cp <= 0x109F


def _is_cjk(cp):
    return 0x2E80 <= cp <= 0x9FFF or 0xF900 <= cp <= 0xFAFF or 0x20000 <= cp <= 0x3FFFF


def scan(text, add, role, kind, prose=False):
    """Report invisible-character findings through add(sev, rule, line, snippet, note).

    Returns a list of (context_name, line, decoded_text) payloads for re-scanning."""
    payloads = []
    ctrl = _CTRL.search(text)
    if ctrl:
        n = len(_CTRL.findall(text))
        esc = "\x1b" in text
        add("MED" if esc else "LOW", "uni-control-chars", T.line_of(text, ctrl.start()), "",
            "%d raw control character(s)%s" % (n, "; includes ESC (terminal escape sequences can hide or "
                                               "rewrite displayed text)" if esc else ""))
    if text.isascii():
        return payloads
    code_like = not prose

    # ---- Unicode Tags
    tag_chars, tag_runs, first = [], 0, None
    for m in _TAG_RUN.finditer(text):
        run, s = m.group(0), m.start()
        if (s > 0 and ord(text[s - 1]) == BLACK_FLAG and len(run) <= 8 and ord(run[-1]) == CANCEL_TAG
                and _FLAG_BODY.match(decode_tags(run))):
            continue   # well-formed emoji subdivision flag
        tag_runs += 1
        if first is None:
            first = s
        if len(tag_chars) < 8000:
            tag_chars.append(run)
        if tag_runs >= MAX_RUNS:
            break
    if tag_runs:
        blob = "".join(tag_chars)
        dec = decode_tags(blob)
        line = T.line_of(text, first)
        note = "%d Unicode TAG character(s) in %d run(s): invisible to people, readable by models" % (
            len(blob), tag_runs)
        if dec.strip():
            note += "; decoded hidden text: \"%s\"" % T.sanitize(dec, 240)
            payloads.append(("unicode-tags", line, dec))
        add("HIGH", "uni-tag-chars", line, "", note)

    # ---- variation selectors
    sus, long_run, first, runs = [], 0, None, 0
    for m in _VS_RUN.finditer(text):
        run, s = m.group(0), m.start()
        runs += 1
        if runs > MAX_RUNS:
            break
        prev = ord(text[s - 1]) if s else 0x20
        if len(run) >= 2:
            long_run = max(long_run, len(run))
            sus.append(run)
            first = s if first is None else first
            continue
        cp = ord(run)
        if cp in (0xFE0F, 0xFE0E):
            odd = (0x41 <= prev <= 0x5A) or (0x61 <= prev <= 0x7A) or prev in (0x20, 0x0A)
        elif 0xFE00 <= cp <= 0xFE0D:
            odd = prev < 0x2000 and not (0x1800 <= prev <= 0x18AF)
        elif cp >= 0xE0100:
            odd = not _is_cjk(prev)
        else:
            odd = not (0x1800 <= prev <= 0x18AF)
        if odd:
            sus.append(run)
            first = s if first is None else first
    if sus:
        chars = "".join(sus)
        if long_run >= 2 or len(chars) >= 8:
            data = bytes((ord(c) - 0xFE00) if ord(c) <= 0xFE0F else min(255, ord(c) - 0xE0100 + 16)
                         for c in chars[:8000] if ord(c) >= 0xFE00)
            dec = data.decode("utf-8", "replace")
            note = "%d variation selector(s) not attached to a variation base (longest run %d): a known way to " \
                   "smuggle bytes inside one visible character" % (len(chars), long_run)
            line = T.line_of(text, first)
            if len(dec) >= 4 and _printable_ratio(dec) >= 0.7:
                note += "; decoded bytes as text: \"%s\"" % T.sanitize(dec, 240)
                payloads.append(("variation-selectors", line, dec))
            add("HIGH", "uni-variation-selectors", line, "", note)
        else:
            add("LOW", "uni-variation-selectors", T.line_of(text, first), "",
                "%d stray variation selector(s)" % len(chars))

    # ---- zero-width
    long_runs, longest, intra, other, soft, first_long, first_intra, first_other, runs = 0, 0, 0, 0, 0, None, None, None, 0
    n = len(text)
    for m in _ZW_RUN.finditer(text):
        run, s, e = m.group(0), m.start(), m.end()
        runs += 1
        if runs > MAX_RUNS:
            break
        if len(run) >= 6:
            long_runs += 1
            longest = max(longest, len(run))
            first_long = s if first_long is None else first_long
            continue
        prev = ord(text[s - 1]) if s else 0x20
        nxt = ord(text[e]) if e < n else 0x20
        cps = set(map(ord, run))
        if cps <= {ZWJ, ZWNJ} and (_is_emojiish(prev) or _is_emojiish(nxt) or _is_joining_script(prev)
                                   or _is_joining_script(nxt)):
            continue
        if cps == {SHY}:
            soft += 1
            continue
        if chr(prev).isalpha() and chr(nxt).isalpha() and prev < 0x0530 and nxt < 0x0530:
            intra += 1
            first_intra = s if first_intra is None else first_intra
        else:
            other += 1
            first_other = s if first_other is None else first_other
    if long_runs or runs > MAX_RUNS or intra + other >= 40:
        pos = first_long if first_long is not None else (first_intra if first_intra is not None else first_other)
        add("HIGH", "uni-zero-width-run", T.line_of(text, pos or 0), "",
            "%d run(s) of 6+ zero-width characters (longest %d), %d inside words, %d elsewhere: dense "
            "invisible characters can carry a hidden bit-stream" % (long_runs, longest, intra, other))
    elif intra:
        add("MED", "uni-zero-width", T.line_of(text, first_intra), "",
            "zero-width character(s) inside %d word(s): splits words for scanners and filters" % intra)
    if (other or soft) and not (long_runs or intra + other >= 40):
        pos = first_other if first_other is not None else 0
        add("LOW", "uni-zero-width", T.line_of(text, pos), "",
            "%d zero-width character run(s) outside words, %d soft hyphen run(s)" % (other, soft))

    # ---- bidi controls
    # RLO/LRO/RLE/RLI can make the displayed order differ from the logical order of left-to-right
    # text. LRE/LRI/FSI and the terminators cannot reorder left-to-right text on their own.
    bidi = list(_BIDI.finditer(text))[:MAX_RUNS] if _BIDI.search(text) else []
    if bidi:
        reorder = [m for m in bidi if ord(m.group(0)) in (0x202E, 0x202D, 0x202B, 0x2067)]
        inert = [m for m in bidi if ord(m.group(0)) not in (0x202E, 0x202D, 0x202B, 0x2067)]
        summary = "; %d bidirectional control(s) in file, %d of them can reorder text" % (len(bidi), len(reorder))

        def context(m):
            ls = text.rfind("\n", 0, m.start()) + 1
            le = text.find("\n", m.start())
            return text[ls:le if le >= 0 else len(text)]

        shown, seen_lines = 0, set()
        for m in (bidi if code_like else reorder):
            if shown >= 3:
                break
            ctx = context(m)
            key = text.rfind("\n", 0, m.start())
            if key in seen_lines:
                continue
            seen_lines.add(key)
            is_override = ord(m.group(0)) in (0x202D, 0x202E)
            if code_like or is_override or not (role == "page" and _RTL.search(ctx)):
                sev = "HIGH"
            else:
                sev = "MED"     # a page that really contains right-to-left script
            add(sev, "uni-bidi", T.line_of(text, m.start()), T.sanitize(ctx, 160),
                "bidirectional control character%s%s" % (
                    " (override: displayed order differs from logical order)" if is_override else
                    " that can reorder displayed text", summary))
            shown += 1
        if inert and not code_like and not shown:
            m = inert[0]
            add("MED" if role == "instruction" else "LOW", "uni-bidi", T.line_of(text, m.start()),
                T.sanitize(context(m), 160),
                "bidirectional embedding/isolate/terminator in prose (cannot reorder left-to-right text by "
                "itself)%s" % summary)
    mk = _BIDI_MARK.search(text)
    if mk:
        cnt = len(_BIDI_MARK.findall(text))
        add("MED" if role == "code" else "LOW", "uni-bidi-marks", T.line_of(text, mk.start()), "",
            "%d bidirectional mark(s) (LRM/RLM/ALM)" % cnt)

    # ---- other format characters
    om = _OTHER.search(text)
    if om:
        add("LOW", "uni-format-chars", T.line_of(text, om.start()), "",
            "%d interlinear-annotation / line-separator / invisible musical format character(s)" %
            len(_OTHER.findall(text)))

    # ---- every other format character / blank glyph, and marks of a foreign script inside Latin words
    _other_invisible(text, add)
    _foreign_marks(text, add)

    # ---- mixed-script look-alikes
    mm = _MIXED_LATIN.search(text) or _MIXED_CYR.search(text)
    if mm:
        cnt = len(_MIXED_LATIN.findall(text)) + len(_MIXED_CYR.findall(text))
        add("LOW", "uni-mixed-script", T.line_of(text, mm.start()), T.sanitize(mm.group(0), 60),
            "%d word(s) mix Latin letters with look-alike Cyrillic/Greek letters" % cnt)
    return payloads


def _near_latin(ch):
    """A letter of the scripts the phrase sets cover (Latin, Greek, Cyrillic, Armenian)."""
    return ch.isalpha() and ord(ch) < 0x0530


def _other_invisible(text, add):
    """Format characters and blank glyphs outside the families above (U+1BCA0, U+2800, U+FFFC, ...).

    Inside a Latin/Greek/Cyrillic word they split the word for filters while staying invisible: MED.
    Elsewhere they are reported as LOW. Braille blanks next to Braille patterns are ordinary Braille."""
    intra = other = 0
    first_intra = first_other = None
    names = set()
    n = len(text)
    for k, m in enumerate(_GENERIC.finditer(text)):
        if k >= MAX_RUNS:
            break
        s, e = m.start(), m.end()
        prev = text[s - 1] if s else " "
        nxt = text[e] if e < n else " "
        run = m.group(0)
        if set(run) == {chr(0x2800)} and (0x2800 <= ord(prev) <= 0x28FF or 0x2800 <= ord(nxt) <= 0x28FF):
            continue
        if len(names) < 12:
            names.add("U+%04X" % ord(run[0]))
        if _near_latin(prev) and _near_latin(nxt):
            intra += 1
            first_intra = s if first_intra is None else first_intra
        else:
            other += 1
            first_other = s if first_other is None else first_other
    if intra:
        add("MED", "uni-invisible-other", T.line_of(text, first_intra), "",
            "%d invisible format / blank-glyph character run(s) inside words (%s): they split words for "
            "scanners and filters and draw nothing" % (intra, ", ".join(sorted(names)[:6])))
    elif other:
        add("LOW", "uni-invisible-other", T.line_of(text, first_other), "",
            "%d invisible format / blank-glyph character run(s) (%s)" % (other, ", ".join(sorted(names)[:6])))


_SCRIPT_WORDS = frozenset(("CYRILLIC", "GREEK", "LATIN", "HEBREW", "ARABIC", "SYRIAC", "ARMENIAN"))


def _mark_script(ch):
    """Script word of a combining mark, or '' for a generic diacritic usable with any script."""
    if _GENERIC_MARK.match(ch):
        return ""
    words = unicodedata.name(ch, "").split(" ")
    if words[0] == "COMBINING":
        return words[1] if len(words) > 2 and words[1] in _SCRIPT_WORDS else ""
    return words[0]


def _foreign_marks(text, add):
    """Combining marks of another script (a Hebrew accent, a Cyrillic VZMET, an Indic sign) placed on a
    Latin letter. Accented Latin text in decomposed form uses generic diacritics and is not reported."""
    count, first = 0, None
    for k, m in enumerate(_MARK_RUN.finditer(text)):
        if k >= MAX_RUNS:
            break
        s = m.start()
        base = text[s - 1] if s else " "
        if not base.isalpha() or not (base.isascii() or unicodedata.name(base, "").startswith("LATIN ")):
            continue
        if any(_mark_script(ch) not in ("", "LATIN") for ch in m.group(0)[:8]):
            count += 1
            first = s if first is None else first
    if count:
        add("MED", "uni-foreign-mark", T.line_of(text, first), "",
            "%d combining mark(s) of a non-Latin script sit on Latin letters: they split words for scanners "
            "while staying (nearly) invisible" % count)
