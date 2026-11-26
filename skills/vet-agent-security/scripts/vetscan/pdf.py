"""Best-effort, bounded text extraction from PDF files (standard library only).

What it does: finds every "N G obj ... stream ... endstream" object, undoes the stream filters it knows
(FlateDecode with size and ratio caps, ASCIIHexDecode, ASCII85Decode, RunLengthDecode, LZWDecode),
and pulls text out of content streams (the strings of the Tj, TJ, ' and " operators, decoded byte by
byte without font maps), out of object streams (string literals) and out of XMP metadata.

What it reports as NOT analyzed (the caller marks the scan incomplete): encrypted files, filters it does
not implement, streams over the size or ratio caps or that fail to decompress, and text drawn with glyph
codes that cannot be read without the font's ToUnicode map. Images are never analyzed (text in images is
out of reach, as the README says). Nothing is rendered or executed.
"""
import re
import zlib

MAX_OBJECTS = 20_000
MAX_STREAM_OUT = 8_000_000          # decoded bytes per stream
MAX_TOTAL_OUT = 40_000_000          # decoded bytes per file
MAX_RATIO = 200                     # decoded / encoded, above 1 MB of output (decompression bomb guard)
MAX_TEXT = 4_000_000                # extracted characters per file

_OBJ_RX = re.compile(rb"(\d{1,10})\s{1,10}(\d{1,5})\s{1,10}obj\b")
_STREAM_KW = re.compile(rb"stream\r?\n|stream\r")
_FILTER_RX = re.compile(rb"/Filter\s{0,10}(\[[^\]]{0,400}\]|/[A-Za-z0-9]{1,40})")
_NAME_RX = re.compile(rb"/([A-Za-z0-9]{1,40})")
_LENGTH_RX = re.compile(rb"/Length\s{1,10}(\d{1,10})(?!\d)(?!\s{1,10}\d{1,5}\s{1,10}R)")
_IMAGE_FILTERS = frozenset((b"DCTDecode", b"DCT", b"JPXDecode", b"CCITTFaxDecode", b"CCF", b"JBIG2Decode"))
_KNOWN_FILTERS = frozenset((b"FlateDecode", b"Fl", b"ASCIIHexDecode", b"AHx", b"ASCII85Decode", b"A85",
                            b"RunLengthDecode", b"RL", b"LZWDecode", b"LZW"))
# Content-stream tokens: a hex string, an array bracket, a name, a number or operator, a comment, or the
# "(" that starts a literal string. Literal strings (nested parentheses, escapes) are read by
# _read_string, which only moves forward, so a stream full of unclosed "(" stays linear.
_TOK = re.compile(rb"<[0-9A-Fa-f\s]{0,20000}>|\[|\]|/[^\s/<>\[\]()%{}]{0,127}|[^\s/<>\[\]()%{}]{1,64}|"
                  rb"%[^\r\n]{0,500}|\(")
_STR_SPECIAL = re.compile(rb"[()\\]")
MAX_STRING = 65_536
_ESC = {b"n": b"\n", b"r": b"\r", b"t": b"\t", b"b": b"\b", b"f": b"\f", b"(": b"(", b")": b")", b"\\": b"\\"}
_ESC_RX = re.compile(rb"\\([nrtbf()\\]|[0-7]{1,3}|\r\n|\r|\n)")


def _read_string(data, start):
    """(token, end) of the literal string that starts with "(" at `start` (balanced parentheses,
    backslash escapes). An unterminated string ends at MAX_STRING bytes or at the end of the data."""
    depth, j, limit = 1, start + 1, min(len(data), start + MAX_STRING)
    while depth:
        m = _STR_SPECIAL.search(data, j, limit)
        if not m:
            return data[start:limit], limit
        k = m.start()
        c = data[k]
        if c == 0x5C:                       # backslash: skip the escaped byte
            j = k + 2
        elif c == 0x28:
            depth += 1
            j = k + 1
        else:
            depth -= 1
            j = k + 1
    return data[start:j], j


def _tokens(data):
    """Content-stream tokens in order (literal strings included)."""
    pos, n = 0, len(data)
    while pos < n:
        m = _TOK.search(data, pos)
        if not m:
            return
        if m.group(0) == b"(":
            tok, pos = _read_string(data, m.start())
            yield tok
        else:
            pos = m.end()
            yield m.group(0)


def _literals(data, min_len=6):
    """Literal strings anywhere in `data` (object streams, annotation dictionaries)."""
    pos = 0
    while True:
        i = data.find(b"(", pos)
        if i < 0:
            return
        tok, pos = _read_string(data, i)
        if len(tok) >= min_len + 2:
            yield tok
_PRINTABLE = frozenset(range(32, 127)) | {9, 10, 13}


class PdfText:
    __slots__ = ("visible", "hidden", "meta", "limits", "info")

    def __init__(self):
        self.visible = []        # text drawn on pages (render modes other than invisible)
        self.hidden = []         # invisible text (render mode 3), strings in object streams, metadata
        self.meta = []
        self.limits = {}         # reason -> count of content that was not analyzed
        self.info = {"objects": 0, "streams": 0, "decoded": 0, "images": 0, "fonts": 0}

    def limit(self, reason, n=1):
        self.limits[reason] = self.limits.get(reason, 0) + n


def _unescape(raw):
    def repl(m):
        g = m.group(1)
        if g in _ESC:
            return _ESC[g]
        if g[:1] in b"\r\n":
            return b""                       # line continuation
        return bytes((int(g, 8) & 0xFF,))
    return _ESC_RX.sub(repl, raw)


def _string_bytes(tok):
    if tok[:1] == b"(":
        return _unescape(tok[1:-1])
    hexs = re.sub(rb"\s", b"", tok[1:-1])
    if len(hexs) % 2:
        hexs += b"0"
    try:
        return bytes.fromhex(hexs.decode("ascii"))
    except ValueError:
        return b""


def _readable(b):
    """Text for the bytes of one PDF string, or None when they look like glyph codes of a font."""
    if not b:
        return ""
    if b[:2] == b"\xfe\xff":
        return b[2:].decode("utf-16-be", "replace")
    if len(b) >= 4 and len(b) % 2 == 0 and b[0::2].count(0) >= len(b) // 2 * 0.9:
        return b.decode("utf-16-be", "replace")        # two-byte codes that are plain Unicode
    printable = sum(1 for x in b if x in _PRINTABLE or x >= 160)
    if printable >= len(b) * 0.85:
        return b.decode("latin-1")
    return None


def _lzw(data, cap):
    """LZWDecode (early change 1), bounded."""
    out = bytearray()
    table = [bytes((i,)) for i in range(256)] + [b"", b""]
    bits, buf, nbits, prev = 9, 0, 0, b""
    for byte in data:
        buf = (buf << 8) | byte
        nbits += 8
        while nbits >= bits:
            nbits -= bits
            code = (buf >> nbits) & ((1 << bits) - 1)
            if code == 256:
                table = table[:258]
                bits, prev = 9, b""
                continue
            if code == 257:
                return bytes(out)
            if code < len(table):
                entry = table[code]
            elif code == len(table) and prev:
                entry = prev + prev[:1]
            else:
                raise ValueError("bad LZW code")
            out += entry
            if len(out) > cap:
                raise OverflowError
            if prev:
                table.append(prev + entry[:1])
                if len(table) + 1 >= (1 << bits) and bits < 12:
                    bits += 1
            prev = entry
    return bytes(out)


def _decode(data, filters, budget_left):
    """Apply the filter chain. Returns (bytes, None) or (None, reason)."""
    for f in filters:
        if f in (b"FlateDecode", b"Fl"):
            d = zlib.decompressobj()
            try:
                out = d.decompress(data, min(MAX_STREAM_OUT, budget_left) + 1)
            except zlib.error:
                # damaged streams often still inflate up to the damage; keep what came out
                return None, "PDF stream that does not decompress"
            if len(out) > min(MAX_STREAM_OUT, budget_left):
                return None, "PDF stream over the size limit"
            if len(out) > 1_000_000 and len(out) > MAX_RATIO * max(1, len(data)):
                return None, "PDF stream with an implausible compression ratio (bomb guard)"
            data = out
        elif f in (b"ASCIIHexDecode", b"AHx"):
            hexs = re.sub(rb"[^0-9A-Fa-f]", b"", data.split(b">", 1)[0])
            if len(hexs) % 2:
                hexs += b"0"
            data = bytes.fromhex(hexs.decode("ascii"))
        elif f in (b"ASCII85Decode", b"A85"):
            import base64
            body = data.strip()
            if body.startswith(b"<~"):
                body = body[2:]
            body = body.split(b"~>", 1)[0]
            try:
                data = base64.a85decode(re.sub(rb"\s", b"", body))
            except ValueError:
                return None, "PDF stream that does not decode (ASCII85)"
        elif f in (b"RunLengthDecode", b"RL"):
            out, i = bytearray(), 0
            while i < len(data):
                n = data[i]
                if n == 128:
                    break
                if n < 128:
                    out += data[i + 1:i + 2 + n]
                    i += n + 2
                else:
                    out += data[i + 1:i + 2] * (257 - n)
                    i += 2
                if len(out) > MAX_STREAM_OUT:
                    return None, "PDF stream over the size limit"
            data = bytes(out)
        elif f in (b"LZWDecode", b"LZW"):
            try:
                data = _lzw(data, min(MAX_STREAM_OUT, budget_left))
            except OverflowError:
                return None, "PDF stream over the size limit"
            except ValueError:
                return None, "PDF stream that does not decode (LZW)"
        else:
            return None, "PDF stream filter not supported (%s)" % f.decode("ascii", "replace")
    return data, None


def _content_text(data, out):
    """Strings shown by text operators. Returns (visible text, invisible text, glyph-code string count)."""
    vis, hid = [], []
    operands, glyph, mode = [], 0, 0
    for tok in _tokens(data[:MAX_STREAM_OUT]):
        c = tok[:1]
        if c in (b"(", b"<") and tok != b"<<":
            operands.append(tok)
            continue
        if c in (b"[", b"]", b"/", b"%"):
            operands.append(tok)
            continue
        if tok in (b"Tj", b"'", b'"', b"TJ"):
            strings, gap = [], False
            if tok == b"TJ":
                # strings inside the array; a large negative number between them is a word space
                depth = 0
                for t in reversed(operands):
                    if t == b"]":
                        depth += 1
                    elif t == b"[":
                        break
                    elif t[:1] in (b"(", b"<"):
                        strings.append((t, gap))
                        gap = False
                    else:
                        try:
                            gap = gap or float(t) < -180
                        except ValueError:
                            pass
                strings.reverse()
            else:
                for t in reversed(operands):
                    if t[:1] in (b"(", b"<"):
                        strings.append((t, False))
                        break
            parts = []
            for t, space_after in strings:
                text = _readable(_string_bytes(t))
                if text is None:
                    glyph += 1
                    continue
                parts.append(text + (" " if space_after else ""))
            line = "".join(parts)
            (hid if mode == 3 else vis).append(line)
            operands = []
        elif tok == b"Tr":
            try:
                mode = int(operands[-1]) if operands else 0
            except ValueError:
                mode = 0
            operands = []
        elif tok in (b"ET", b"T*", b"Td", b"TD", b"Tm"):
            (hid if mode == 3 else vis).append("\n")
            operands = []
        elif c.isalpha() or c in (b"'", b'"', b"*"):
            operands = []
        else:
            operands.append(tok)
            if len(operands) > 4000:
                operands = operands[-2000:]
    return "".join(vis), "".join(hid), glyph


def extract(data):
    """PdfText for the bytes of one PDF file."""
    res = PdfText()
    if re.search(rb"/Encrypt\s{0,10}(?:\d|<<)", data[-200_000:]) or re.search(rb"/Encrypt\s{0,10}\d", data[:200_000]):
        res.limit("encrypted PDF: streams not analyzed")
    total_out = 0
    pos = 0
    n_obj = 0
    glyph_total = 0
    text_chars = 0
    while True:
        m = _OBJ_RX.search(data, pos)
        if not m:
            break
        n_obj += 1
        if n_obj > MAX_OBJECTS:
            res.limit("PDF objects beyond the object limit (%d)" % MAX_OBJECTS)
            break
        end = data.find(b"endobj", m.end())
        if end < 0:
            end = len(data)
        sm = _STREAM_KW.search(data, m.end(), end)
        if not sm:
            pos = end + 6 if end < len(data) else len(data)
            chunk = data[m.end():min(end, m.end() + MAX_STREAM_OUT)]
            if b"(" in chunk and b"/Annot" in chunk:
                for lit in _literals(chunk):
                    t = _readable(_unescape(lit[1:-1]))
                    if t:
                        res.hidden.append(t)
            continue
        res.info["streams"] += 1
        head = data[m.end():sm.start()]
        body_start = sm.end()
        es = data.find(b"endstream", body_start, end + 9 if end < len(data) else len(data))
        if es < 0:
            es = end
        lm = _LENGTH_RX.search(head)
        if lm and body_start + int(lm.group(1)) <= es:
            raw = data[body_start:body_start + int(lm.group(1))]
        else:
            raw = data[body_start:es].rstrip(b"\r\n")
        pos = max(es + 9, end + 6) if end < len(data) else len(data)
        fm = _FILTER_RX.search(head)
        filters = [f for f in _NAME_RX.findall(fm.group(1))] if fm else []
        if any(f in _IMAGE_FILTERS for f in filters) or re.search(rb"/Subtype\s{0,5}/Image", head):
            res.info["images"] += 1
            continue
        if re.search(rb"/Length[123]\b|/Subtype\s{0,5}/(?:Type1C|CIDFontType0C|OpenType)\b", head):
            res.info["fonts"] += 1
            continue
        if re.search(rb"/Type\s{0,5}/XRef\b", head):
            continue
        unknown = [f for f in filters if f not in _KNOWN_FILTERS]
        if unknown:
            res.limit("PDF stream filter not supported (%s)" % unknown[0].decode("ascii", "replace"))
            continue
        decoded, why = _decode(raw, filters, MAX_TOTAL_OUT - total_out)
        if why:
            res.limit(why)
            continue
        total_out += len(decoded)
        res.info["decoded"] += 1
        if total_out >= MAX_TOTAL_OUT:
            res.limit("PDF content beyond the per-file decode limit")
            break
        if re.search(rb"/Type\s{0,5}/ObjStm\b", head):
            for lit in _literals(decoded[:MAX_STREAM_OUT]):
                t = _readable(_unescape(lit[1:-1]))
                if t:
                    res.hidden.append(t)
            continue
        if re.search(rb"/Type\s{0,5}/Metadata\b", head) or decoded[:200].lstrip().startswith(b"<?xpacket"):
            res.meta.append(decoded[:MAX_STREAM_OUT].decode("utf-8", "replace"))
            continue
        if b"begincmap" in decoded[:4000]:
            continue                          # ToUnicode / CMap program, not page text
        vis, hid, glyph = _content_text(decoded, res)
        glyph_total += glyph
        if vis.strip():
            res.visible.append(vis)
            text_chars += len(vis)
        if hid.strip():
            res.hidden.append(hid)
            text_chars += len(hid)
        if text_chars > MAX_TEXT:
            res.limit("PDF text beyond the per-file extraction limit")
            break
    if glyph_total:
        res.limit("PDF text drawn with font glyph codes (no ToUnicode decoding): not read", glyph_total)
    res.info["objects"] = n_obj
    return res
