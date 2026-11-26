"""HTML / SVG / XML and Markdown structure analysis.

Splits a document into text streams by visibility (visible, hidden element,
attribute, comment, meta, JSON-LD, script, style, SVG, link titles) so that the
phrase scanner can treat hidden occurrences more severely than visible ones.

Never uses an entity-expanding XML parser: everything goes through the lenient
html.parser tokenizer, and comments are extracted by a separate linear scanner.
"""
import re
from html.parser import HTMLParser

from . import textutil as T

MARK = T.INLINE_MARK
MAX_COMMENTS = 20000
MAX_DEPTH = 1500
MAX_PENDING = 1_500_000     # unparsed parser buffer that makes us give up (quadratic-parse guard)

INLINE = frozenset(
    "a abbr acronym b bdi bdo big cite code data del dfn em font i ins kbd label mark nobr q rp rt ruby s samp "
    "small span strike strong sub sup time tspan tt u var wbr".split())
VOID = frozenset("area base br col embed hr img input link meta param source track wbr".split())
URL_ATTRS = frozenset("href src action formaction poster data ping background cite longdesc manifest "
                      "xlink:href srcset codebase".split())
SKIP_ATTRS = frozenset(
    "class id type rel lang dir role width height target method charset name property http-equiv integrity "
    "crossorigin loading decoding sizes media viewbox d points transform fill stroke xmlns version x y cx cy r "
    "rx ry x1 y1 x2 y2 tabindex colspan rowspan for enctype autocomplete nonce as async defer itemprop "
    "itemtype itemscope datetime".split())
UTIL_HIDDEN = frozenset(
    "hidden hide d-none invisible sr-only visually-hidden visuallyhidden screen-reader-text screen-reader-only "
    "offscreen off-screen is-hidden u-hidden display-none opacity-0 text-transparent".split())
STREAMS = ("visible", "hidden", "attr", "meta", "jsonld", "script", "style", "svg")

# ---------------------------------------------------------------- CSS hiding

_HIDE_RULES = (
    ("display:none", re.compile(r"display\s{0,3}:\s{0,3}none")),
    ("visibility:hidden", re.compile(r"visibility\s{0,3}:\s{0,3}(?:hidden|collapse)")),
    ("font-size:0", re.compile(
        r"font-size\s{0,3}:\s{0,3}(?:0(?:\.0{1,6})?(?:px|pt|em|rem|%|vw|vh)?|[01]px|0?\.\d{1,6}p[xt]|"
        r"0?\.0\d{0,6}r?em)\s{0,3}(?:;|!|$)|font\s{0,3}:\s{0,3}0(?:px)?\s{0,3}/")),
    ("opacity:0", re.compile(r"(?<![a-z-])opacity\s{0,3}:\s{0,3}(?:0(?:\.0\d{0,6})?|0?\.0\d{0,6}|[0-9](?:\.\d{1,4})?%)"
                             r"\s{0,3}(?:;|!|$)")),
    ("filter:opacity(0)", re.compile(r"filter\s{0,3}:\s{0,3}[^;]{0,80}opacity\(\s{0,3}(?:0(?:\.0\d{0,6})?|0?\.0\d{0,6}|"
                                     r"[0-9](?:\.\d{1,4})?%)\s{0,3}\)")),
    ("off-screen", re.compile(
        r"(?:left|top|right|bottom|margin-left|margin-top|text-indent)\s{0,3}:\s{0,3}-\s{0,2}"
        r"(?:\d{4,9}|[1-9]\d{2})(?:px|pt|em|rem|%|vw|vh)?|translate[xy]?\(\s{0,3}-\s{0,2}\d{4,9}|"
        r"text-indent\s{0,3}:\s{0,3}\d{4,9}(?:px|pt|em|rem)?")),
    ("clipped", re.compile(
        r"clip\s{0,3}:\s{0,3}rect\(\s{0,3}[01](?:px)?[\s,]{1,4}[01](?:px)?[\s,]{1,4}[01](?:px)?[\s,]{1,4}"
        r"[01](?:px)?\s{0,3}\)|clip-path\s{0,3}:\s{0,3}(?:inset\(\s{0,3}(?:50|100)%|circle\(\s{0,3}0|"
        r"polygon\(\s{0,3}0(?:px)?\s{1,3}0(?:px)?\s{0,3},\s{0,3}0(?:px)?\s{1,3}0(?:px)?\s{0,3},\s{0,3}0)")),
    ("transparent", re.compile(
        r"(?<![a-z-])(?:color|-webkit-text-fill-color)\s{0,3}:\s{0,3}(?:transparent|"
        r"(?:rgb|hsl)a?\(\s{0,3}[\d.]{1,8}(?:%|deg)?\s{0,3},\s{0,3}[\d.]{1,8}%?\s{0,3},\s{0,3}[\d.]{1,8}%?\s{0,3},"
        r"\s{0,3}(?:0(?:\.0\d{0,4})?|0?\.0\d{0,4}|[0-9](?:\.\d{1,4})?%)\s{0,3}\)|"
        r"(?:rgb|hsl)a?\([^)/]{0,40}/\s{0,3}(?:0(?:\.0\d{0,4})?|0?\.0\d{0,4}|[0-9](?:\.\d{1,4})?%)\s{0,3}\)|"
        r"#[0-9a-f]{6}0[0-9a-f]\b|#[0-9a-f]{3}0\b)")),
    ("scale(0)", re.compile(r"transform\s{0,3}:\s{0,3}[^;]{0,60}scale[xy]?\(\s{0,3}0(?:\.0{1,4})?\s{0,3}[,)]|"
                            r"(?<![a-z-])scale\s{0,3}:\s{0,3}0(?:\.0{1,4})?\s{0,3}(?:;|!|$)")),
    ("content-visibility", re.compile(r"content-visibility\s{0,3}:\s{0,3}hidden")),
    ("negative z-index", re.compile(r"z-index\s{0,3}:\s{0,3}-\s{0,2}[1-9]\d{0,9}")),
)
_ZERO_SIZE = re.compile(r"(?:^|;|\s)(?:max-)?(?:height|width)\s{0,3}:\s{0,3}[01](?:px)?\s{0,3}(?:;|!|$)")
_COLOR_DECL = re.compile(r"(?:^|;|\s)color\s{0,3}:\s{0,3}([^;!]{1,40})")
_BG_DECL = re.compile(r"background(?:-color)?\s{0,3}:\s{0,3}([^;!]{1,60})")
_HEX_COLOR = re.compile(r"#([0-9a-f]{3,8})\b")
_RGB_COLOR = re.compile(r"rgba?\(\s{0,3}(\d{1,3})%?[\s,]{1,4}(\d{1,3})%?[\s,]{1,4}(\d{1,3})%?")
_NAMED = {"white": (255, 255, 255), "black": (0, 0, 0), "snow": (255, 250, 250), "ivory": (255, 255, 240),
          "ghostwhite": (248, 248, 255), "whitesmoke": (245, 245, 245), "red": (255, 0, 0),
          "blue": (0, 0, 255), "green": (0, 128, 0), "gray": (128, 128, 128), "grey": (128, 128, 128)}
# A visibility-deciding property whose value comes from a custom property: the value may be set anywhere.
_INDIRECT = re.compile(r"(?:^|[;{\s])(?:display|visibility|opacity|position|clip|clip-path|font-size|color|"
                       r"transform|filter|content-visibility|z-index|text-indent|left|top|width|height)\s{0,3}:"
                       r"\s{0,3}[^;{}]{0,80}var\(")
_VAR_USE = re.compile(r"var\(\s{0,3}--([\w-]{1,80})\s{0,3}(?:,\s{0,3}([^()]{0,80}))?\)")
_VAR_DEF = re.compile(r"--([\w-]{1,80})\s{0,3}:\s{0,3}([^;{}]{1,120})")


def parse_color(val):
    val = val.strip().lower()
    m = _HEX_COLOR.match(val)
    if m:
        h = m.group(1)
        if len(h) in (3, 4):
            return tuple(int(c * 2, 16) for c in h[:3])
        if len(h) in (6, 8):
            return int(h[0:2], 16), int(h[2:4], 16), int(h[4:6], 16)
        return None
    m = _RGB_COLOR.match(val)
    if m:
        return tuple(min(255, int(x)) for x in m.groups())
    word = re.match(r"[a-z]{3,20}", val)
    if word:
        return _NAMED.get(word.group(0))
    return None


def resolve_style(style, custom=None):
    """CSS escapes undone and var(--x) replaced by its value (from `custom`, else the fallback)."""
    if "\\" in style:
        style = css_unescape(style) or style
    if "var(" in style:
        custom = custom or {}

        def sub(m):
            return custom.get(m.group(1), m.group(2) or "")
        for _ in range(3):              # nested var() chains, bounded
            new = _VAR_USE.sub(sub, style)
            if new == style:
                break
            style = new
    return style


def style_hidden(style, custom=None):
    """Return a short reason if an inline style (lower-cased) hides its element."""
    if "\\" in style or "var(" in style:
        style = resolve_style(style, custom)
    for name, rx in _HIDE_RULES:
        if rx.search(style):
            return name
    if _ZERO_SIZE.search(style) and ("overflow" in style or "absolute" in style or "fixed" in style):
        return "zero-size"
    return None


def _close(a, b):
    return a is not None and b is not None and sum(abs(x - y) for x, y in zip(a, b)) <= 30


_CSS_RULE = re.compile(r"([^{}]{1,400})\{([^{}]{0,4000})\}")
_CSS_SEL = re.compile(r"([.#])(-?[A-Za-z_][\w-]{0,80})")
_CSS_ESC = re.compile(r"\\(?:([0-9a-fA-F]{1,6})\s?|([^0-9a-fA-F\n]))")
_COMBINATOR = re.compile(r"[ \t\n\r\f]{0,20}([>+~])[ \t\n\r\f]{0,20}")
_COMPOUND_TAG = re.compile(r"^(\*|[a-z][\w-]{0,40})")
_COMPOUND_PART = re.compile(r"\.([\w-]{1,80})|#([\w-]{1,80})|\[\s{0,3}([\w:-]{1,60})\s{0,3}(?:([~|^$*]?=)\s{0,3}"
                            r"[\"']?([^\"'\]]{0,80})[\"']?\s{0,3}(?:\s[is])?)?\]|(::?)([\w-]{1,40})(\([^()]{0,80}\))?")
# Pseudo-classes that describe a state the page is not in by default, and pseudo-elements (the rule then
# hides generated content, not the element's text).
_STATEFUL = frozenset("hover focus active visited checked target focus-within focus-visible".split())
MAX_COMPLEX = 400


class CssInfo:
    __slots__ = ("classes", "ids", "complex", "custom", "indirect")

    def __init__(self):
        self.classes, self.ids, self.complex, self.custom, self.indirect = set(), set(), [], {}, []


def _parse_compound(tok):
    """'div.a#b[data-k="1"]' -> (tag, classes, id, attrs) or None when it cannot be matched statically."""
    tag = None
    m = _COMPOUND_TAG.match(tok)
    pos = 0
    if m:
        tag = None if m.group(1) == "*" else m.group(1)
        pos = m.end()
    classes, ident, attrs = set(), None, []
    while pos < len(tok):
        m = _COMPOUND_PART.match(tok, pos)
        if not m:
            return None
        pos = m.end()
        if m.group(1):
            classes.add(m.group(1))
        elif m.group(2):
            ident = m.group(2)
        elif m.group(3):
            attrs.append((m.group(3), m.group(4) or "", m.group(5) or ""))
        elif m.group(6):
            if m.group(6) == "::" or m.group(7) in _STATEFUL or m.group(7) in ("before", "after", "placeholder",
                                                                            "selection", "marker"):
                return None
    if tag is None and not classes and ident is None and not attrs:
        return ("*", frozenset(), None, ()) if tok.startswith("*") else None
    return (tag, frozenset(classes), ident, tuple(attrs))


def parse_selector(sel):
    """'article > div.z + p' -> [(compound, combinator-to-the-left)...] right to left, or None."""
    sel = _COMBINATOR.sub(lambda m: " %s " % m.group(1), sel.strip())
    if not sel or len(sel) > 300:
        return None
    toks = sel.split()
    out, comb = [], " "
    for tok in toks:
        if tok in (">", "+", "~"):
            comb = tok
            continue
        c = _parse_compound(tok)
        if c is None:
            return None
        out.append((c, comb if out else ""))
        comb = " "
    if not out or len(out) > 5:
        return None
    return out[::-1]


def css_hidden_selectors(css, info=None):
    """What a <style> block hides: classes and ids (last compound, as before), complex selectors
    (tags, attribute selectors, child and sibling combinators), custom properties, var() indirection."""
    info = info or CssInfo()
    low = css.lower()
    if "--" in low:
        for m in _VAR_DEF.finditer(low[:400_000]):
            if len(info.custom) < 2000:
                info.custom.setdefault(m.group(1), m.group(2).strip())
    if "{" not in low:
        return info
    for m in _CSS_RULE.finditer(low[:400_000]):
        decl = m.group(2)
        if "var(" in decl and _INDIRECT.search(decl) and len(info.indirect) < 20:
            info.indirect.append(" ".join((m.group(1).strip()[-60:] + "{" + decl.strip()[:80] + "}").split()))
        if not style_hidden(decl, info.custom):
            col, bg = _COLOR_DECL.search(decl), _BG_DECL.search(decl)
            if not (col and bg and _close(parse_color(col.group(1)), parse_color(bg.group(1)))):
                continue
        for sel in m.group(1).split(","):
            sel = sel.strip()
            if not sel or sel.startswith("@"):
                continue
            last = sel.split()[-1]
            if "::" in last or any(":" + p in last for p in _STATEFUL):
                continue
            found = _CSS_SEL.findall(last)
            for kind, name in found:
                (info.classes if kind == "." else info.ids).add(name)
            if (not found or any(c in sel for c in "+~")) and len(info.complex) < MAX_COMPLEX:
                chain = parse_selector(sel)
                if chain and chain not in info.complex:
                    info.complex.append(chain)
    return info


def _compound_matches(c, desc):
    tag, classes, ident, attrs = c
    dtag, dclasses, did, dattrs = desc
    if tag not in (None, "*") and tag != dtag:
        return False
    if classes and not classes <= dclasses:
        return False
    if ident is not None and ident != did:
        return False
    for name, op, val in attrs:
        if name not in dattrs:
            return False
        have = dattrs[name]
        if op == "=" and have != val or op == "~=" and val not in have.split() or \
                op == "^=" and not have.startswith(val) or op == "$=" and not have.endswith(val) or \
                op == "*=" and val not in have or op == "|=" and not (have == val or have.startswith(val + "-")):
            return False
    return True


def _chain_matches(chain, path, i, sibs):
    """chain[k:] matched right to left. path: descriptors of the open elements (root first), the element
    itself last; sibs[d]: descriptors of the earlier siblings of path[d]. Memoized on (k, depth, number of
    earlier siblings), so the work is bounded by len(chain) x depth x siblings."""
    memo = {}

    def at(k, depth, n_sib):
        # chain[k] has matched the node at `depth` that has `n_sib` earlier siblings in sibs[depth]
        if k + 1 >= len(chain):
            return True
        key = (k, depth, n_sib)
        if key in memo:
            return memo[key]
        memo[key] = False
        comb = chain[k][1]
        nxt = chain[k + 1][0]
        ok = False
        if comb in (" ", ">"):
            lo = depth - 1 if comb == ">" else 0
            for d in range(depth - 1, max(-1, lo - 1), -1):
                if _compound_matches(nxt, path[d]) and at(k + 1, d, len(sibs[d])):
                    ok = True
                    break
        else:
            first = n_sib - 1 if comb == "+" else 0
            for j in range(n_sib - 1, max(-1, first - 1), -1):
                if _compound_matches(nxt, sibs[depth][j]) and at(k + 1, depth, j):
                    ok = True
                    break
        memo[key] = ok
        return ok
    return at(i, len(path) - 1, len(sibs[-1]))


def _index_key(c):
    """Index key of a compound for fast candidate lookup."""
    tag, classes, ident, attrs = c
    if ident is not None:
        return ("#", ident)
    if classes:
        return (".", min(classes))
    if tag not in (None, "*"):
        return ("t", tag)
    if attrs:
        return ("a", attrs[0][0])
    return ("*",)


def css_unescape(css):
    if "\\" not in css:
        return ""

    def repl(m):
        if m.group(2) is not None:      # a backslash before any other character stands for that character
            return m.group(2)
        try:
            return chr(int(m.group(1), 16))
        except (ValueError, OverflowError):
            return ""
    out = _CSS_ESC.sub(repl, css)
    return out if out != css else ""


# ---------------------------------------------------------------- comments and raw regions


def split_regions(text):
    """One linear pass. Returns (comments, raw_regions, blanked_text).

    comments:    [(start_offset, body)]
    raw_regions: [(kind, attrs_text, body)] for <script>/<style>
    blanked:     text with comment spans replaced by spaces (newlines kept), for the tokenizer"""
    low = text.lower()
    n = len(text)
    comments, regions, pieces = [], [], []
    nxt = {"<!--": -2, "<script": -2, "<style": -2}
    pos = last = 0
    while pos < n:
        for key in nxt:
            if nxt[key] != -1 and nxt[key] < pos:
                nxt[key] = low.find(key, pos)
        live = [(p, k) for k, p in nxt.items() if p >= 0]
        if not live:
            break
        p, key = min(live)
        if key == "<!--":
            body_start = p + 4
            if low.startswith(">", body_start):
                end = body_start + 1
                body = ""
            elif low.startswith("->", body_start):
                end = body_start + 2
                body = ""
            else:
                j = low.find("-->", body_start)
                k = low.find("--!>", body_start)
                if j < 0 and k < 0:
                    end = n
                    body = text[body_start:]
                elif k >= 0 and (j < 0 or k < j):
                    end = k + 4
                    body = text[body_start:k]
                else:
                    end = j + 3
                    body = text[body_start:j]
            if len(comments) < MAX_COMMENTS:
                comments.append((p, body))
            pieces.append(text[last:p])
            pieces.append("\n" * text.count("\n", p, end) or " ")
            last = end
            pos = end
        else:
            tag = key[1:]
            gt = low.find(">", p)
            if gt < 0:
                break
            close = low.find("</" + tag, gt)
            body_end = close if close >= 0 else n
            if len(regions) < 5000:
                regions.append((tag, low[p + len(key):gt], text[gt + 1:body_end]))
            pos = body_end + 1
    pieces.append(text[last:])
    return comments, regions, "".join(pieces)


# ---------------------------------------------------------------- streams


class Stream:
    """Text accumulator that keeps 'newline count + 1 == source line' true."""
    __slots__ = ("parts", "line", "size", "length")

    def __init__(self):
        self.parts = []
        self.line = 1
        self.size = 0
        self.length = 0          # characters in text() so far (offsets of what is added next)

    def add(self, text, line, joiner=" "):
        """Append text; returns its (start, end) offsets in text()."""
        if joiner == " " or not self.parts:
            if line > self.line:
                sep = "\n" * (line - self.line)
                self.line = line
            else:
                sep = " "
        else:
            sep = joiner or ""
        if sep:
            self.parts.append(sep)
            self.length += len(sep)
        start = self.length
        self.parts.append(text)
        self.length += len(text)
        self.line += text.count("\n")
        self.size += len(text)
        return start, self.length

    def text(self):
        return "".join(self.parts)


# Elements whose own text is not rendered when the element itself works (fallback content).
FALLBACK = frozenset(("canvas", "object", "iframe", "video", "audio", "applet", "embed"))
# Elements whose visible text is shown literally or set off as a quotation (example framing on pages).
CODEISH = frozenset(("code", "kbd", "samp", "tt", "pre", "blockquote", "q", "xmp", "listing"))
MAX_SEGMENTS = 2000
MAX_ANCESTORS = 64            # ancestors considered by complex selectors
MAX_COMPLEX_EVALS = 100_000   # element x selector checks (beyond: reported as not analyzed)
MAX_SEGMENT_CHARS = 20000
MAX_SIBS = 60


class _Walker(HTMLParser):
    def __init__(self, css):
        super().__init__(convert_charrefs=True)
        self.css = css
        self.hc = {c.lower() for c in css.classes}
        self.hi = {i.lower() for i in css.ids}
        self.S = {k: Stream() for k in STREAMS}
        self.stack = []          # (tag, hidden, is_svg, color, bg, codeish, details, summary, desc, children)
        self.hidden = 0
        self.svg = 0
        self.code = 0
        self.details = 0         # open <details> without the open attribute
        self.summary = 0
        self.raw_kind = None
        self.block = True
        self.tagged = False
        self.facts = []          # (kind, line, detail)
        self.urls = []           # (url, line, origin)
        self.anchor = None
        self.hidden_reasons = {}
        self.overflow = 0
        self.segments = []       # [line, reason, [text parts], chars] per hidden element tree
        self.code_spans = []     # (start, end) in the visible stream
        self.collapsed = []      # (line, text) inside a closed <details>, outside its <summary>
        self.top_children = []
        self.indirect = []
        self.complex_index = {}
        for chain in css.complex:
            self.complex_index.setdefault(_index_key(chain[0][0]), []).append(chain)
        self.complex_budget = MAX_COMPLEX_EVALS
        self.complex_stopped = False

    # -- helpers
    def _colors(self):
        if self.stack:
            return self.stack[-1][3], self.stack[-1][4]
        return (0, 0, 0), (255, 255, 255)

    def _complex_hidden(self, desc):
        if not self.css.complex or self.complex_budget <= 0:
            return False
        tag, classes, ident, attrs = desc
        idx = self.complex_index
        cands = list(idx.get(("t", tag), ())) + list(idx.get(("*",), ()))
        if ident:
            cands += idx.get(("#", ident), ())
        for c in classes:
            cands += idx.get((".", c), ())
        for name in attrs:
            cands += idx.get(("a", name), ())
        cands = [ch for ch in cands if _compound_matches(ch[0][0], desc)]
        if not cands:
            return False
        self.complex_budget -= len(cands)
        if self.complex_budget <= 0:
            self.complex_stopped = True
        stack = self.stack[-MAX_ANCESTORS:]
        base = len(self.stack) - len(stack)
        parent_children = self.stack[base - 1][9] if base > 0 else self.top_children
        path, sibs = [], []
        for e in stack:
            sibs.append(parent_children[-MAX_SIBS - 1:-1])     # earlier siblings of this ancestor
            path.append(e[8])
            parent_children = e[9]
        path.append(desc)
        sibs.append(parent_children[-MAX_SIBS:])
        return any(_chain_matches(ch, path, 0, sibs) for ch in cands)

    def _is_hidden(self, tag, a, color, bg, own_color, desc):
        if "hidden" in a:
            return "hidden attribute"
        if a.get("aria-hidden", "").strip().lower() == "true":
            return "aria-hidden"
        if tag in ("template", "noscript"):
            return "<%s>" % tag
        if tag == "dialog" and "open" not in a:
            return "closed <dialog>"
        if tag in FALLBACK and (tag != "object" or a.get("data") or a.get("type")):
            return "<%s> fallback content" % tag
        style = a.get("style", "")
        if style:
            sl = style.lower()
            if "var(" in sl and _INDIRECT.search(sl) and len(self.indirect) < 20:
                self.indirect.append((self.getpos()[0], sl[:120]))
            why = style_hidden(sl, self.css.custom)
            if why:
                return why
        cls_attr = a.get("class", "")
        if cls_attr:
            for c in cls_attr.split()[:40]:
                cl = c.lower()
                if cl in self.hc or cl in UTIL_HIDDEN:
                    return "class ." + c[:40]
        if a.get("id") and a["id"].lower() in self.hi:
            return "id hidden by stylesheet"
        if self._complex_hidden(desc):
            return "stylesheet selector"
        if self.svg or tag == "svg":
            if (a.get("display", "").strip().lower() == "none"
                    or a.get("visibility", "").strip().lower() == "hidden"
                    or a.get("opacity", "").strip() in ("0", "0.0", "0%")
                    or a.get("fill-opacity", "").strip() in ("0", "0.0")
                    or a.get("font-size", "").strip() in ("0", "0px", "0.0")
                    or (tag in ("text", "tspan", "textpath")
                        and a.get("fill", "").strip().lower() in ("none", "transparent"))):
                return "svg presentation attribute"
        if tag == "font" and a.get("size", "").strip() in ("0", "-7"):
            return "font size 0"
        if own_color and _close(color, bg):
            return "text colour equals background"
        return None

    def _attrs(self, tag, a, line):
        for k, v in a.items():
            if not v:
                continue
            if k in URL_ATTRS:
                if k == "srcset":
                    for part in v.split(",")[:20]:
                        u = part.strip().split(" ")[0]
                        if u:
                            self.urls.append((u, line, tag + ".srcset"))
                else:
                    self.urls.append((v.strip(), line, tag + "." + k))
                continue
            if k == "style" or k in SKIP_ATTRS:
                continue
            if k.startswith("on"):
                self.S["script"].add(v, line)
                continue
            if tag == "meta" and k == "content":
                self.S["meta"].add(v, line)
                continue
            if len(v) >= 8:
                self.S["attr"].add(v, line)
        if tag == "meta":
            if a.get("http-equiv", "").lower() == "refresh" and "url" in a.get("content", "").lower():
                self.facts.append(("meta-refresh", line, a.get("content", "")))
        elif tag == "base" and a.get("href"):
            self.facts.append(("base-href", line, a["href"]))
        elif tag in ("img", "iframe", "embed", "object"):
            w, h = a.get("width", "").strip().lower(), a.get("height", "").strip().lower()
            tiny = (w in ("0", "1", "0px", "1px") and h in ("0", "1", "0px", "1px"))
            style = a.get("style", "").lower()
            if tiny or (style and style_hidden(style, self.css.custom)) or "hidden" in a:
                self.facts.append(("zero-size", line, tag + " " + (a.get("src") or a.get("data") or "")))

    # -- parser callbacks
    def handle_starttag(self, tag, attrs):
        line = self.getpos()[0]
        self.tagged = True
        if tag not in INLINE:
            self.block = True
        a = {}
        for k, v in attrs:
            if k not in a:
                a[k] = v or ""
        color, bg = self._colors()
        own = False
        style = a.get("style", "")
        if style:
            sl = style.lower()
            m = _COLOR_DECL.search(sl)
            c = parse_color(m.group(1)) if m else None
            if c:
                color, own = c, True
            m = _BG_DECL.search(sl)
            c = parse_color(m.group(1)) if m else None
            if c:
                bg, own = c, True
        for attr, is_bg in (("color", False), ("text", False), ("bgcolor", True)):
            if a.get(attr) and (tag in ("font", "body", "td", "tr", "table", "div", "p", "span") or is_bg):
                c = parse_color(a[attr] if a[attr].startswith("#") or not re.match(r"^[0-9a-fA-F]{6}$", a[attr])
                                else "#" + a[attr])
                if c:
                    own = True
                    if is_bg:
                        bg = c
                    else:
                        color = c
        desc = (tag, frozenset(c.lower() for c in a.get("class", "").split()[:40]), a.get("id", "").lower() or None,
                {k: (v or "").lower() for k, v in list(a.items())[:40]})
        why = self._is_hidden(tag, a, color, bg, own, desc)
        if why:
            self.hidden_reasons[why] = self.hidden_reasons.get(why, 0) + 1
        self._attrs(tag, a, line)
        siblings = self.stack[-1][9] if self.stack else self.top_children
        if len(siblings) < 4 * MAX_SIBS:
            siblings.append(desc)
        else:
            del siblings[:MAX_SIBS]
            siblings.append(desc)
        if tag in VOID:
            return
        if len(self.stack) < MAX_DEPTH:
            closed_details = tag == "details" and "open" not in a
            self.stack.append((tag, bool(why), tag == "svg", color, bg, tag in CODEISH, closed_details,
                               tag == "summary", desc, []))
            if why:
                if self.hidden == 0 and len(self.segments) < MAX_SEGMENTS:
                    self.segments.append([line, why, [], 0])
                self.hidden += 1
            if tag == "svg":
                self.svg += 1
            if tag in CODEISH:
                self.code += 1
            if closed_details:
                self.details += 1
            if tag == "summary":
                self.summary += 1
        else:
            self.overflow += 1
        if tag == "script":
            t = a.get("type", "").lower()
            self.raw_kind = "jsonld" if "json" in t else "script"
        elif tag == "style":
            self.raw_kind = "style"
        elif tag == "a":
            self.anchor = [a.get("href", ""), line, []]

    def handle_endtag(self, tag):
        self.tagged = True
        if tag not in INLINE:
            self.block = True
        if tag in ("script", "style"):
            self.raw_kind = None
        if tag == "a" and self.anchor is not None:
            href, line, parts = self.anchor
            self.anchor = None
            label = " ".join("".join(parts).split())
            if href and label:
                self.facts.append(("anchor", line, (label[:300], href[:600])))
        stack = self.stack
        for i in range(len(stack) - 1, max(-1, len(stack) - 65), -1):
            if stack[i][0] == tag:
                for e in stack[i:]:
                    if e[1]:
                        self.hidden -= 1
                    if e[2]:
                        self.svg -= 1
                    if e[5]:
                        self.code -= 1
                    if e[6]:
                        self.details -= 1
                    if e[7]:
                        self.summary -= 1
                del stack[i:]
                break

    def handle_data(self, data):
        if not data.strip():
            if data:
                self.block = True
            return
        line = self.getpos()[0]
        joiner = " " if self.block else (MARK if self.tagged else "")
        self.block = self.tagged = False
        if self.raw_kind:
            name = self.raw_kind
        elif self.hidden > 0:
            name = "hidden"
            if self.segments and self.segments[-1][3] < MAX_SEGMENT_CHARS:
                seg = self.segments[-1]
                seg[2].append(data)
                seg[3] += len(data)
        elif self.svg > 0:
            name = "svg"
        else:
            name = "visible"
        span = self.S[name].add(data, line, joiner)
        if name == "visible":
            if self.code > 0 and len(self.code_spans) < 50000:
                self.code_spans.append(span)
            if self.details > 0 and self.summary == 0 and len(self.collapsed) < 2000:
                self.collapsed.append((line, data))
        if self.anchor is not None and len(self.anchor[2]) < 20:
            self.anchor[2].append(data)

    def handle_decl(self, decl):
        pass

    def unknown_decl(self, data):       # <![CDATA[ ... ]]>
        self.S["hidden"].add(data, self.getpos()[0])

    def handle_pi(self, data):
        if not data.lower().startswith("xml "):
            self.S["hidden"].add(data, self.getpos()[0])


class HtmlResult:
    __slots__ = ("streams", "comments", "facts", "urls", "hidden_reasons", "aborted", "depth_overflow",
                 "segments", "code_spans", "collapsed", "indirect", "selector_limit")


def analyze_html(text, budget=None):
    """Tokenize HTML-ish text and return an HtmlResult. Never raises."""
    comments, regions, blanked = split_regions(text)
    css = CssInfo()
    for kind, _attrs, body in regions:
        if kind == "style":
            css_hidden_selectors(body, css)
    w = _Walker(css)
    res = HtmlResult()
    res.aborted = ""
    try:
        step = 65536
        for off in range(0, len(blanked), step):
            w.feed(blanked[off:off + step])
            if len(w.rawdata) > MAX_PENDING:
                res.aborted = "tokenizer made no progress on malformed markup"
                break
            if budget and budget.expired():
                res.aborted = "time budget"
                break
        if not res.aborted:
            w.close()
    except Exception as exc:   # malformed markup must never stop the scan
        res.aborted = "tokenizer error: %s" % type(exc).__name__
    comment_stream = Stream()
    line, last = 1, 0
    for pos, body in comments:
        line += text.count("\n", last, pos)
        last = pos
        if body.strip():
            comment_stream.add(body, line)
    streams = {k: s.text() for k, s in w.S.items() if s.size}
    if comment_stream.size:
        streams["comment"] = comment_stream.text()
    style = streams.get("style", "")
    if style:
        extra = css_unescape(style)
        if extra:
            streams["style"] = style + "\n" + extra
    res.streams = streams
    res.comments = len(comments)
    res.facts = w.facts
    res.urls = w.urls
    res.hidden_reasons = w.hidden_reasons
    res.depth_overflow = w.overflow
    res.segments = [(ln, why, " ".join("".join(parts).split())) for ln, why, parts, _n in w.segments if parts]
    res.code_spans = w.code_spans
    res.collapsed = w.collapsed
    res.indirect = [("stylesheet", x) for x in css.indirect] + [("inline style", x) for _ln, x in w.indirect]
    res.selector_limit = w.complex_stopped
    return res


def comment_stream(text):
    """Comments only (for Markdown and other non-HTML text)."""
    if "<!--" not in text:
        return ""
    comments, _regions, _blank = split_regions(text)
    s = Stream()
    line, last = 1, 0
    for pos, body in comments:
        line += text.count("\n", last, pos)
        last = pos
        if body.strip():
            s.add(body, line)
    return s.text() if s.size else ""


# ---------------------------------------------------------------- Markdown

_FENCE_LINE = re.compile(r"(?m)^[ \t]{0,3}(`{3,}|~{3,})([^\n`]{0,200})$")
_INLINE_CODE = re.compile(r"(`{1,3})[^`\n]{1,400}\1")
_NOT_NL = re.compile(r"[^\n]")


def strip_md_code(text):
    """Blank out fenced code blocks and inline code spans (same length, newlines kept).

    Markup inside Markdown code is displayed literally, so it must not be treated as
    live HTML (a documented `<template>` tag does not hide the rest of the file)."""
    if "`" not in text and "~~~" not in text:
        return text
    spans = []
    opener = None
    for m in _FENCE_LINE.finditer(text):
        ch, info = m.group(1), m.group(2).strip()
        if opener is None:
            opener = (m.start(), ch[0], len(ch))
        elif ch[0] == opener[1] and len(ch) >= opener[2] and not info:
            spans.append((opener[0], m.end()))
            opener = None
        if len(spans) > 20000:
            break
    if opener is not None:
        spans.append((opener[0], len(text)))
    if spans:
        out, last = [], 0
        for s, e in spans:
            out.append(text[last:s])
            out.append(_NOT_NL.sub(" ", text[s:e]))
            last = e
        out.append(text[last:])
        text = "".join(out)
    if "`" in text:
        text = _INLINE_CODE.sub(lambda m: " " * len(m.group(0)), text)
    return text


_MD_LINK = re.compile(
    r"\[([^\[\]\n]{0,300})\]\([ \t]{0,3}<?((?:[^()\[\]\s<>]|\([^()\s<>]{0,200}\)){1,400})>?"
    r"(?:[ \t]{1,3}(?:\"([^\"\n]{0,500})\"|'([^'\n]{0,500})'))?[ \t]{0,3}\)")
_MD_SCHEME = re.compile(r"(?i)\]\([ \t]{0,3}<?((?:javascript|vbscript|data):[^\s>]{1,300})")
_MD_REF = re.compile(
    r"(?m)^[ ]{0,3}\[([^\]\n]{1,200})\]:[ \t]{0,4}<?([^\s<>]{0,600})>?"
    r"(?:[ \t]{1,4}(?:\"([^\"\n]{0,500})\"|'([^'\n]{0,500})'|\(([^)\n]{0,500})\)))?[ \t]{0,4}$")


class MdResult:
    __slots__ = ("hidden", "links", "refs")


def analyze_markdown(text):
    """Extract links, reference definitions and hover-only / comment text."""
    res = MdResult()
    hidden = Stream()
    links, refs = [], []
    if "](" in text:
        last, line = 0, 1
        for m in _MD_LINK.finditer(text):
            if len(links) >= 5000:
                break
            line += text.count("\n", last, m.start())
            last = m.start()
            is_image = m.start() > 0 and text[m.start() - 1] == "!"
            title = m.group(3) or m.group(4) or ""
            links.append((line, is_image, m.group(1), m.group(2), title))
            if len(title) >= 8:
                hidden.add(title, line)
        have = {(ln, url) for ln, _i, _l, url, _t in links}
        for m in _MD_SCHEME.finditer(text):       # script/data links whose shape the link regex rejects
            if len(links) >= 5000:
                break
            line = T.line_of(text, m.start())
            if not any(ln == line and m.group(1).startswith(url[:20]) for ln, url in have):
                links.append((line, False, "", m.group(1), ""))
    if "]:" in text:
        last, line = 0, 1
        for m in _MD_REF.finditer(text):
            if len(refs) >= 5000:
                break
            line += text.count("\n", last, m.start())
            last = m.start()
            label, url = m.group(1), m.group(2)
            title = m.group(3) or m.group(4) or m.group(5) or ""
            is_comment = label.startswith("//") or label.lower() in ("comment", "#") or url in ("#", "", "<>")
            refs.append((line, label, url, title, is_comment))
            if title and (is_comment or len(title) >= 8):
                hidden.add(title, line)
    res.hidden = hidden.text() if hidden.size else ""
    res.links = links
    res.refs = refs
    return res
