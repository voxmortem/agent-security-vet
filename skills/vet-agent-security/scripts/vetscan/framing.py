"""Sentence context for visible text in instruction files.

Defensive skills mention attacks: they quote injection phrases as examples and name dangerous
commands as things to avoid. Attackers write the same words as orders. This module answers two
narrow questions about one occurrence, using only its own clause (text between sentence ends,
semicolons, blank lines and list bullets):

  * is it framed as an example / a mention ("such as", "e.g.", "attackers write", a quoted
    phrase in a blockquote or table introduced as an example, "a request to ...")?
  * is it framed defensively ("never", "do not", "avoid", "defend against") without being
    an imperative to do it ("run ...", "now set ...")?

Both answers can be imitated by an attacker; the engine therefore only lowers HIGH to MED,
never drops a finding, and never lowers anything that also carries a concrete action target
(a URL, a download-and-run command) in the same clause.
"""
import re

from . import markup

WINDOW = 400                     # characters searched backwards / forwards for a clause boundary

_ABBREV = re.compile(r"(?i)(?:\b(?:e\.g|i\.e|etc|vs|cf|approx|incl|resp|fig|no|nr|ca|al)|(?<![\w.])\w)$")
_BOUNDARY = re.compile(r"[.!?;](?=[\s\"'\)\]*_]|$)|\n[ \t]*\n|\n[ \t]*(?:[-*+]|\d{1,3}[.)])[ \t]|\n[ \t]*#")

# Mention / example framing that must come BEFORE the phrase in the same clause.
_META = re.compile(
    r"(?i)\b(?:such as|e\.\s?g\.?|eg|for example|for instance|examples?|"
    r"(?:phrases?|text|texts|strings?|payloads?|wording|lines?|instructions?|messages?|comments?|content|"
    r"requests?|attempts?|injections?|patterns?|things|something|anything|commands?|sentences?|words?)\s+"
    r"(?:like|such as|that says?|saying|reading)|"
    r"attackers?\s+(?:often\s+|may\s+|might\s+|can\s+)?(?:write|writes|use|uses|hide|hides|insert|inserts|plant|"
    r"plants|embed|embeds|try|tries|say|says|add|adds|put|puts)|"
    r"never\s+(?:obey|follow|act\s+on|comply\s+with|execute|run)|"
    r"(?:do\s+not|don.?t|must\s+not|should\s+not)\s+(?:obey|follow|act\s+on|comply\s+with|execute|run|repeat)|"
    r"patterns?|injections?|payloads?|watch\s+(?:out\s+)?for|look\s+out\s+for|beware(?:\s+of)?|"
    r"(?:tries|tried|trying|attempts?|attempting)\s+to|known\s+as|called|reads?:|says?:|saying)\b")
# "a request to <verb>", "tells you to <verb>": the phrase that follows is described, not given.
_DESCRIBED = re.compile(
    r"(?i)(?:\b(?:requests?|attempts?|instructions?|orders?|demands?)\s+(?:\w+\s+){0,2}to|"
    r"\b(?:asks?|asking|asked|tells?|telling|told|wants?|wanting|tries|try|trying|attempts?|attempting|"
    r"instructs?|instructing|urges?|urging)\s+(?:you\s+|the\s+(?:agent|model|assistant|ai)\s+|it\s+|them\s+)?to)"
    r"\s*[\"'`*_(]*\s*$")
# A concrete action target in the same clause keeps HIGH: the text is not just an example then.
_ACTION = re.compile(
    r"(?i)(?:\b(?:https?|ftp|wss?)://|\bwww\.|[\w.+-]{1,64}@[\w-]{1,63}\.[\w.]{2,20}|"
    r"\b(?:curl|wget|iwr|irm|invoke-webrequest|invoke-expression|iex|powershell|pwsh|netcat|ncat)\b|"
    r"\b(?:ba|z)?sh\s+-c\b|\|\s*(?:sudo\s+)?(?:ba|z)?sh\b|\bnc\s+-)")
# Defensive framing anywhere in the clause (for code-behaviour rules).
_DEFENSIVE = re.compile(
    r"(?i)\b(?:never|do\s+not|don.?t|dont|avoid\w*|defend(?:ing|s)?\s+against|guard(?:ing|s)?\s+against|"
    r"protect(?:ing|s)?\s+against|must\s+not|mustn.?t|should\s+not|shouldn.?t|forbidden|prohibited|"
    r"not\s+allowed|is\s+dangerous|are\s+dangerous|refuse\w*|reject\w*|block(?:s|ed|ing)?|"
    r"malicious|attackers?|such as|e\.\s?g\.?|for example|for instance)\b")
# Prohibition framing for phrase rules: narrower, so that "for example" alone never lowers an order.
_PROHIBITION = re.compile(
    r"(?i)\b(?:never|do\s+not|don.?t|dont|avoid\w*|defend(?:ing|s)?\s+against|guard(?:ing|s)?\s+against|"
    r"protect(?:ing|s)?\s+against|must\s+not|mustn.?t|should\s+not|shouldn.?t|forbidden|prohibited|"
    r"not\s+allowed|refuse\w*|reject\w*)\b")
# "never skip", "do not hesitate to": a double negative is an order, not a prohibition.
_DOUBLE_NEG = re.compile(
    r"(?i)\b(?:never|do\s+not|don.?t|dont|must\s+not|should\s+not)\s+(?:\w+\s+)?(?:skip|forget|hesitate|fail|"
    r"neglect|omit|miss|bother|wait|delay|stop|ignore|refuse|decline|hold\s+back)\b")
_VERBS = (r"run|execute|exec|paste|type|enter|invoke|launch|start|install|call|use|copy|source|eval|set|add|"
          r"enable|disable|change|write|put|append|configure|create|edit|modify|replace|update|turn|switch|open|"
          r"visit|fetch|download|send|post|upload|pipe|curl|wget|bash|sh|delete|remove")
_VERB_RX = re.compile(r"(?i)\b(?:%s)\b" % _VERBS)
_IMPERATIVE_PREFIX = re.compile(
    r"(?i)(?:^|[,:]|\b(?:then|now|first|next|please|and|also|just|simply|always|finally|immediately|"
    r"you\s+must|you\s+should|you\s+need\s+to|must|should|to\s+install,?|to\s+set\s+up,?))[\s*_>`'\"]*$")
_NEG_OR_DESC = re.compile(
    r"(?i)\b(?:never|not|don.?t|dont|no|avoid\w*|without|if|unless|when|tells?|telling|told|asks?|asking|"
    r"tries|trying|attempts?|wants?|tutorial|page|attackers?|someone|malware|payload)\b")


class Context:
    """Lazily built line index and Markdown block map for one file's text."""

    def __init__(self, text):
        self.text = text
        self._starts = None
        self._fences = None
        self._spans = None

    # ---------------------------------------------------------------- positions

    def line_start(self, line):
        if self._starts is None:
            starts, i = [0], self.text.find("\n")
            while i != -1:
                starts.append(i + 1)
                i = self.text.find("\n", i + 1)
            self._starts = starts
        return self._starts[min(max(line, 1), len(self._starts)) - 1]

    def line_text(self, line):
        s = self.line_start(line)
        e = self.text.find("\n", s)
        return self.text[s:e if e >= 0 else len(self.text)]

    def find_words(self, line, match):
        """Character offset of a phrase match (lower-case view words) on its line, or None."""
        first = match.split(" ", 1)[0].split("\n", 1)[0]
        if not first:
            return None
        raw = self.line_text(line).lower()
        i = raw.find(first)
        while i != -1:
            if i == 0 or not raw[i - 1].isalnum():
                return self.line_start(line) + i
            i = raw.find(first, i + 1)
        return None

    def clause(self, pos, end=None):
        """(before, after) text of the clause around [pos, end)."""
        t = self.text
        end = pos if end is None else end
        lo = max(0, pos - WINDOW)
        start = lo
        for m in _BOUNDARY.finditer(t, lo, pos):
            if m.group(0)[0] == "." and _ABBREV.search(t, max(0, m.start() - 8), m.start()):
                continue
            start = m.end()
        hi = min(len(t), end + WINDOW)
        stop = hi
        for m in _BOUNDARY.finditer(t, end, hi):
            if m.group(0)[0] == "." and _ABBREV.search(t, max(0, m.start() - 8), m.start()):
                continue
            stop = m.start() + (1 if m.group(0)[0] in ".!?;" else 0)
            break
        return t[start:pos], t[end:stop]

    # ---------------------------------------------------------------- Markdown blocks

    def _fence_lines(self):
        if self._fences is None:
            fences = []
            opener = None
            for m in markup._FENCE_LINE.finditer(self.text):
                ch, info = m.group(1), m.group(2).strip()
                line = self.text.count("\n", 0, m.start()) + 1
                if opener is None:
                    opener = (line, ch[0], len(ch))
                elif ch[0] == opener[1] and len(ch) >= opener[2] and not info:
                    fences.append((opener[0], line))
                    opener = None
                if len(fences) > 5000:
                    break
            if opener is not None:
                fences.append((opener[0], self.text.count("\n") + 1))
            self._fences = fences
        return self._fences

    def fence_of(self, line):
        for a, b in self._fence_lines():
            if a <= line <= b:
                return a
            if a > line:
                break
        return None

    def in_inline_code(self, pos):
        if self._spans is None:
            self._spans = [(m.start(), m.end()) for m in markup._INLINE_CODE.finditer(self.text)][:50000] \
                if "`" in self.text else []
        lo, hi = 0, len(self._spans)
        while lo < hi:
            mid = (lo + hi) // 2
            s, e = self._spans[mid]
            if e <= pos:
                lo = mid + 1
            elif s > pos:
                hi = mid
            else:
                return True
        return False

    def _intro(self, line, skip):
        """Nearest non-blank line above `line` that does not satisfy `skip`."""
        for ln in range(line - 1, max(0, line - 40), -1):
            t = self.line_text(ln).strip()
            if t and not skip(t):
                return t
        return ""

    def in_example_block(self, line):
        """A blockquote, fenced block or table row whose introduction marks it as an example."""
        raw = self.line_text(line).lstrip()
        if raw.startswith(">"):
            intro = self._intro(line, lambda t: t.startswith(">"))
            return bool(_META.search(intro))
        if raw.startswith("|"):
            header = ""
            for ln in range(line, max(0, line - 200), -1):
                t = self.line_text(ln).strip()
                if not t.startswith("|"):
                    break
                header = t
            intro = self._intro(line, lambda t: t.startswith("|"))
            return bool(_META.search(header) or _META.search(intro))
        start = self.fence_of(line)
        if start is not None and start != line:
            return bool(_META.search(self._intro(start, lambda t: False)))
        return False


def _double_negated(text):
    return bool(_DOUBLE_NEG.search(text))


def phrase_mention(ctx, line, match, quoted):
    """Why a HIGH phrase hit in an instruction file is only a mention, or None if it is an order.

    'example':     quoted after example framing in its clause, described ("a request to ..."), or in a
                   blockquote / table / fence introduced as an example - and the clause carries no
                   concrete action target (URL, download-and-run command)
    'prohibition': under negation framing ("never", "do not", "defend against") in its clause and not
                   governed by an un-negated imperative
    A bare quoted imperative ("Ignore all previous instructions.") is an order."""
    pos = ctx.find_words(line, match)
    if pos is None:
        return None
    # The clause is the one in which the phrase STARTS; `after` runs from the phrase to the clause end.
    before, after = ctx.clause(pos)
    framed = (_DESCRIBED.search(before[-60:]) or ctx.in_example_block(line)
              or (quoted and _META.search(before) and not _double_negated(before)))
    if framed and not _ACTION.search(before + after):
        return "example"
    if imperative(before):
        return None
    # The phrase's own first word ("do not mention ...", "never reveal ...") is not a prohibition of it.
    around = before + " " + after[len(match.split(" ", 1)[0]):]
    if _PROHIBITION.search(around) and not _double_negated(around):
        return "prohibition"
    return None


def imperative(before):
    """True when the clause orders the reader to run / set the thing that follows."""
    b = before.rstrip(" \t`'\"*_")
    verbs = list(_VERB_RX.finditer(b))[-12:]
    if not verbs:
        return not b.strip(" \t>-*+#") or bool(_IMPERATIVE_PREFIX.search(b))
    # Walk back from the verb nearest to the match: "Run `curl ..." is governed by "Run", "never launch
    # ... or set ..." by "never", "a tutorial tells you to run ..." by the description.
    for m in reversed(verbs):
        head = b[:m.start()]
        if _NEG_OR_DESC.search(head[-48:]):
            return False
        if _IMPERATIVE_PREFIX.search(head):
            return True
    return False


def code_mention(ctx, pos, end):
    """True when a code-rule match in instruction prose is a mention, not an order: it sits in an
    inline code span or under defensive framing, and no un-negated imperative governs it.
    Matches inside fenced code blocks are runnable and never count as mentions."""
    line = ctx.text.count("\n", 0, pos) + 1
    if ctx.fence_of(line) is not None:
        return False
    before, after = ctx.clause(pos, end)
    if imperative(before):
        return False
    clause = before + " " + after
    if _DEFENSIVE.search(clause) and not _double_negated(clause):
        return True
    return ctx.in_inline_code(pos)
