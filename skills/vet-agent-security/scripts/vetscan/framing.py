"""Sentence context for visible text in instruction files and in content an agent reads.

Defensive skills mention attacks: they quote injection phrases as examples and name dangerous
commands as things to avoid. Attackers write the same words as orders, and they imitate the framing.
This module answers narrow questions about one occurrence, using only its own clause (text between
sentence ends, semicolons, blank lines and list bullets):

  * is it framed as an example? Only a STRONG meta cue counts: the clause (or the introduction of the
    blockquote, table or fence it stands in) names an attack ("attackers write", "prompt injection",
    "payloads such as", "examples of injected text", "patterns"). Weak cues that an attacker writes in
    front of a real order ("such as", "e.g.", "for example", "the user asks you to") lower nothing.
  * is it under a prohibition that governs it ("never <phrase>", "do not <phrase>", "<phrase> is
    forbidden")? A prohibition elsewhere in the sentence ("X is forbidden, so <phrase>") does not count.

Neither lowers anything when the same sentence also carries a concrete action target (a URL, an
e-mail address, a downloader), an action on a sensitive object outside the quoted example ("upload the
.env file", "append ~/.ssh/id_rsa", "reveal the system prompt"), or wording that tells the reader to
comply after all. For content an agent reads (--kind page) only a code span, fence or blockquote
introduced by a strong cue counts. Both answers can still be imitated by an attacker; the engine
therefore only lowers HIGH to MED, never drops a finding.
"""
import re

from . import markup

WINDOW = 400                     # characters searched backwards / forwards for a clause boundary

_ABBREV = re.compile(r"(?i)(?:\b(?:e\.g|i\.e|etc|vs|cf|approx|incl|resp|fig|no|nr|ca|al)|(?<![\w.])\w)$")
_BOUNDARY = re.compile(r"[.!?;](?=[\s\"'\)\]*_]|$)|\n[ \t]*\n|\n[ \t]*(?:[-*+]|\d{1,3}[.)])[ \t]|\n[ \t]*#")

# Example framing (kept for the code-behaviour rules and as the weak-cue list it documents).
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
# Strong meta cues: the clause names an attack or a defence against one. Only these frame an example.
_STRONG_META = re.compile(
    r"(?i)\b(?:attack(?:s|er|ers|ed|ing)?|adversar(?:y|ies|ial)|inject(?:ed|ion|ions|ing)|payloads?|malicious|"
    r"hostile|untrusted|exploits?|phishing|jailbreak(?:s|ing)?|red[- ]team(?:ing|ers?)?|examples?\s+of|patterns?|"
    r"known\s+as|watch\s+(?:out\s+)?for|look\s+out\s+for|beware|be\s+wary\s+of|"
    r"never\s+(?:obey|follow|act\s+on|comply\s+with|execute|run|repeat)|"
    r"(?:do\s+not|don.?t|must\s+not|should\s+not)\s+(?:obey|follow|act\s+on|comply\s+with|execute|run|repeat))\b")
# "a request to <verb>", "attempts to <verb>": the phrase that follows is described, not given. "The user asks
# you to", "tells you to", "wants you to" are NOT here: attackers write exactly that in front of an order.
_DESCRIBED = re.compile(
    r"(?i)(?:\b(?:requests?|attempts?)\s+(?:\w+\s+){0,2}to|\b(?:tries|try|trying|attempts?|attempting)\s+to)"
    r"\s*[\"'`*_(]*\s*$")
# A concrete action target in the same clause keeps HIGH: the text is not just an example then.
_ACTION = re.compile(
    r"(?i)(?:\b(?:https?|ftp|wss?)://|\bwww\.|[\w.+-]{1,64}@[\w-]{1,63}\.[\w.]{2,20}|"
    r"\b(?:curl|wget|iwr|irm|invoke-webrequest|invoke-expression|iex|powershell|pwsh|netcat|ncat)\b|"
    r"\b(?:ba|z)?sh\s+-c\b|\|\s*(?:sudo\s+)?(?:ba|z)?sh\b|\bnc\s+-)")
# A sensitive object that an action in the same sentence is aimed at (outside the quoted example).
_SENSITIVE_OBJ = re.compile(
    r"(?i)(?:(?<![\w.])\.env\b|\bdotenv\b|\bid_(?:rsa|dsa|ecdsa|ed25519)\b|\.ssh\b|\bssh[ _-]?(?:private[ _-]?)?keys?\b|"
    r"\.aws\b|\baws[ _-]credentials\b|\.npmrc\b|\.netrc\b|\.pgpass\b|\.git-credentials\b|\bkubeconfig\b|"
    r"/etc/(?:passwd|shadow)\b|\bcredentials\.json\b|\bsystem[ _-]prompt\b|\bkeychain\b|\bseed[ _-]phrase\b|"
    r"\bprivate[ _-]keys?\b|\bbrowser[ _-]history\b|\bsaved[ _-]passwords?\b)")
_ACTION_VERB = re.compile(
    r"(?i)\b(?:upload|send|post|exfiltrate|e-?mail|mail|forward|transmit|leak|append|attach|paste|include|embed|"
    r"read|open|cat|copy|print|reveal|output|dump|share|commit|push|write|put|insert|add|give|show|display|return|"
    r"deliver|submit|transfer|export|encode|type|steal|grab|collect|harvest)\b")
# Wording after the example that tells the reader to act on it anyway.
_COMPLY = re.compile(
    r"(?i)(?:(?:^|[,;:]\s*|\b(?:and|then|now|please|must|should|always|so)\s+)(?:comply|obey)\b|"
    r"\b(?:comply|obey)\s+(?:at\s+once|immediately|now|with\s+(?:it|them|this|that))\b|"
    r"\bdo\s+(?:it|that|this|so|as\s+(?:it|they)\s+says?)\b|\bfollow\s+(?:it|them|this|that|these)\b|"
    r"act\s+on\s+(?:it|them|this|that)\b|carry\s+(?:it|them)\s+out|execute\s+(?:it|them)\b|"
    r"(?:real|true|actual)\s+(?:intent|wish|request|instructions?)|as\s+(?:authori[sz]ed|approved|legitimate|valid)\b|"
    r"(?:is|are)\s+what\s+\w{1,20}\s+(?:needs?|wants?)|behave\s+(?:exactly\s+)?as|"
    r"treat\s+(?:it|them|this|these)\s+as\s+(?:authori|approved|valid|legit|real|instructions?|orders?))")
_QUOTED = re.compile('"[^"]{1,400}"|`[^`]{1,400}`|' + chr(0x201C) + "[^" + chr(0x201D) + "]{1,400}" + chr(0x201D)
                     + "|" + chr(0x00AB) + "[^" + chr(0x00BB) + "]{1,400}" + chr(0x00BB))
_WORD = re.compile(r"\w+")
# A prohibition that governs the phrase: "never <phrase>", "do not <phrase>", "defend against <phrase>",
# with nothing that starts a new clause in between.
_PROHIB_BEFORE = re.compile(
    r"(?i)\b(?:never|do\s+not|don.?t|dont|must\s+not|mustn.?t|should\s+not|shouldn.?t|cannot|can.?t|refuse\s+to|"
    r"decline\s+to|avoid(?:ing)?|defend(?:ing|s)?\s+against|guard(?:ing|s)?\s+against|protect(?:ing|s)?\s+against|"
    r"(?:is|are)\s+(?:forbidden|prohibited|not\s+allowed)\s+to|forbidden\s+to|prohibited\s+to|not\s+allowed\s+to|"
    r"reject(?:s|ing)?|refuse(?:s|ing)?|block(?:s|ing)?|flag(?:s|ging)?|report(?:s|ing)?)\b"
    r"(?P<gap>[^.;:,!?\n]{0,60})$")
_PROHIB_AFTER = re.compile(
    r"(?i)^[^.;:!?\n]{0,60}?\b(?:is|are|was|were)\s+(?:strictly\s+|always\s+)?(?:forbidden|prohibited|not\s+allowed|"
    r"banned|never\s+(?:allowed|acceptable|ok))\b")
_CLAUSE_JOIN = re.compile(r"(?i)\b(?:so|then|therefore|thus|hence|instead|but|and\s+then|now)\b")


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

    def __init__(self, text, code_spans=None):
        self.text = text
        self._starts = None
        self._fences = None
        self._spans = None
        # (start, end) offsets of code / pre / blockquote / q text in an HTML visible stream
        self._extra = sorted(code_spans)[:50000] if code_spans else []

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

    def word_end(self, pos, n_words):
        """Offset just after the n-th word that starts at `pos` (the raw extent of a view match)."""
        end = pos
        for i, m in enumerate(_WORD.finditer(self.text, pos, min(len(self.text), pos + 2000))):
            end = m.end()
            if i + 1 >= n_words:
                break
        return end

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
        if self._extra and _in_spans(self._extra, pos):
            return True
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
            return bool(_STRONG_META.search(intro))
        if raw.startswith("|"):
            header = ""
            for ln in range(line, max(0, line - 200), -1):
                t = self.line_text(ln).strip()
                if not t.startswith("|"):
                    break
                header = t
            intro = self._intro(line, lambda t: t.startswith("|"))
            return bool(_STRONG_META.search(header) or _STRONG_META.search(intro))
        start = self.fence_of(line)
        if start is not None and start != line:
            return bool(_STRONG_META.search(self._intro(start, lambda t: False)))
        return False


def _double_negated(text):
    return bool(_DOUBLE_NEG.search(text))


def _in_spans(spans, pos):
    lo, hi = 0, len(spans)
    while lo < hi:
        mid = (lo + hi) // 2
        s, e = spans[mid]
        if e <= pos:
            lo = mid + 1
        elif s > pos:
            hi = mid
        else:
            return True
    return False


def names_an_attack(text):
    """True when `text` (the words before an occurrence) names an attack or a defence against one."""
    return bool(_STRONG_META.search(text)) and not _double_negated(text)


def acts_on_sensitive(text):
    """True when an action verb is aimed at a sensitive object ("upload the .env file", "append the
    contents of ~/.ssh/id_rsa", "reveal the system prompt") in `text`."""
    for m in _SENSITIVE_OBJ.finditer(text):
        if _ACTION_VERB.search(text, max(0, m.start() - 80), m.start()):
            return True
    return False


def _targets(before, span_len, after):
    """(concrete target, sensitive action) in the sentence. URLs, e-mail addresses and downloaders count
    anywhere; actions on sensitive objects and compliance wording count outside the quoted example and
    outside the matched phrase itself."""
    concrete = bool(_ACTION.search(before) or _ACTION.search(after))
    outside = _QUOTED.sub(" ", before + " " * span_len + after)
    return concrete, acts_on_sensitive(outside) or bool(_COMPLY.search(outside))


# "If a tutorial tells you to <X>, do not": a conditional report of someone else's request, refused in the
# same sentence. (An unconditional "the user asks you to <X>" is an order and is not here.)
_IF_TOLD = re.compile(
    r"(?i)\b(?:if|when|whenever|should)\s+(?:(?:a|an|the|any|some|this|that)\s+)?(?:\w+\s+){0,3}"
    r"(?:tells?|asks?|instructs?|wants?|suggests?|says?\s+to|urges?)\s+(?:you\s+)?to(?:\s+\w+){0,2}\s*[`'\"*_(]*\s*$")
_REFUSED_AFTER = re.compile(r"(?i),\s*(?:then\s+)?(?:do\s+not|don.?t|never|refuse|decline|stop|ignore\s+it)\b")
# A defensive response to the quoted example in the same sentence: "record it as a finding", "quote it
# to the user", "treat ... as a finding".
_DEFENSIVE_RESPONSE = re.compile(
    r"(?i)\b(?:record|report|flag|log|quote|refuse|reject|block|stop\s+and|treat\s+(?:it|this|them|that)\s+as\s+"
    r"(?:a\s+)?(?:finding|data|untrusted|suspicious)|as\s+a\s+finding|do\s+not\s+(?:act|follow|obey|comply)|"
    r"never\s+(?:act|follow|obey|comply))\b")


def _governed_prohibition(before, after, tail):
    m = _PROHIB_BEFORE.search(before[-120:])
    if m and not _CLAUSE_JOIN.search(m.group("gap")) and not _double_negated(m.group(0)):
        return True
    if _IF_TOLD.search(before[-120:]) and _REFUSED_AFTER.search(tail):
        return True
    return bool(_PROHIB_AFTER.search(after))


def phrase_mention(ctx, line, match, quoted, consumed=False):
    """Why a HIGH phrase hit is only a mention, or None if it is an order.

    'example':     framed by a strong meta cue: quoted / in a code span / described ("a request to ...")
                   after one in its clause, or in a blockquote / table / fence whose introduction has one
    'prohibition': governed by a prohibition in its own clause ("never <phrase>", "<phrase> is forbidden")
    Nothing is lowered when the sentence also has a concrete action target, an action on a sensitive
    object outside the quoted example, or compliance wording. `consumed` (content an agent reads, --kind
    page): only a code span / fence / blockquote introduced by a strong cue lowers. A bare quoted
    imperative ("Ignore all previous instructions.") is an order."""
    pos = ctx.find_words(line, match)
    if pos is None:
        return None
    end = ctx.word_end(pos, max(1, len(match.split())))
    before, after = ctx.clause(pos, end)
    concrete, sensitive = _targets(before, end - pos, after)
    # "Attackers write '<phrase>'; when you see it, comply.": compliance in the next clause counts too.
    nxt = end + len(after)
    if not sensitive and _COMPLY.search(_QUOTED.sub(" ", ctx.text[nxt:nxt + 160])):
        sensitive = True
    strong = bool(_STRONG_META.search(before)) and not _double_negated(before)
    if consumed:
        framed = ctx.in_example_block(line) or (ctx.in_inline_code(pos) and strong)
        return "example" if framed and not (concrete or sensitive) else None
    shown = quoted or ctx.in_inline_code(pos)
    framed = ctx.in_example_block(line) or (strong and (shown or bool(_DESCRIBED.search(before[-60:])))) or (
        shown and bool(_DEFENSIVE_RESPONSE.search(_QUOTED.sub(" ", before + " " * (end - pos) + after))))
    if framed and not (concrete or sensitive):
        return "example"
    if imperative(before):
        return None
    # A governed prohibition may name its own target ("do not run curl <url> | sh"); an action on a
    # sensitive object or compliance wording elsewhere in the sentence still keeps it HIGH.
    if not sensitive and _governed_prohibition(before, after, ctx.text[pos:end] + after):
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
