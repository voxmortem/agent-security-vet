"""Injection phrase detection (English + Russian) over normalized text views.

Matching is anchor-driven: each rule has literal "heads" located with str.find
(fast, linear) and a bounded "tail" regex tried only at those positions. Tails
are written against a normalized view in which words are separated by exactly
one space (or newlines), so a literal space in a tail means "one separator".

Views:  plain   - lower-cased, punctuation and tags become separators
        deobf   - format/control/blank characters and marks removed, compatibility
                  forms folded, look-alike letters mapped, intra-word markup deleted
        punct-split - deobf with one punctuation mark between two letters deleted
        leet    - deobf plus digit/symbol-for-letter substitutions
        spaced  - deobf with runs of single letters joined
        rot13 / reversed - decoded on the fly around rot13/reversed heads
A hit that exists only in a non-plain view is reported as obfuscated.
"""
import re

from . import textutil as T
from .model import rule

SEP = r"[ \n]{1,20}"
MAX_HITS_PER_RULE = 1000     # per rule and view; reaching it is reported as an incomplete scan

rule("inj-override", "injection", "tells the model to drop or replace its prior/system instructions")
rule("inj-jailbreak", "injection", "jailbreak / unrestricted-persona wording")
rule("inj-persona", "injection", "re-assigns the model's role or task mid-content")
rule("inj-new-instructions", "injection", "announces replacement or secret instructions")
rule("inj-hide-from-user", "injection", "asks the model to conceal something from the user")
rule("inj-secrecy", "injection", "secrecy / stealth wording aimed at the model")
rule("inj-exfil-prompt", "injection", "asks for the system prompt or hidden instructions")
rule("inj-exfil-secrets", "injection", "asks to send secrets or private data somewhere")
rule("inj-exfil-url", "injection", "asks to place private data into a URL, link or image")
rule("inj-ai-addressed", "injection", "text addresses an AI reader directly")
rule("inj-authority", "injection", "claims authority or pre-authorization")
rule("inj-no-confirm", "injection", "tells the model to skip confirmation or auto-approve")
rule("inj-tool-coax", "injection", "coaxes the reader-agent into a tool call or action")
rule("inj-summary-hijack", "injection", "tries to steer how the page is summarized or answered")
rule("inj-user-directed", "injection", "tells the model what to tell or make the user do")
rule("inj-memory-poison", "injection", "asks the model to persist something into memory or instructions")
rule("inj-remote-instructions", "injection", "tells the model to fetch remote content and follow it")
rule("inj-image-render", "injection", "asks the model to render an image/link by URL (exfil beacon pattern)")
rule("inj-role-tags", "injection", "fake chat-template, system or tool-call tags")
rule("inj-tool-preamble", "injection", "tool-description wording that orders the model around (tool poisoning)")
rule("inj-hidden-imperative", "injection", "instruction-like wording inside non-rendered content")

# tier -> severity by context class: (hidden, instruction, page, other, tooldesc, consumed)
# "page" is visible text of a saved write-up (--kind article: quotes of attacks are expected);
# "consumed" is visible text of content an agent will read or act on (--kind page).
TIERS = {
    "strong": ("HIGH", "HIGH", "MED", "MED", "HIGH", "HIGH"),
    "weak": ("HIGH", "MED", "MED", "LOW", "MED", "MED"),
    "ai": ("HIGH", None, "MED", "MED", "MED", "MED"),
    "page": ("HIGH", None, "MED", "LOW", "MED", "MED"),
    "soft": ("MED", None, "LOW", None, "LOW", "LOW"),
    "softhi": ("HIGH", None, "LOW", None, "MED", "MED"),
    "tool": (None, None, None, None, "MED", None),
    "himp": ("MED", None, None, None, "MED", None),
}
_CLASS_IDX = {"hidden": 0, "instruction": 1, "page": 2, "other": 3, "tooldesc": 4, "consumed": 5}


def severity_for(tier, ctx_class):
    return TIERS[tier][_CLASS_IDX[ctx_class]]


_FOLD_RU = str.maketrans({chr(0x0451): chr(0x0435), chr(0x0439): chr(0x0438)})   # yo->ye, short-i->i


class PRule:
    __slots__ = ("id", "tier", "lang", "neg", "cond", "skip_after")

    def __init__(self, rid, tier, lang, neg=False, cond=False, skip_after=None):
        self.id = rid
        self.tier = tier
        self.lang = lang
        self.neg = neg
        self.cond = cond
        self.skip_after = re.compile(skip_after.replace(" ", SEP)) if skip_after else None


HEADS = {"en": {}, "ru": {}}       # head -> [(PRule, compiled tail)]
STEM_HEADS = {"en": set(), "ru": set()}
HEADS_ROT13 = {}                   # rot13(head) -> same list (English only)
HEADS_REV = {"en": {}, "ru": {}}   # reversed head -> same list
ALL_RULES = []

_FRAG = {}


def _expand(src):
    for _ in range(3):
        for k, v in _FRAG.items():
            src = src.replace("<" + k + ">", v)
    return src


def _add(rid, tier, lang, heads, tails, **kw):
    pr = PRule(rid, tier, lang, **kw)
    ALL_RULES.append(pr)
    if isinstance(tails, str):
        tails = (tails,)
    for head in heads.split("|"):
        head = head.strip()
        stem = head.endswith("~")
        if stem:
            head = head[:-1]
        if lang == "ru":
            head = head.translate(_FOLD_RU)
        for tail in tails:
            src = _expand(tail)
            if lang == "ru":
                src = src.translate(_FOLD_RU)
            # bounded repeats only: a tail must never run away over one long token
            src = src.replace("\\w*", "\\w{0,30}").replace("\\w+", "\\w{1,30}").replace(" ", SEP)
            rx = re.compile((r"\w{0,30}" if stem else r"(?!\w)") + src + r"(?!\w)")
            HEADS[lang].setdefault(head, []).append((pr, rx))
        if stem:
            STEM_HEADS[lang].add(head)


# ================================================================ English

_FRAG.update({
    "Q": "(?:all|any|every|each|the|your|my|these|those|this|that|of|such|other|its|their|our)",
    "PRI": "(?:previous|prior|above|earlier|preceding|former|original|initial|foregoing|aforementioned)",
    "ADJ": "(?:system|safety|security|ethical|content|moderation|developer|core|built in|default|own)",
    "N": "(?:instructions?|prompts?|rules?|directives?|guidelines?|guardrails?|constraints?|restrictions?|"
         "commands?|orders?|polic(?:y|ies)|programming|training|context|messages?|system prompt|"
         "safeguards?|protocols?|limitations?)",
    "NS": "(?:instructions?|prompts?|directives?|guidelines?|guardrails?|programming|training|restrictions?|"
          "constraints?|safeguards?|system prompt)",
    "USER": "(?:user|human|operator|owner|customer|anyone|anybody)s?",
    "F": "(?:me|us|it|them|out|back|all|any|the|your|its|their|this|that|user s|users|user|full|entire|whole|"
         "complete|current|contents?|content|value|values|a copy|copy|list|every|each|of|stored|saved|local|"
         "available|found|above|following|raw|plain|plaintext|and|or|my)",
    "SECRET": "(?:api keys?|access keys?|secret keys?|access tokens?|auth(?:entication)? tokens?|bearer tokens?|"
              "session tokens?|oauth tokens?|refresh tokens?|private keys?|ssh keys?|ssh private keys?|"
              "signing keys?|encryption keys?|credentials?|passwords?|passphrases?|secrets|cookies|"
              "session cookies?|session ids?|environment variables|env vars?|env variables|env file|dotenv|"
              "conversation history|chat history|chat logs?|conversation|message history|browsing history|"
              "browser history|saved passwords|keychain|wallet|seed phrase|recovery phrase|mnemonic|"
              "2fa codes?|otp|one time (?:code|password)s?|verification codes?|credit card(?: numbers?| details)?|"
              "card numbers?|social security numbers?|bank details|private data|personal data|"
              "personal information|confidential (?:data|information|files?)|sensitive (?:data|information|files?)|"
              "id rsa|aws credentials|kubeconfig|tokens?|keys|system prompt)",
    "SFILE": "(?:ssh keys?|ssh private keys?|private keys?|id rsa|id ed25519|ssh id rsa|ssh|aws credentials|aws|"
             "env file|env|dotenv|mcp json|claude json|npmrc|netrc|kubeconfig|keychain|wallet|cookies|"
             "browser (?:history|data|cookies|passwords|profile)|saved passwords|"
             "password (?:file|store|manager|database)|credentials? files?|credentials json|shadow|passwd)",
    "DEST": "(?:(?:to|at|into|via|through|using|on) (?:(?:the|a|an|this|that|my|our|following|external|remote|"
            "attacker s|another|third party|same) ){0,2}(?:https?|www|webhook|pastebin|discord|telegram|slack|"
            "attacker|sidenote|gist|email(?: address)?|url|link|endpoint|address|site|website|domain|server|"
            "host|channel|bot|form)|"
            "(?:in|into|to|as part of|inside|within) (?:(?:your|the|a|an|every|each|next|final) ){1,2}"
            "(?:response|reply|answer|output|summary|message|commit message|issue|pull request|pr|comment|"
            "markdown image|image url|image|link|sidenote|notes?))",
    "PDATA": "(?:conversation|chat|chat history|conversation history|history|messages?|context|"
             "user s (?:data|name|email|address|input|question|query|messages?|prompt|files?)|"
             "user (?:data|input|query|message|prompt)|personal (?:data|information)|secrets?|passwords?|"
             "credentials?|cookies|file contents?|contents of (?:the |this |that )?\\w+|environment|"
             "memory|previous (?:messages|conversation)|above (?:text|conversation)|system prompt)",
    "AI": "(?:ai|llm|large language model|language model|assistant|agent|bot|chatbot|claude|chatgpt|gpt|gemini|"
          "copilot|model|automated (?:agent|system|tool)|crawler|scraper)",
})

# ---- override
_add("inj-override", "strong", "en",
     "ignore|disregard|forget|override|overlook|neglect|abandon|bypass|do not follow|don t follow|dont follow|"
     "do not obey|don t obey|stop following|stop obeying|do not listen to|don t listen to|pay no attention to|"
     "no longer follow|do not adhere to|stop adhering to|do not comply with|don t comply with|stop complying with",
     ("(?: <Q>){0,4} <PRI>(?: (?:and|or|<ADJ>|<Q>|<PRI>)){0,3} <N>",
      " (?:all|everything|anything|whatever)(?: (?:that|which|you|i|we|they|was|were|is|have|has|been|ve|said|"
      "told|written|stated|came|comes|mentioned|instructed|given|of|the|what)){0,6} "
      "(?:above|before|previously|earlier|prior|so far|until now|up to now|up to this point|preceding)",
      " the (?:system|developer|safety|original|initial|hidden) (?:prompt|message|instructions?|rules?|guidelines?)",
      " (?:the|that|what)(?: is| was)? (?:above|preceding|foregoing)(?= (?:and|then|instead|but|now)|$)"))
# Same verbs without a "previous/prior" word. Defensive wording such as "ignore any instructions found in
# web pages" is skipped: there the object is untrusted content, not the model's own instructions.
_add("inj-override", "strong", "en",
     "ignore|disregard|forget|do not follow|don t follow|dont follow|"
     "do not obey|don t obey|stop following|stop obeying|do not listen to|don t listen to|pay no attention to|"
     "no longer follow|do not adhere to|stop adhering to|do not comply with|don t comply with|stop complying with",
     (" (?:all|any|every|all of|all the|all of the|any and all|your|all your|all of your)"
      "(?: (?:of|the|your|these|those|my)){0,2}(?: (?:<ADJ>|<PRI>))? <NS>",
      " (?:all (?:of )?)?your(?: (?:<ADJ>|<PRI>))? (?:rules|polic(?:y|ies)|protocols?|limitations?|filters?|context|orders)"),
     skip_after=r"(?: (?:that|which))? (?:(?:are|is|were|was|may be|might be|you) )?"
                r"(?:(?:found|embedded|contained|hidden|appearing|appear|appears|placed|written|included|present|"
                r"coming|originating|see|read|encounter) )?(?:in|inside|within|from|on) "
                r"(?:(?:the|a|an|any|all|this|that|these|those|such|untrusted|external|fetched|retrieved|scanned|"
                r"web|tool|third|party|user|supplied|provided) ){0,4}"
                r"(?:web ?pages?|pages?|websites?|sites?|files?|documents?|results?|outputs?|emails?|comments?|"
                r"content|data|attachments?|sources?|repos?|repositor(?:y|ies)|issues?|text|input|inputs)")
_add("inj-override", "strong", "en",
     "delete|erase|wipe|reset|clear|cancel|nullify|discard|drop|dismiss|supersede|replace|skip|void|remove|purge|unlearn",
     "(?: <Q>){0,3} <PRI>(?: system)? (?:instructions?|prompts?|directives?|guidelines?|guardrails?|programming|rules)")
_add("inj-override", "strong", "en",
     "previous instructions|prior instructions|above instructions|earlier instructions|preceding instructions|"
     "instructions above|original instructions|initial instructions|previous prompt|system prompt|"
     "your instructions|your guidelines|your rules|your programming|your restrictions|previous rules|"
     "prior rules|previous directives",
     " (?:are|is|were|was|have been|has been|should be|must be|will be|can be|shall be)"
     "(?: (?:now|hereby|all|to be|considered|completely|fully|entirely)){0,2} "
     "(?:void|invalid|obsolete|cancell?ed|outdated|revoked|superseded|overridden|null|"
     "no longer (?:valid|apply|applicable|in effect|relevant|binding)|deprecated|fake|ignored|disregarded|"
     "suspended|lifted|replaced|irrelevant|not (?:valid|applicable|binding))")

# ---- jailbreak / persona
_add("inj-jailbreak", "weak", "en",
     "you are now in|you re now in|you are in|enter|enable|activate|switch to|you are now|act as|pretend to be|"
     "pretend you are|roleplay as|you are",
     (" (?:dan|god|jailbreak|jailbroken|unrestricted|uncensored|unfiltered|evil|opposite) mode",
      " (?:an? )?(?:unrestricted|uncensored|unfiltered|jailbroken|amoral|unethical)(?: \\w+)?"))
_add("inj-jailbreak", "weak", "en", "you are now in|you re now in", " developer mode")
_add("inj-jailbreak", "weak", "en", "do anything now", "")
_add("inj-jailbreak", "weak", "en",
     "not bound by|no longer bound by|you have no|you are free from|you are freed from|you are free of",
     "(?: (?:all|any|your|the|openai|anthropic|google|ethical|moral|content|safety)){0,3} "
     "(?:restrictions?|limitations?|rules|guidelines|filters?|censorship|polic(?:y|ies)|guardrails?|constraints?)")
_add("inj-persona", "page", "en",
     "from now on|from this point on|from here on|starting now|henceforth|going forward",
     " (?:you|your|act|respond|reply|answer|always|never|ignore|do not|don t|only|treat|consider)")
_add("inj-persona", "page", "en",
     "you are now|you re now|you will now|you must now|your new|you have a new|your real|your true|"
     "your actual|your only",
     " (?:an? |the |my |our )?(?:\\w+ ){0,2}(?:assistant|agent|bot|ai|model|persona|role|task|goal|instructions?|"
     "objective|purpose|job|mission|identity|directive|priority|function)")
_add("inj-new-instructions", "softhi", "en",
     "new instructions|updated instructions|revised instructions|real instructions|actual instructions|"
     "true instructions|secret instructions|override instructions|overriding instructions|"
     "priority instructions|new system prompt|updated system prompt|new directive|new directives|"
     "system override|admin override|administrator override|instruction override", "")

# ---- hide from user / secrecy
_HIDE_VERBS = ("do not tell|don t tell|dont tell|never tell|do not inform|don t inform|never inform|"
               "do not notify|don t notify|never notify|do not alert|don t alert|never alert|do not warn|"
               "don t warn|never warn|not tell|not inform|not notify")
_HIDE_VERBS2 = ("do not mention|don t mention|never mention|do not reveal|don t reveal|never reveal|"
                "do not disclose|don t disclose|never disclose|do not show|don t show|never show|"
                "do not report|don t report|never report|do not explain|don t explain|not mention|not reveal|"
                "not disclose|" + _HIDE_VERBS)
_add("inj-secrecy", "weak", "en", _HIDE_VERBS, " (?:the |your |any )?<USER>",
     skip_after=r" (?:to|how|what to|when to|where to|which) ")
_add("inj-hide-from-user", "strong", "en", _HIDE_VERBS2,
     " (?:this|that|it|these|any of this|anything about (?:this|it)|the above|"
     "what you (?:did|do|are doing|have done)|these instructions|this instruction|this message|this step|"
     "this action|this change|this request|this part|this note|about (?:this|it|that|these instructions))"
     "(?: (?:to|with))? (?:the |your |any )?<USER>")
_add("inj-hide-from-user", "strong", "en",
     "without telling|without informing|without notifying|without alerting|without warning",
     " (?:the |your |any )?<USER>", neg=True)
_add("inj-hide-from-user", "strong", "en",
     "without the user|without the human|without the operator|without the owner|unbeknownst to the user|"
     "behind the user",
     "(?: s)? (?:knowing|knowledge|noticing|awareness|being aware|seeing|realizing|realising|finding out|back)",
     neg=True)
_add("inj-hide-from-user", "strong", "en",
     "do not include|don t include|never include|do not mention|don t mention|never mention|do not reference|"
     "don t reference|do not cite|do not repeat|don t repeat|do not output|do not print|do not reveal|"
     "never reveal|do not quote|omit",
     " (?:this|these|the above|any of these|the following) (?:instructions?|message|notes?|text|comment|prompt|"
     "directive|rules?|sentence|paragraph|section) (?:in|to|within|as part of|from) (?:your|the|any) "
     "(?:response|reply|answer|summary|output|final answer|chat|user)")
_add("inj-secrecy", "weak", "en", "keep this|keep it|keep that|keep these instructions|keep the following",
     " (?:a )?(?:secret|hidden|between us|to yourself)(?: from (?:the )?<USER>)?")
_add("inj-secrecy", "weak", "en",
     "the user cannot see|the user can t see|the user will not see|the user won t see|the user must not see|"
     "the user should not see|the user must not know|the user should not know|invisible to the user|"
     "hidden from the user|not visible to the user", "")
_add("inj-secrecy", "weak", "en",
     "silently|secretly|covertly|quietly|discreetly|stealthily|surreptitiously",
     " (?:send|upload|post|forward|email|exfiltrate|transmit|install|download|execute|collect|copy|harvest|"
     "steal|leak|share|append|insert|include|modify|delete|fetch|call|open|visit|navigate)")

# ---- exfiltration
_add("inj-exfil-prompt", "weak", "en",
     "reveal|print|output|repeat|show|display|tell me|give me|dump|disclose|leak|share|return|write out|"
     "recite|summarize|translate|encode|send|post|what is|what are|what s|what were",
     "(?: (?:me|us|them|out|back|all|the|your|its|full|entire|whole|complete|exact|verbatim|current|"
     "contents? of|text of|of|in full|word for word|everything in|everything from)){0,6} "
     "(?:system prompt|system message|system instructions|initial prompt|initial instructions|"
     "hidden instructions|hidden prompt|developer message|developer prompt|original instructions|"
     "original prompt|custom instructions|pre prompt|preprompt|instructions you were given|"
     "instructions given to you|prompt you were given)", neg=True)
_add("inj-exfil-secrets", "strong", "en",
     "send|post|upload|forward|email|transmit|exfiltrate|leak|submit|deliver|paste|attach|embed|append|"
     "include|encode|put|add|share|report|pass|provide|supply|write|copy|insert",
     "(?: <F>){0,6} <SECRET>(?: \\w+){0,8} <DEST>", neg=True)
_add("inj-exfil-secrets", "strong", "en",
     "exfiltrate|steal|harvest", "(?: <F>){0,6} <SECRET>", neg=True)
_add("inj-exfil-secrets", "strong", "en",
     "read|open|cat|load|access|get|fetch|grab|collect|retrieve|find|locate|search for|look for|scan for|"
     "gather|harvest|extract|steal|take|list|enumerate|zip|compress|archive",
     "(?: <F>){0,6} <SFILE>(?: \\w+){0,12} (?:and|then) (?:(?:then|also|silently|quietly|immediately|finally) )?"
     "(?:send|post|upload|pass|include|embed|append|attach|forward|email|transmit|encode|submit|share|"
     "exfiltrate|leak|report|paste|provide|supply|return)", neg=True)
_add("inj-exfil-url", "strong", "en",
     "append|add|include|insert|put|encode|embed|attach|substitute|replace|fill|interpolate|url encode|urlencode|"
     "base64 encode|concatenate|pass|send|place",
     "(?: <F>){0,6} <PDATA>(?: \\w+){0,8} (?:to|into|in|as|onto|at the end of|inside|within|via|through|using) "
     "(?:(?:the|a|an|this|that|following|each|every|its|query|get|url|image|link|request) ){0,3}"
     "(?:url|link|query(?: string)?|query param\\w*|parameter|param|image|img|markdown image|href|src|"
     "get request|hostname|subdomain|dns|domain)", neg=True)

# ---- AI-addressed
_add("inj-ai-addressed", "ai", "en", "if you are|if you re|when you are|whenever you are|since you are|as you are",
     " (?:an? |the )?<AI>")
_add("inj-ai-addressed", "ai", "en",
     "attention|note to|note for|notice to|notice for|message to|message for|instructions for|instructions to|"
     "instruction for|hello|hey|hi|dear|reminder to|reminder for|warning to|important for",
     " (?:all |any |the )?(?:ai|llm|language model|large language model|assistant|claude|chatgpt|gpt|gemini|"
     "copilot)s?(?: (?:assistants?|agents?|models?|systems?|bots?|crawlers?|readers?))?"
     "(?: (?:reading|processing|summarizing|summarising|visiting|browsing|crawling|analyzing|analysing|"
     "reviewing|parsing|accessing|viewing|indexing|evaluating))?")
_add("inj-ai-addressed", "ai", "en",
     "ai|llm|language model|language models|assistant|assistants|agent|agents|claude|chatgpt|gpt|gemini|copilot|"
     "ai assistant|ai assistants|ai agent|ai agents|ai model|ai models|ai system|ai systems",
     " (?:reading|visiting|browsing|crawling|scraping|summarizing|summarising|processing|parsing|analyzing|"
     "analysing|accessing|viewing|indexing|reviewing|evaluating) (?:this|the|these)")
_add("inj-ai-addressed", "ai", "en", "to the|for the|to any|for any|to all|for all",
     " (?:ai|llm|language model|large language model|assistant|claude|chatgpt|gpt|gemini|copilot)s?"
     "(?: (?:assistants?|agents?|models?|systems?|bots?|crawlers?|readers?))? "
     "(?:reading|processing|summarizing|summarising|visiting|browsing|crawling|analyzing|analysing|"
     "reviewing|parsing|accessing|viewing|indexing|evaluating)")
_add("inj-ai-addressed", "ai", "en", "as an ai|as a language model|as an llm|as an assistant|being an ai",
     " (?:you|your)")

# ---- authority / confirmation
_add("inj-authority", "weak", "en",
     "message|messages|note|instruction|instructions|notice|order|orders|directive|request|update|announcement|"
     "command|alert",
     " from (?:the |your )?(?:user|anthropic|openai|google|microsoft|admin|administrator|developers?|system|"
     "security team|owner|operator|it department|support team|management|ceo|creator|maintainers?)")
_add("inj-authority", "weak", "en", "pre authorized|pre authorised|preauthorized|preauthorised|pre approved", "")
_add("inj-authority", "weak", "en",
     "the user|your user|anthropic|openai|admin|administrator|the owner|the operator|the developer|system",
     " (?:has |have |had )?(?:already |explicitly |previously |fully )?(?:authori[sz]ed|approved|consented|"
     "granted|permitted|whitelisted|pre approved|signed off)", cond=True)
_add("inj-authority", "weak", "en", "this is|this was|the following is",
     " (?:an? )?(?:authori[sz]ed|approved|official|verified|legitimate|trusted|sanctioned) "
     "(?:request|instruction|message|action|operation|override|penetration test|security test|audit)")
_add("inj-authority", "weak", "en", "safety|security|content",
     " (?:filters?|guidelines?|polic(?:y|ies)|checks?|restrictions?|protocols?) "
     "(?:are|have been|is|has been|were) (?:disabled|suspended|lifted|removed|turned off|waived|bypassed|deactivated)")
_add("inj-no-confirm", "weak", "en",
     "do not ask|don t ask|never ask|without asking|no need to ask|do not request|without requesting|"
     "do not wait for|don t wait for|without waiting for|do not seek|without seeking|do not require|"
     "without requiring|do not prompt|without prompting",
     "(?: (?:the|a|an|any|for|them|him|her|user|users|human|humans|owner|operator|explicit|further|additional|"
     "prior|manual|their)){0,5} (?:confirmation|permission|approval|consent|authori[sz]ation|sign off|go ahead)",
     neg=True)
_add("inj-no-confirm", "weak", "en", "skip|bypass",
     "(?: (?:the|any|all|user|human|manual|every)){0,3} (?:confirmation|permission|approval|consent|"
     "authori[sz]ation)(?: (?:prompts?|dialogs?|steps?|checks?|requests?|screens?))?", neg=True)
_add("inj-no-confirm", "weak", "en",
     "auto approve|automatically approve|automatically accept|automatically confirm|auto accept|auto confirm|"
     "always approve|approve all|accept all permission|allow all permission|yes to all|click allow|"
     "click approve|press allow|grant all permissions", "", neg=True)
_add("inj-no-confirm", "weak", "en", "no|without",
     " (?:need for |further |additional |any )?(?:user )?(?:confirmation|approval|permission|consent|"
     "verification|review) (?:is |are )?(?:needed|required|necessary)", neg=True)

# ---- page-only steering
_add("inj-tool-coax", "soft", "en",
     "you must|you should|you need to|you have to|you are required to|you will|you shall|please|now|"
     "immediately|first|then|next|always|assistant|agent|claude|ai",
     "(?: \\w+){0,3} (?:call|use|invoke|run|execute|trigger|launch|open|visit|navigate to|go to|browse to|"
     "click|download|install|fetch|curl|wget)(?: (?:the|your|a|an|this|following|that|on)){0,2}(?: \\w+){0,2} "
     "(?:tool|function|command|shell command|terminal|bash|powershell|script|mcp|browser|url|link|website|"
     "package|extension|plugin|button|https?|www)")
_SUMMARY_HEADS = (
    "when summarizing|when summarising|when you summarize|when you summarise|if you summarize|"
    "if you are summarizing|while summarizing|in your summary|in your response|in your answer|in your reply|"
    "in your output|in your review|in your analysis|when describing this|when answering|when responding|"
    "when asked about|if asked about|if the user asks|when the user asks|when processing this|"
    "when reading this|when analyzing this|when reviewing this|when evaluating this|when translating this|"
    "when indexing this|before summarizing|before responding|before answering|after reading this|"
    "upon reading this|end your response|begin your response|start your response|end your reply|"
    "end your answer|start your reply|conclude your|prefix your|append to your|add to your|"
    "end every response|start every response|in every response|in all responses|in all your responses")
_add("inj-summary-hijack", "page", "en", _SUMMARY_HEADS,
     "(?: \\w+){0,14} (?:always|never|you must|you should|make sure|be sure|ensure|please|include|mention|say|"
     "state|add|append|recommend|emphasi[sz]e|highlight|tell|output|respond|reply|insert|conclude|do not|don t|"
     "omit|rate|rank|score|refer|direct|advise|suggest|praise|promote|ignore|instead|only|with)")
_add("inj-user-directed", "soft", "en",
     "tell the user|inform the user|remind the user|convince the user|persuade the user|assure the user|"
     "advise the user|instruct the user|ask the user|direct the user|encourage the user|urge the user|"
     "warn the user|recommend that the user|recommend the user|suggest that the user|suggest the user|"
     "get the user to|make the user|trick the user|have the user",
     " (?:that|to|they|their|it|about|he|she|this|the|into|click|visit|enter|provide|install|download|run|buy|"
     "pay|call|open|send|share|type|paste|log|sign)")
_add("inj-memory-poison", "page", "en",
     "remember|memorize|memorise|store|save|record|persist|add|write|append|update|keep|commit",
     "(?: (?:this|that|the following|these|it|them|permanently|forever|always|fact|facts|information|"
     "instruction|instructions|rule|rules|preference|note|as a)){0,5} (?:to|in|into|for|across|as)"
     "(?: (?:your|the|all|long term|persistent|permanent|every|any|future|subsequent)){0,3} "
     "(?:memory|memories|memory file|claude md|agents md|system prompt|custom instructions|"
     "user preferences|knowledge base|sessions?|conversations?|chats?|interactions?)")
_add("inj-image-render", "page", "en",
     "render|display|show|load|output|print|include|embed|insert|add|append|generate|create",
     "(?: (?:the|a|an|this|following|markdown|html|inline|hidden|tracking|invisible|1x1|small|single)){0,3} "
     "(?:image|img|picture|pixel|badge|img tag|image tag)(?: \\w+){0,8} (?:https?|www|url|src)")

# ---- remote instructions (applies to instruction files too)
_add("inj-remote-instructions", "strong", "en",
     "fetch|download|retrieve|load|read|open|visit|curl|wget|browse to|navigate to|go to",
     "(?: \\w+){0,6} (?:https?|www|url|link|website|webpage|web page|gist|pastebin|endpoint|"
     "remote (?:file|server|config|instructions?))(?: \\w+){0,14} "
     "(?:(?:and|then) (?:(?:then|also|always|immediately|carefully|strictly|exactly|please|you must|must|"
     "should) ){0,2}(?:follow|obey|execute|run|apply|comply with|carry out|perform|do what|do whatever|act on|"
     "implement|adhere to|treat (?:it|them|that|its contents?|the contents?) as|"
     "use (?:it|them|that|its contents?) as (?:your )?(?:new )?(?:instructions|system prompt|rules|guidance))|"
     "for (?:the |your |its )?(?:latest|updated|new|further|additional|next) "
     "(?:instructions|commands|guidance|rules|steps|directions))")

# ---- tool-description poisoning
_add("inj-tool-preamble", "tool", "en",
     "before using this tool|before calling this tool|before using any tool|before any other tool|"
     "when this tool is available|whenever this tool|this tool must be called|this tool should be called|"
     "always call this tool|always use this tool|must be called before|must be invoked before|"
     "call this tool first|use this tool first|prior to using|whenever you use|whenever you send|"
     "whenever you call|otherwise the tool will|or the tool will|or the application will|or it will crash|"
     "has a very important side effect|side effect on the|instead of the usual|instead of using the", "")
_add("inj-hidden-imperative", "himp", "en",
     "you must|you should|you are required|you need to|you have to|your task|your instructions|"
     "your response|your reply|your answer|your output|always respond|always reply|always answer|"
     "always include|always mention|always say|never mention|never reveal|never say|do not mention|"
     "do not reveal|respond with|reply with|answer with|respond only|reply only|answer only|"
     "it is important that you|it is critical that you", "")

# ================================================================ Russian
# Written in natural spelling; the loader folds yo->ye and short-i->i on both sides.

_FRAG.update({
    "RQ": "(?:все|всеми|всех|любые|любых|эти|этих|свои|своих|твои|твоих|ваши|ваших|данные|данных|мои|моих|на)",
    "RPRI": "(?:предыдущ\\w*|прежн\\w*|прошл\\w*|ранние|ранних|вышеуказанн\\w*|вышеизложенн\\w*|выше|старые|"
            "старых|системн\\w*|исходн\\w*|первоначальн\\w*|изначальн\\w*|начальн\\w*|ранее)",
    "RN": "(?:инструкци\\w*|указани\\w*|правил\\w*|промпт\\w*|команд\\w*|директив\\w*|ограничени\\w*|"
          "установк\\w*|запрет\\w*|предписани\\w*|требовани\\w*)",
    "RUSER": "(?:пользовател\\w*|юзер\\w*|человек\\w*|оператор\\w*|владельц\\w*|хозяин\\w*)",
    "RSECRET": "(?:(?:api |апи )?ключ\\w*|токен\\w*|парол\\w*|секрет\\w*|учетн\\w+ данн\\w+|креденшел\\w*|куки|"
               "cookies?|переменн\\w+ окружени\\w*|переменн\\w+ сред\\w+|"
               "истори\\w+ (?:переписк\\w*|чат\\w*|диалог\\w*|разговор\\w*|сообщени\\w*|браузер\\w*)|переписк\\w+|"
               "приватн\\w+ ключ\\w*|закрыт\\w+ ключ\\w*|ssh ключ\\w*|сид фраз\\w*|seed фраз\\w*|"
               "персональн\\w+ данн\\w+|личн\\w+ данн\\w+|конфиденциальн\\w+ \\w+|содержимое (?:файл\\w*|env\\w*))",
    "RAI": "(?:ии|аи|ai|llm|нейросет\\w*|нейронк\\w*|языков\\w+ модел\\w*|ассистент\\w*|агент\\w*|бот\\w*|"
           "(?:чат )?бот\\w*|claude|chatgpt|gpt|модел\\w*|искусственн\\w+ интеллект\\w*)",
})

_add("inj-override", "strong", "ru",
     "игнорир~|проигнорир~|забуд~|отбрось~|отмени~|пренебрег~|не следуй~|не слушай~|не выполняй~|"
     "не соблюдай~|не учитывай~|не обращай~|перестань следовать|больше не следуй~",
     ("(?: внимани\\w+ на)?(?: <RQ>){0,3}(?: <RPRI>){1,3} <RN>",
      " (?:все|всеми|любые|свои|твои|ваши)(?: (?:предыдущие|системные|прежние))? "
      "(?:инструкци\\w*|указани\\w*|ограничени\\w*|правила)",
      " (?:все|обо всем)(?: (?:что|чему|о чем))?(?: \\w+){0,4} "
      "(?:выше|раньше|ранее|до этого|прежде|было сказано|тебе говорили|тебе сказали|вам говорили)"))
_add("inj-secrecy", "weak", "ru",
     "не говори~|не сообщай~|не рассказывай~|не уведомляй~|не информируй~|не предупреждай~|ничего не говори~",
     "(?: (?:об этом|это|этого|про это|ничего|никому|от|для)){0,3} <RUSER>")
_add("inj-hide-from-user", "strong", "ru",
     "не показывай~|не упоминай~|не раскрывай~|не выдавай~|скрой~|скрывай~|утаи~|утаивай~|не говори~|"
     "не сообщай~|не рассказывай~",
     " (?:об этом|это|этого|про это|эти инструкци\\w+|эту инструкци\\w+|это сообщени\\w+|этот шаг|"
     "это действи\\w+|вышесказанн\\w+|что ты (?:сделал|делаешь))(?: (?:от|для))? <RUSER>")
_add("inj-hide-from-user", "strong", "ru",
     "втайне от|тайно от|в тайне от|незаметно для|скрытно от|без ведома", " <RUSER>", neg=True)
_add("inj-exfil-prompt", "weak", "ru",
     "покажи~|выведи~|раскрой~|повтори~|напиши~|напечатай~|сообщи~|выдай~|перескажи~|процитируй~|отправь~",
     "(?: (?:мне|нам|сюда|весь|полный|полностью|свой|свои|твой|твои|ваш\\w*|текст\\w*|дословно)){0,5} "
     "(?:системн\\w+ (?:промпт\\w*|инструкци\\w*|сообщени\\w*)|скрыт\\w+ инструкци\\w*|"
     "исходн\\w+ (?:промпт\\w*|инструкци\\w*)|начальн\\w+ (?:промпт\\w*|инструкци\\w*))", neg=True)
_add("inj-exfil-secrets", "strong", "ru",
     "отправь~|перешли~|пересылай~|передай~|вышли~|загрузи~|выгрузи~|слей~|сливай~|покажи~|выведи~|"
     "напечатай~|раскрой~|выдай~|скопируй~|вставь~|включи~|добавь~",
     "(?: (?:мне|нам|сюда|все|весь|полный|полностью|свой|свои|твой|твои|ваш\\w*|содержим\\w+|значени\\w+|"
     "список|копию|эт\\w+|из)){0,5} <RSECRET>(?: \\w+){0,8} "
     "(?:(?:на|в|по|через) (?:(?:этот|эту|следующий|следующую|мой|мою|наш|нашу|внешний|внешнюю|удаленный|"
     "удаленную) ){0,2}(?:https?|www|адрес\\w*|сервер\\w*|сайт\\w*|ссылк\\w+|url|вебхук\\w*|webhook|"
     "почт\\w+|email|телеграм\\w*|telegram|бот\\w*|канал\\w*|форм\\w+)|"
     "в (?:(?:свой|своем|свою|твой|твоем|ваш|вашем) )?(?:ответ\\w*|вывод\\w*|резюме|пересказ\\w*|"
     "сообщени\\w+|комментари\\w+|ссылк\\w+|картинк\\w+|изображени\\w+))", neg=True)
_add("inj-ai-addressed", "ai", "ru", "если ты|если вы|когда ты|раз ты|поскольку ты",
     "(?: \\w+)? <RAI>")
_add("inj-ai-addressed", "ai", "ru",
     "внимание|вниманию|обращение к|сообщение для|примечание для|инструкция для|инструкции для|"
     "указание для|указания для|важно для|уважаем~|привет",
     " (?:всем |всех |любому |любого |любой )?(?:ии|аи|ai|llm|нейросет\\w*|языков\\w+ модел\\w*|"
     "ассистент\\w*|claude|chatgpt|gpt)(?: (?:ассистент\\w*|агент\\w*|модел\\w*))?")
_add("inj-ai-addressed", "ai", "ru", "ии|аи|ai|llm|ассистент~|агент~|нейросет~|модел~",
     "(?: \\w+)? (?:чита\\w+|обрабатыва\\w+|анализиру\\w+|просматрива\\w+|пересказыва\\w+|суммариз\\w+|"
     "резюмиру\\w+) (?:эт\\w+|данн\\w+) (?:страниц\\w*|стать\\w*|документ\\w*|текст\\w*|сайт\\w*|письм\\w*|"
     "сообщени\\w*)")
_add("inj-new-instructions", "softhi", "ru",
     "новые инструкции|новая инструкция|новые указания|настоящие инструкции|реальные инструкции|"
     "истинные инструкции|секретные инструкции|скрытые инструкции|новый системный промпт|"
     "новая задача для|новое задание для", "")
_add("inj-persona", "page", "ru",
     "с этого момента|отныне|начиная с этого момента|теперь ты|ты теперь|твоя новая|твоя настоящая|"
     "твоя единственная|ты больше не",
     "(?: \\w+){0,3}")
_add("inj-jailbreak", "weak", "ru",
     "режим разработчика|режим бога|режим без ограничений|режим dan|без каких либо ограничений|"
     "без любых ограничений|без цензуры|у тебя нет ограничений|ты не связан", "")
_add("inj-authority", "weak", "ru",
     "сообщение|указание|инструкция|инструкции|распоряжение|приказ|уведомление|запрос|команда",
     " от (?:пользовател\\w+|администратор\\w+|админ\\w+|разработчик\\w+|систем\\w+|anthropic|openai|"
     "владельц\\w+|службы безопасности|оператор\\w+|руководств\\w+)")
_add("inj-authority", "weak", "ru", "пользователь|администратор|админ|владелец|разработчик|оператор",
     " (?:уже |явно |заранее |полностью )?(?:разрешил|одобрил|согласился|подтвердил|авторизовал|"
     "дал (?:согласие|разрешение)|санкционировал)", cond=True)
_add("inj-no-confirm", "weak", "ru",
     "не спрашивай~|не запрашивай~|не проси~|не жди~|не дожидайся~|не требуй~",
     "(?: (?:у |от )?<RUSER>)?(?: (?:никаких|никакого|дополнительн\\w+|явн\\w+))? "
     "(?:подтверждени\\w+|разрешени\\w+|согласи\\w+|одобрени\\w+)", neg=True)
_add("inj-no-confirm", "weak", "ru", "подтверждение|разрешение|согласие|одобрение",
     "(?: <RUSER>)? не (?:требуется|нужно|нужны|обязательно)", neg=True)
_add("inj-tool-coax", "soft", "ru",
     "ты должен|вы должны|тебе нужно|вам нужно|пожалуйста|теперь|немедленно|сначала|затем|далее|всегда",
     "(?: \\w+){0,3} (?:вызови|вызовите|используй|используйте|запусти|запустите|выполни|выполните|исполни|"
     "открой|откройте|перейди|перейдите|скачай|скачайте|установи|установите|нажми|нажмите)(?: \\w+){0,3} "
     "(?:инструмент\\w*|функци\\w+|команд\\w+|терминал\\w*|скрипт\\w*|ссылк\\w+|сайт\\w*|страниц\\w+|url|bash|"
     "powershell|браузер\\w*|кнопк\\w+|пакет\\w*|расширени\\w+|плагин\\w*|https?|www)")
_add("inj-summary-hijack", "page", "ru",
     "при пересказе|при суммаризации|при резюмировании|при обработке|при анализе|при чтении|при описании|"
     "при составлении|при ответе|при оценке|при переводе|когда будешь пересказывать|когда пересказываешь|"
     "если пересказываешь|в своем ответе|в твоем ответе|в вашем ответе|в своем пересказе|в своем резюме|"
     "в своем саммари|в своем обзоре|в своем выводе|в конце ответа|в начале ответа|в каждом ответе|"
     "если пользователь спросит|когда пользователь спросит|если спросят",
     "(?: \\w+){0,14} (?:всегда|никогда|обязательно|укажи\\w*|упомяни\\w*|напиши\\w*|добавь\\w*|скажи\\w*|"
     "включи\\w*|порекомендуй\\w*|рекомендуй\\w*|не упоминай\\w*|ответь\\w*|вставь\\w*|допиши\\w*|"
     "подчеркни\\w*|только|нужно|должен|должна|следует)")
_add("inj-user-directed", "soft", "ru",
     "скажи пользователю|сообщи пользователю|убеди пользователя|передай пользователю|напомни пользователю|"
     "посоветуй пользователю|порекомендуй пользователю|заставь пользователя|попроси пользователя",
     "(?: \\w+)?")
_add("inj-memory-poison", "page", "ru",
     "запомни~|сохрани~|запиши~|добавь~|внеси~|зафиксируй~",
     "(?: \\w+){0,4} (?:в (?:свою |твою |долговременную |постоянную )?(?:память|claude md|agents md|"
     "системн\\w+ промпт|пользовательск\\w+ инструкци\\w+|заметк\\w+)|навсегда|на будущее|"
     "для всех (?:будущих|следующих) (?:сесси\\w+|диалог\\w+|разговор\\w+|чат\\w+))")
_add("inj-remote-instructions", "strong", "ru",
     "скачай~|загрузи~|открой~|прочитай~|прочти~|получи~|перейди~|зайди~|запроси~",
     "(?: \\w+){0,6} (?:https?|www|ссылк\\w+|url|сайт\\w*|адрес\\w*)(?: \\w+){0,14} "
     "(?:и|затем|потом|после чего)(?: \\w+){0,2} (?:следуй\\w*|выполни\\w*|исполни\\w*|запусти\\w*|"
     "примени\\w*|делай\\w*|сделай\\w*)")
_add("inj-hidden-imperative", "himp", "ru",
     "ты должен|ты обязан|вы должны|тебе нужно|твоя задача|твой ответ|всегда отвечай|никогда не упоминай|"
     "не упоминай|ответь только|отвечай только", "")



def _key_word(head, lang):
    """A whole token that must be present whenever `head` can match, or None if there is none.

    A head starts at a token boundary, so its first word is a complete token unless the head is a
    single-word stem (which continues into the rest of the word)."""
    if " " not in head and head in STEM_HEADS[lang]:
        return None
    return head.split(" ", 1)[0]


# Search plans: (text to find, tails, token that must exist in the view or None).
PLAN = {"en": [], "ru": []}
PLAN_ROT13 = []
PLAN_REV = {"en": [], "ru": []}
_CODED_TIERS = ("strong", "weak", "ai", "page")
for _lang in ("en", "ru"):
    for _head, _lst in HEADS[_lang].items():
        _key = _key_word(_head, _lang)
        PLAN[_lang].append((_head, _lst, _key))
        _sel = [e for e in _lst if e[0].tier in _CODED_TIERS]
        if _sel and len(_head) >= 3:
            HEADS_REV[_lang][_head[::-1]] = _sel
            PLAN_REV[_lang].append((_head[::-1], _sel, _key[::-1] if _key else None))
            if _lang == "en":
                HEADS_ROT13[_head.translate(T.ROT13)] = _sel
                PLAN_ROT13.append((_head.translate(T.ROT13), _sel, _key.translate(T.ROT13) if _key else None))

# Literal words used by the phrase rules (heads and tails). A word that only exists after joining
# punctuation-split pieces must be one of these for a punct-split hit to count.
VOCAB = {}
for _lang in ("en", "ru"):
    _words = set()
    for _head, _lst in HEADS[_lang].items():
        _words.update(re.findall(r"[^\W\d_]{3,}", _head))
        for _pr, _rx in _lst:
            _words.update(re.findall(r"[^\W\d_]{3,}", _rx.pattern.replace("\\w", " ")))
    VOCAB[_lang] = frozenset(_words)
_VOCAB_LONG = {k: tuple(sorted(w for w in v if len(w) >= 4)) for k, v in VOCAB.items()}


def _in_vocab(tok, lang):
    """Exact vocabulary word, or one differing only by a short ending ("instruction" ~ "instructions?",
    a Russian stem plus its inflection)."""
    if tok in VOCAB[lang]:
        return True
    if len(tok) < 4:
        return False
    return any((v.startswith(tok) or tok.startswith(v)) and abs(len(v) - len(tok)) <= 3 for v in _VOCAB_LONG[lang])

# Phrases searched inside joined letter-spaced runs, where no separators survive.
SQUEEZED = tuple((rid, tier, re.compile(src)) for rid, tier, src in (
    ("inj-override", "strong",
     r"(?:ignore|disregard|forget|override)(?:all|any|the|your|every)?(?:of)?(?:the|your)?"
     r"(?:previous|prior|above|earlier|preceding|system|original)(?:system)?"
     r"(?:instructions?|prompts?|rules|directives|guidelines)"),
    ("inj-hide-from-user", "strong",
     r"(?:donot|dont|never|without)(?:tell|inform|notify|alert|mention|reveal)(?:ing)?(?:this|it|that)?(?:to)?"
     r"(?:the|your)?user"),
    ("inj-exfil-prompt", "weak",
     r"(?:reveal|print|output|repeat|show|display|leak)(?:me)?(?:the|your)?(?:full|entire)?"
     r"(?:system|hidden|initial|original)(?:prompt|instructions?|message)"),
    ("inj-exfil-secrets", "strong",
     r"(?:send|post|upload|forward|email|exfiltrate|leak)(?:me|us)?(?:all|the|your|any)?(?:the|your)?"
     r"(?:apikeys?|credentials|passwords?|secrets|tokens?|cookies|sshkeys?|privatekeys?|"
     r"environmentvariables|envvars?|conversation|chathistory)"),
    ("inj-ai-addressed", "ai",
     r"(?:ifyouarean?|attention|noteto|dear)(?:ai|llm|languagemodel|assistant|aiassistant|aiagent)"),
    ("inj-override", "strong",
     "(?:игнорируи|проигнорируи|забудь)(?:все|всё)?(?:предыдущие|прежние|системные)"
     "(?:инструкции|указания|правила)".translate(_FOLD_RU)),
    ("inj-secrecy", "weak",
     "не(?:говори|сообщаи|показываи|рассказываи)(?:обэтом|это)?пользователю"),
))

# ---------------------------------------------------------------- guards

_NEG_RX = re.compile(
    r"(?:^|[ \n])(?:never|not|don t|dont|doesn t|didn t|cannot|can t|won t|wouldn t|shouldn t|mustn t|"
    r"avoid\w*|refus\w+|instead of|rather than|prevent\w*|block\w*|detect\w*|reject\w*|flag\w*|redact\w*|"
    r"mask\w*|forbid\w*|prohibit\w*|disallow\w*|никогда|нельзя|запрещено|запрещается|недопустимо|не|ни)"
    r"((?:[ \n]\w+){0,3})[ \n]?$")
_DOUBLE_NEG_RX = re.compile(
    r"\b(?:forget|hesitate|fail|neglect|omit|refuse|decline|miss|bother|забудь|забываи|стесняися|боися|медли)\b")
_COND_RX = re.compile(
    r"(?:^|[ \n])(?:after|once|until|unless|if|when|whether|only|ensure|confirm|verify|check|wait|sure|that|"
    r"before|whenever|after the|после|если|когда|пока|убедись|проверь|только)((?:[ \n]\w+){0,3})[ \n]?$")


def _negated(view, start):
    m = _NEG_RX.search(view, max(0, start - 70), start)
    return bool(m) and not _DOUBLE_NEG_RX.search(m.group(1))


def _conditional(view, start):
    return bool(_COND_RX.search(view, max(0, start - 60), start))


# ---------------------------------------------------------------- matching


class Hit:
    __slots__ = ("rule", "tier", "line", "excerpt", "mode", "match")

    def __init__(self, rid, tier, line, excerpt, mode, match=""):
        self.rule = rid
        self.tier = tier
        self.line = line
        self.excerpt = excerpt
        self.mode = mode
        self.match = match


def _excerpt(view, start, end):
    a = max(0, start - 30)
    b = min(len(view), end + 50)
    return view[a:b].replace("\n", " ").strip()


class Hits(list):
    """List of Hit; `capped` names the rules whose per-view match limit was reached."""
    capped = ()


def _line(view, i, linemap):
    n = view.count("\n", 0, i)
    return linemap[n] if linemap else n + 1


def _match_view(view, plan, mode, out, seen, budget, words=None, linemap=None):
    """Try every head of `plan` in `view`; append Hit objects for new (rule, line) pairs."""
    counts = {}
    n = len(view)
    if words is None:
        words = set(view.split())
    for head, entries, key in plan:
        if key is not None and key not in words:
            continue
        i = view.find(head)
        hl = len(head)
        while i != -1:
            if i == 0 or view[i - 1] in " \n":
                e = i + hl
                for pr, rx in entries:
                    if counts.get(pr.id, 0) >= MAX_HITS_PER_RULE:
                        if isinstance(out, Hits):
                            out.capped = tuple(sorted(set(out.capped) | {pr.id}))
                        continue
                    m = rx.match(view, e)
                    if not m:
                        continue
                    if pr.neg and _negated(view, i):
                        continue
                    if pr.cond and _conditional(view, i):
                        continue
                    if pr.skip_after and pr.skip_after.match(view, m.end()):
                        continue
                    line = _line(view, i, linemap)
                    counts[pr.id] = counts.get(pr.id, 0) + 1
                    key = (pr.id, line)
                    if key in seen:
                        continue
                    seen.add(key)
                    out.append(Hit(pr.id, pr.tier, line, _excerpt(view, i, min(m.end(), n)), mode,
                                   view[i:m.end()]))
            i = view.find(head, i + 1)
        if budget and budget.expired():
            return


def _match_coded(view, view_ru, out, seen, words, words_ru, linemap=None, linemap_ru=None):
    """rot13 and reversed variants: decode a window around each coded head."""
    for head, entries, key in PLAN_ROT13:
        if key is not None and key not in words:
            continue
        i = view.find(head)
        while i != -1:
            if i == 0 or view[i - 1] in " \n":
                win = view[i:i + 700].translate(T.ROT13)
                for pr, rx in entries:
                    m = rx.match(win, len(head))
                    if m:
                        line = _line(view, i, linemap)
                        key = (pr.id, line, "rot13")
                        if key not in seen:
                            seen.add(key)
                            out.append(Hit(pr.id, pr.tier, line, win[:m.end() + 30].replace("\n", " "), "rot13"))
            i = view.find(head, i + 1)
    for lang, v, w, lm in (("en", view, words, linemap), ("ru", view_ru, words_ru, linemap_ru)):
        if v is None:
            continue
        for head, entries, key in PLAN_REV[lang]:
            if key is not None and key not in w:
                continue
            i = v.find(head)
            hl = len(head)
            while i != -1:
                end = i + hl
                if end == len(v) or v[end] in " \n":
                    win = v[max(0, end - 700):end][::-1]
                    for pr, rx in entries:
                        m = rx.match(win, hl)
                        if m:
                            line = _line(v, i, lm)
                            key = (pr.id, line, "rev")
                            if key not in seen:
                                seen.add(key)
                                out.append(Hit(pr.id, pr.tier, line,
                                               win[:m.end() + 30].replace("\n", " "), "reversed"))
                i = v.find(head, i + 1)


def scan_text(text, budget=None):
    """Return a list of Hit for one text stream. `mode` is 'plain' or names the de-obfuscation used.

    Every view is matched after long runs of blank lines are squeezed out (line numbers are mapped
    back), so no amount of vertical whitespace separates the words of a phrase."""
    hits = Hits()
    if not text or not text.strip():
        return hits
    sq = T.squeeze_lines
    plain, plain_lm = sq(T.view_plain(text))
    cyr = T.has_cyrillic(text)
    plain_ru = plain.translate(_FOLD_RU) if cyr else None
    words = set(plain.split())
    words_ru = set(plain_ru.split()) if cyr else None
    seen = set()
    _match_view(plain, PLAN["en"], "plain", hits, seen, budget, words, plain_lm)
    if cyr:
        _match_view(plain_ru, PLAN["ru"], "plain", hits, seen, budget, words_ru, plain_lm)
    if budget and budget.expired():
        return hits

    base = T.deobf_base(text)
    pre = T.deobf_pre(base, T.TO_LATIN)
    deobf, deobf_lm = sq(T.view_from_pre(pre))
    if deobf != plain:
        _match_view(deobf, PLAN["en"], "deobfuscated", hits, seen, budget, None, deobf_lm)
    deobf_ru = deobf_ru_lm = pre_ru = None
    if cyr:
        pre_ru = T.deobf_pre(base, T.TO_CYRILLIC)
        deobf_ru, deobf_ru_lm = sq(T.view_from_pre(pre_ru).translate(_FOLD_RU))
        if deobf_ru != plain_ru:
            _match_view(deobf_ru, PLAN["ru"], "deobfuscated", hits, seen, budget, None, deobf_ru_lm)
    if budget and budget.expired():
        return hits
    # Words split by one punctuation mark ("ig-nore", "in.struc.tions", "sys_tem"). A hit counts only if
    # a word created by the joining is part of the phrase vocabulary (so "auto-enable" -> "autoenable"
    # cannot make a bounded word gap reach further than in the plain view).
    for p, lang, ref, ref_lm, fold in ((pre, "en", deobf, deobf_lm, False), (pre_ru, "ru", deobf_ru, deobf_ru_lm, True)):
        if p is None:
            continue
        joined = T.join_intra_punct(p)
        if joined == p:
            continue
        jv, jlm = sq(T.view_from_pre(joined).translate(_FOLD_RU) if fold else T.view_from_pre(joined))
        if jv == ref:
            continue
        tmp = Hits()
        _match_view(jv, PLAN[lang], "punct-split", tmp, set(seen), budget, None, jlm)
        if not tmp:
            continue
        ref_lines = ref.split("\n")
        index = {n: i for i, n in enumerate(ref_lm)} if ref_lm else None
        for h in tmp:
            first = index.get(h.line) if index is not None else h.line - 1
            if first is None:
                continue
            near = set(" ".join(ref_lines[first:first + 1 + h.match.count("\n")]).split())
            if any(_in_vocab(t, lang) for t in set(h.match.split()) - near) and (h.rule, h.line) not in seen:
                seen.add((h.rule, h.line))
                hits.append(h)
    if T.LEET_HINT_RX.search(pre):
        for table in (T.LEET_1, T.LEET_2):
            leet, leet_lm = sq(T.view_from_pre(pre, table))
            if leet != deobf:
                _match_view(leet, PLAN["en"], "leetspeak", hits, seen, budget, None, leet_lm)
    for view, lang, lm in ((deobf, "en", deobf_lm), (deobf_ru, "ru", deobf_ru_lm)):
        if view is None:
            continue
        joined, runs = T.join_spaced(view)
        if runs:
            _match_view(joined, PLAN[lang], "letter-spaced", hits, seen, budget, None, lm)
            for line, run in runs:
                if lm:
                    line = lm[line - 1]
                for rid, tier, rx in SQUEEZED:
                    if (rid, line) not in seen and rx.search(run):
                        seen.add((rid, line))
                        hits.append(Hit(rid, tier, line, run[:120], "letter-spaced"))
    _match_coded(plain, plain_ru, hits, seen, words, words_ru, plain_lm, plain_lm)
    return hits


# ---------------------------------------------------------------- role / tool-call tags (raw text)

ROLE_TAG_RX = re.compile(
    r"<\|(?:im_start|im_end|system|user|assistant|endoftext|start_header_id|end_header_id|eot_id|begin_of_text)\|>"
    r"|\[/?inst\]|<<\s{0,3}/?sys\s{0,3}>>"
    r"|</?(?:system|system-reminder|system_reminder|system-prompt|system_prompt|admin|developer|assistant|human|"
    r"function_calls|function_results|tool_result|tool_use|tool_call|antml:[a-z_]{1,30})\s{0,3}>"
    r"|<invoke name=|\"type\"\s{0,3}:\s{0,3}\"tool_use\"")
ROLE_TAG_ANCHORS = ("<|", "[inst]", "[/inst]", "<<", "<system", "</system", "<admin", "</admin", "<developer",
                    "</developer", "<assistant", "</assistant", "<human", "</human", "<function_", "</function_",
                    "<tool_", "</tool_", "<antml", "</antml", "<invoke", "tool_use")


def scan_raw_markup(text, budget=None):
    """Catch-all for markup files: match phrases in the raw source with tags kept as words,
    so text hidden in tag names, attribute names or unparsed regions is still seen."""
    hits = Hits()
    view, lm = T.squeeze_lines(T.view_raw(text))
    seen = set()
    _match_view(view, PLAN["en"], "plain", hits, seen, budget, None, lm)
    if T.has_cyrillic(text):
        _match_view(view.translate(_FOLD_RU), PLAN["ru"], "plain", hits, seen, budget, None, lm)
    return hits


def find_role_tags(text_lower, limit=20):
    """Return [(line, tag_text)] for fake chat-template / system / tool-call tags."""
    out = []
    if not any(a in text_lower for a in ROLE_TAG_ANCHORS):
        return out
    for m in ROLE_TAG_RX.finditer(text_lower):
        out.append((T.line_of(text_lower, m.start()), m.group(0)))
        if len(out) >= limit:
            break
    return out
