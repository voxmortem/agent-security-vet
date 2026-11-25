"""Shared data model: severities, rule registry, findings."""
import hashlib

SEVERITIES = ("HIGH", "MED", "LOW")
SEV_RANK = {"HIGH": 0, "MED": 1, "LOW": 2}

# rule id -> {"category": str, "title": str}
RULES = {}


def rule(rid, category, title):
    """Register a rule id. Every finding must use a registered id."""
    RULES[rid] = {"category": category, "title": title}
    return rid


def bump(sev):
    """One step more severe."""
    return {"LOW": "MED", "MED": "HIGH", "HIGH": "HIGH"}[sev]


def lower(sev):
    """One step less severe."""
    return {"HIGH": "MED", "MED": "LOW", "LOW": "LOW"}[sev]


def worst(a, b):
    return a if SEV_RANK[a] <= SEV_RANK[b] else b


class Finding:
    __slots__ = ("sev", "rule", "category", "file", "line", "snippet", "note", "context",
                 "sha256", "fingerprint")

    def __init__(self, sev, rule_id, file, line, snippet, note, context="", sha256=""):
        self.sev = sev
        self.rule = rule_id
        self.category = RULES.get(rule_id, {}).get("category", "misc")
        self.file = file
        self.line = int(line or 0)
        self.snippet = snippet or ""
        self.note = note or ""
        self.context = context or ""
        self.sha256 = sha256 or ""
        basis = "\0".join((rule_id, file, self.context, " ".join(self.snippet.split())))
        self.fingerprint = hashlib.sha256(basis.encode("utf-8", "replace")).hexdigest()[:16]

    def sort_key(self):
        return (SEV_RANK[self.sev], self.file, self.line, self.rule, self.context, self.snippet, self.note)

    def as_dict(self):
        return {
            "severity": self.sev,
            "rule": self.rule,
            "category": self.category,
            "file": self.file,
            "line": self.line,
            "context": self.context,
            "snippet": self.snippet,
            "note": self.note,
            "file_sha256": self.sha256,
            "fingerprint": self.fingerprint,
        }
