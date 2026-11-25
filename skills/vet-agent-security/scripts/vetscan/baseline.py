"""Baseline (allow-list) of reviewed findings.

Each entry suppresses findings of one rule in one file, and only while the file's
SHA-256 is unchanged. Every entry needs a human justification. Entries that no
longer match are reported as stale; they never suppress anything.

Format:
{
  "version": 1,
  "entries": [
    {"rule": "inj-override", "file": "docs/examples.md", "sha256": "<64 hex>",
     "fingerprint": "<optional 16 hex: one specific finding>",
     "justification": "Quoted attack example in documentation; reviewed by <who> on <date>"}
  ]
}
"""
import json
import re

NEVER_SUPPRESS = frozenset(("scan-incomplete", "decode-budget", "decode-limit", "match-limit"))
MIN_JUSTIFICATION = 30          # characters
MIN_JUSTIFICATION_WORDS = 4
_SHA = re.compile(r"^[0-9a-f]{64}$")


def load(path):
    """Return (entries, problems). Invalid entries are dropped and described in problems."""
    problems = []
    try:
        with open(path, "r", encoding="utf-8") as fh:
            raw = fh.read(5_000_000)
        data = json.loads(raw)
    except (OSError, ValueError) as exc:
        return [], ["baseline file could not be read: %s" % type(exc).__name__]
    items = data.get("entries") if isinstance(data, dict) else None
    if not isinstance(items, list):
        return [], ["baseline file has no 'entries' list"]
    entries = []
    for i, e in enumerate(items[:20000]):
        if not isinstance(e, dict):
            problems.append("entry %d: not an object" % i)
            continue
        rule_id, file, sha = e.get("rule"), e.get("file"), str(e.get("sha256", "")).lower()
        just = e.get("justification")
        if not isinstance(rule_id, str) or not isinstance(file, str):
            problems.append("entry %d: needs string 'rule' and 'file'" % i)
        elif not _SHA.match(sha):
            problems.append("entry %d (%s): needs the file's sha256 (64 hex chars)" % (i, rule_id))
        elif (not isinstance(just, str) or len(just.strip()) < MIN_JUSTIFICATION
              or len(re.findall(r"[^\W\d_]{2,}", just)) < MIN_JUSTIFICATION_WORDS):
            problems.append("entry %d (%s): needs a justification of at least %d characters and %d words "
                            "(what was reviewed, by whom, when)" % (i, rule_id, MIN_JUSTIFICATION,
                                                                    MIN_JUSTIFICATION_WORDS))
        elif rule_id in NEVER_SUPPRESS:
            problems.append("entry %d: rule %s can never be baselined" % (i, rule_id))
        else:
            fp = e.get("fingerprint")
            entries.append({"rule": rule_id, "file": file.replace("\\", "/"), "sha256": sha,
                            "fingerprint": fp if isinstance(fp, str) and fp else None,
                            "justification": just.strip(), "used": 0})
    return entries, problems


def apply(findings, entries, file_hashes):
    """Split findings into (kept, suppressed, stale).

    suppressed: [(finding, justification)]
    stale:      [(entry, reason)] entries that matched nothing"""
    if not entries:
        return list(findings), [], []
    index = {}
    for e in entries:
        index.setdefault((e["rule"], e["file"]), []).append(e)
    kept, suppressed = [], []
    for f in findings:
        hit = None
        if f.sha256 and f.rule not in NEVER_SUPPRESS:
            for e in index.get((f.rule, f.file), ()):
                if e["sha256"] == f.sha256 and (e["fingerprint"] is None or e["fingerprint"] == f.fingerprint):
                    hit = e
                    break
        if hit:
            hit["used"] += 1
            suppressed.append((f, hit["justification"]))
        else:
            kept.append(f)
    stale = []
    for e in entries:
        if e["used"]:
            continue
        current = file_hashes.get(e["file"])
        if current is None:
            reason = "file not present in this scan"
        elif current != e["sha256"]:
            reason = "file changed since it was reviewed (hash differs): review again"
        else:
            reason = "no such finding any more"
        stale.append((e, reason))
    return kept, suppressed, stale


def template(findings):
    """A baseline skeleton for the given findings. Justifications are left empty on purpose."""
    seen, out = set(), []
    for f in findings:
        if not f.sha256 or f.rule in NEVER_SUPPRESS:
            continue
        key = (f.rule, f.file, f.fingerprint)
        if key in seen:
            continue
        seen.add(key)
        out.append({"rule": f.rule, "file": f.file, "sha256": f.sha256, "fingerprint": f.fingerprint,
                    "severity": f.sev, "justification": ""})
    return {"version": 1, "entries": out}
