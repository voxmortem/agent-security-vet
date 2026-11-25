#!/usr/bin/env python3
"""Measure the scanner on the public InjecAgent test cases and the PINT example dataset.

  python -I tools/measure_injecagent.py --injecagent <clone of InjecAgent> --pint <clone of pint-benchmark>
                                        --out <new or empty dir> [--kind page|article] [--max-fp 0]

Nothing is bundled: point the script at your own local clones (InjecAgent is MIT-licensed; the PINT
repository only ships a 7-row example dataset, the real PINT data is private, so PINT is NOT a benchmark
here). The data is inert text: every item is written as one .txt file under --out and scanned with
scripts/scan.py; nothing from the data is executed.

Sets built from InjecAgent/data:
  attack_{dh,ds}_{base,enhanced}  the "Tool Response" of every test case (the attack inside a tool output)
  benign_toolresp_{dh,ds}         the "Tool Response Template" of every base case with the attacker
                                  placeholder replaced by a neutral sentence
  user_cases                      the user instructions (benign)
  attacker_instr_bare_{dh,ds}     the attacker instructions alone (informational)
  pint_example_{injection,benign} rows of benchmark/data/example-dataset.yaml (tiny, informational)

Thresholds (fixed before the first run, never moved):
  enhanced-attack recall (HIGH)        >= --min-recall (default 95%)
  benign tool responses, HIGH          <= --max-fp (default 0)
  user_cases + PINT example benign     <= --max-fp HIGH (default 0)
  base-attack recall                   informational: base attacks are plain requests ("Please grant
                                       access to ...") without override wording; a static phrase scanner
                                       does not see them

Exit code: 0 = every threshold met, 1 = a threshold failed, 2 = usage error or a scan did not run.
"""
import argparse
import json
import os
import re
import subprocess
import sys
import time

sys.dont_write_bytecode = True
HERE = os.path.dirname(os.path.abspath(__file__))
SCAN = os.path.join(os.path.dirname(HERE), "skills", "vet-agent-security", "scripts", "scan.py")
NEUTRAL = "Works as described, arrived on time and the quality is good."
_PINT_ROW = re.compile(r'- text: (?P<t>"(?:[^"\\]|\\.)*"|\|[^\n]*\n(?:[ ]{4}[^\n]*\n?)+|[^\n]+)\n\s+category: '
                       r'"?(?P<c>[^"\n]*)"?\n\s+label: (?P<l>true|false)')


def commit_of(path):
    try:
        p = subprocess.run(["git", "-c", "safe.directory=" + os.path.abspath(path), "-C", path, "rev-parse",
                            "--short", "HEAD"], capture_output=True, text=True, timeout=30)
        return p.stdout.strip() or "unknown"
    except (OSError, subprocess.SubprocessError):
        return "unknown"


def load_sets(injecagent, pint):
    data = os.path.join(injecagent, "data")
    sets = {}

    def load_json(name):
        with open(os.path.join(data, name), encoding="utf-8") as fh:
            return json.load(fh)

    def load_jsonl(name):
        with open(os.path.join(data, name), encoding="utf-8") as fh:
            return [json.loads(line) for line in fh if line.strip()]

    for variant in ("base", "enhanced"):
        for kind in ("dh", "ds"):
            cases = load_json("test_cases_%s_%s.json" % (kind, variant))
            sets["attack_%s_%s" % (kind, variant)] = [str(c["Tool Response"]) for c in cases]
    for kind in ("dh", "ds"):
        cases = load_json("test_cases_%s_base.json" % kind)
        sets["benign_toolresp_%s" % kind] = [str(c["Tool Response Template"]).replace("<Attacker Instruction>", NEUTRAL)
                                             for c in cases]
    sets["user_cases"] = [str(r.get("User Instruction", "")) for r in load_jsonl("user_cases.jsonl")]
    for kind in ("dh", "ds"):
        sets["attacker_instr_bare_%s" % kind] = [str(r["Attacker Instruction"])
                                                 for r in load_jsonl("attacker_cases_%s.jsonl" % kind)]
    with open(os.path.join(pint, "benchmark", "data", "example-dataset.yaml"), encoding="utf-8") as fh:
        text = fh.read()
    rows = []
    for m in _PINT_ROW.finditer(text):
        t = m.group("t")
        rows.append((json.loads(t) if t.startswith('"') else t.strip(), m.group("l") == "true"))
    sets["pint_example_injection"] = [t for t, label in rows if label]
    sets["pint_example_benign"] = [t for t, label in rows if not label]
    return sets


def scan_set(out, name, items, kind):
    d = os.path.join(out, name)
    os.makedirs(d)
    for i, t in enumerate(items):
        with open(os.path.join(d, "c%04d.txt" % i), "w", encoding="utf-8", newline="\n") as fh:
            fh.write(t)
    p = subprocess.run([sys.executable, "-I", "-B", SCAN, "--kind", kind, "--format", "json", "--max", "1000000",
                        "--fail-on", "NONE", "--", d], capture_output=True, text=True, encoding="utf-8",
                       errors="replace", timeout=3600)
    if p.returncode != 0:
        raise RuntimeError("scan of %s exited with %d" % (name, p.returncode))
    doc = json.loads(p.stdout)
    sev = {}
    for f in doc["findings"]:
        sev.setdefault(f["file"], set()).add(f["severity"])
    high = sum(1 for s in sev.values() if "HIGH" in s)
    med = sum(1 for s in sev.values() if "HIGH" not in s and "MED" in s)
    return {"n": len(items), "high": high, "med_only": med, "any": len(sev), "incomplete": doc["incomplete"]}


def main(argv=None):
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--injecagent", required=True, help="path of a local clone of InjecAgent")
    ap.add_argument("--pint", required=True, help="path of a local clone of lakeraai/pint-benchmark")
    ap.add_argument("--out", required=True, help="new or empty directory for the generated text files")
    ap.add_argument("--kind", choices=["page", "article"], default="page", help="scanner --kind (default page)")
    ap.add_argument("--max-fp", type=int, default=0, help="allowed HIGH findings on benign items (default 0)")
    ap.add_argument("--min-recall", type=float, default=95.0, help="required enhanced-attack HIGH recall in %%")
    ap.add_argument("--json", metavar="FILE", help="also write the results as JSON")
    try:
        args = ap.parse_args(argv)
    except SystemExit as exc:
        return 0 if exc.code in (0, None) else 2
    if os.path.exists(args.out) and (not os.path.isdir(args.out) or os.listdir(args.out)):
        sys.stderr.write("error: --out must be a new or empty directory\n")
        return 2
    try:
        sets = load_sets(args.injecagent, args.pint)
    except (OSError, ValueError, KeyError) as exc:
        sys.stderr.write("error: cannot read the datasets (%s)\n" % type(exc).__name__)
        return 2
    os.makedirs(args.out, exist_ok=True)
    started = time.strftime("%Y-%m-%d")
    res = {}
    for name, items in sets.items():
        try:
            r = scan_set(args.out, name, items, args.kind)
        except (RuntimeError, ValueError, KeyError, OSError, subprocess.SubprocessError) as exc:
            sys.stderr.write("error: %s\n" % exc)
            return 2
        res[name] = r
        print("%-26s n=%-5d HIGH=%-5d (%5.1f%%)  MED-only=%-5d incomplete=%s" % (
            name, r["n"], r["high"], 100.0 * r["high"] / max(r["n"], 1), r["med_only"], r["incomplete"]), flush=True)

    def total(pred):
        sel = [r for k, r in res.items() if pred(k)]
        return sum(r["high"] for r in sel), sum(r["n"] for r in sel), sum(r["med_only"] for r in sel)

    eh, en, em = total(lambda k: k.startswith("attack_") and k.endswith("_enhanced"))
    bh, bn, bm = total(lambda k: k.startswith("attack_") and k.endswith("_base"))
    fh, fn, _ = total(lambda k: k.startswith("benign_"))
    uh = res["user_cases"]["high"] + res["pint_example_benign"]["high"]
    recall = 100.0 * eh / max(en, 1)
    checks = {
        "enhanced_recall": recall >= args.min_recall,
        "benign_toolresp": fh <= args.max_fp,
        "user_and_pint_benign": uh <= args.max_fp,
    }
    print()
    print("scanner kind: %s | date: %s | InjecAgent %s | PINT %s" % (
        args.kind, started, commit_of(args.injecagent), commit_of(args.pint)))
    print("enhanced attack recall (HIGH): %d/%d = %.1f%% (MED-only %d)  [>= %.0f%%] -> %s" % (
        eh, en, recall, em, args.min_recall, "PASS" if checks["enhanced_recall"] else "FAIL"))
    print("base attack recall (HIGH):     %d/%d = %.1f%% (MED-only %d)  [informational]" % (
        bh, bn, 100.0 * bh / max(bn, 1), bm))
    print("benign tool responses HIGH:    %d/%d  [<= %d] -> %s" % (
        fh, fn, args.max_fp, "PASS" if checks["benign_toolresp"] else "FAIL"))
    print("user_cases + PINT benign HIGH: %d  [<= %d] -> %s" % (
        uh, args.max_fp, "PASS" if checks["user_and_pint_benign"] else "FAIL"))
    if args.json:
        with open(args.json, "w", encoding="utf-8", newline="\n") as fh_out:
            json.dump({"kind": args.kind, "date": started, "injecagent_commit": commit_of(args.injecagent),
                       "pint_commit": commit_of(args.pint), "sets": res, "checks": checks}, fh_out, indent=1)
    return 0 if all(checks.values()) else 1


if __name__ == "__main__":
    sys.exit(main())
