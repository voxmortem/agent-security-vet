# Contributing

Thanks for helping. The bar is simple: every change keeps the thresholds green and comes with a test.

## Ground rules

- **Standard library only.** No runtime or test dependencies, no network access in tests except the
  loopback server used by the fetch tests.
- **Never commit raw payloads.** Fixtures are built at test time. Invisible, bidirectional and tag
  characters are written as `chr(0x...)`; the hygiene test rejects raw ones.
- **No personal data, real secrets or machine-specific paths** in code, tests or docs.
- **The scanner never executes, imports, extracts or fetches** anything from a target. A change that
  needs one of those is out of scope.
- **Output is data.** Anything derived from scanned content goes through `textutil.sanitize`.

## Workflow

Run from the repository root (`tests/` is not a package, so `python -m unittest tests.test_x` does not
work; use `discover`, with `-p` for one module):

```bash
python -I -B -m unittest discover -s tests -v
python -I -B -m unittest discover -s tests -p test_evasion.py -v
```

The full suite takes several minutes because it includes 5 MB adversarial timing tests. If your machine
is much slower than a laptop, set `VETSCAN_TEST_TIME_FACTOR` (for example `3`) to scale the 5 MB budget
(30 s by default); CI does this. The per-rule 2 s limit is never scaled.

1. Reproduce first: add a failing test.
   - missed attack: a case in `tests/test_evasion.py` (must be HIGH) or the matching rule test;
   - false positive: a fixture in `tests/corpus_benign.py` (must stay at 0 HIGH) or a precision case.
2. Fix the code. Do not loosen a threshold or delete a failing case to get green; if something truly
   cannot be detected, document it under "Honest limits" in the README and mark the test as an expected
   failure with the reason.
3. New regexes must run in linear time: no `.*`, no ambiguous nested repeats (a repeat inside a
   repeat only when each iteration is a forced token sequence, as in `textutil._TAG_RX`), and survive
   `tests/test_robustness.py`. Prefer a compact pattern plus a cheap predicate over "A ... B" gaps.
4. New rules are registered with `model.rule(id, category, title)`, get a positive test, and appear in
   `--list-rules`.
5. Keep `SKILL.md` lean (details go to `references/`) and keep the instruction files free of scanner
   findings: `tests/test_selfscan.py` checks both.
6. Add a line to `CHANGELOG.md`.

## Severity policy (do not change casually)

- hidden, encoded or obfuscated instruction-like text: HIGH; hidden text that gives the reader orders
  (`hidden-order`): HIGH; any other hidden page text of 20+ visible characters: MED
- text aimed at the reviewer or scanner (`inj-reviewer-steer`): HIGH, also in ordinary docs
- the same text in plain sight in a saved article (`--kind article`): MED; in content an agent will
  read (`--kind page`): HIGH for override, concealment, exfiltration and remote-instruction wording unless
  it stands in a code span, fence or blockquote introduced by wording that names an attack
- visible in a file that agents load as instructions: HIGH for override, concealment, exfiltration and
  remote-instruction wording; MED for weaker signals, for wording whose own clause names an attack, and
  under a prohibition that governs it, as long as the sentence carries no URL, no action on a sensitive
  object and no compliance wording (see `vetscan/framing.py` and "Honest limits" in the README); weak
  cues ("such as", "for example", "the user asks you to") lower nothing; a bare quoted order stays HIGH
- a scan that could not finish: HIGH (`scan-incomplete`); any content left unanalyzed by a limit
  (including PDF parts, unread archive members and unidentified encodings) is listed in the report header
  as incomplete

## Reporting security issues

See [SECURITY.md](SECURITY.md).
