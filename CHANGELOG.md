# Changelog

All notable changes to this project are documented here. The format follows Keep a Changelog, and
versions follow semantic versioning.

## [1.0.0] - 2026-11-26

### Added
- Skill `vet-agent-security` with three modes: vet a skill / plugin / MCP server / repository (A), vet an
  article or page (B), audit your own browsing-agent setup (C).
- `scripts/scan.py` and the `vetscan` package:
  - visibility-aware text streams for HTML, SVG, XML and Markdown;
  - English and Russian instruction-phrase rules matched on normalized views (invisible characters,
    compatibility forms, look-alike letters, combining marks, intra-word markup, letter spacing,
    digit-for-letter spelling, ROT13, reversed text);
  - decode-and-rescan for base64, base32, base85 / Ascii85 / Z85, hex (also byte-separated),
    quoted-printable, binary digits, escapes, UTF-7, percent-encoding, character references and
    character-code lists, four layers deep, with gzip/zlib/bz2/xz support;
  - invisible-character families: Unicode Tags (decoded), variation selectors (decoded), zero-width,
    bidirectional controls, control characters, mixed-script words;
  - structure-aware checks for skill frontmatter, plugin and marketplace manifests, hooks, MCP server
    entries and tool descriptions, agent settings, auto-loaded instruction files, git internals,
    package and build hooks, CI workflows, dev containers and auto-run editor files;
  - code-behaviour rules with same-file correlations;
  - archive listing without extraction, binary type checks and strings scan;
  - links never followed, size caps, per-file and whole-run time budgets that fail closed;
  - sanitized, deterministic output in Markdown, JSON and SARIF; `--fail-on`; hash-bound baseline with
    mandatory justifications.
- `scripts/fetch_page.py`: raw page fetch with an SSRF guard (public addresses only, checked after DNS
  resolution and on every redirect, connection pinned to the checked address), no cookies or
  credentials, size, time and redirect caps.
- `scripts/canary_pages.py`: benign canary pages across about thirty delivery channels, with a scorer.
- Reference documents: threat model with sources, manual vetting checklist, article vetting method,
  browsing-agent hardening, canary testing guide, report templates.
- Test-suite (standard library `unittest`) with fixed thresholds: benign corpus 0 HIGH, evasion corpus
  100% HIGH, 5 MB adversarial inputs inside a 30 s budget.

### Changed after the pre-release red-team review
- Scanner: punctuation-split view (`ig-nore`, `in.struc.tions`); every Unicode format, control and
  blank-glyph character and every combining mark is stripped for matching, and reported when it sits
  inside a word (`uni-invisible-other`, `uni-foreign-mark`); character references for invisible
  characters; tags that span lines or carry long attributes; raw-markup pass for Markdown; blank-line
  runs of any length; more decoders (see above).
- Quote demotion replaced by clause framing (`vetscan/framing.py`): a bare quoted order stays HIGH;
  example and prohibition framing lowers HIGH to MED only without a URL or shell command in the clause.
  Code-behaviour matches in defensive prose (inline code, negated clauses) are one step lower; fenced
  code and un-negated imperatives are not.
- Report header lists every part that was not fully analyzed (`scan complete: yes/NO`, `incomplete_reasons`)
  and every baseline that suppresses findings; baseline justifications need 30 characters and 4 words.
- `fetch_page.py`: hard wall-clock deadline (`--deadline`), percent-encoded / IDNA URLs, correct
  numeric-host rule, validated header tokens only in the JSON, explicit deny lists including cloud
  metadata addresses, honest integrity reporting (exit code 4), `--out` must be new or empty, https -> http
  redirects refused, no tracebacks.
- `canary_pages.py`: pages served from `site/` under neutral names, channel mapping kept outside it;
  case-insensitive scoring; clean errors.
- `--kind page` for content an agent will read (visible override wording is HIGH); `article` unchanged.
  `tools/measure_injecagent.py` and a "Measured results" section in the README.
- base85 / Ascii85 / Z85 are decoded in parsed HTML streams (entity-escaped, glued to tags) and in
  entity-escaped Markdown; CSS escapes such as `\"` are resolved.
- Docs: targets are acquired outside every project; single-quoted URLs with `--`; corrected install
  commands and CI claims; `.gitattributes` keeps LF line endings.
