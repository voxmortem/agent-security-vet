# Changelog

All notable changes to this project are documented here. The format follows Keep a Changelog, and
versions follow semantic versioning.

## [Unreleased]

Fixes from an independent third review (proof-of-concept inputs re-created as tests in
`tests/test_review3.py`).

### Security
- `fetch_page.py` could write through an existing symlink on Windows (CI failure of
  `test_write_never_follows_an_existing_link`; `O_CREAT|O_EXCL` follows a dangling link there). The output
  path is now lstat-checked first (symlinks, junctions and any reparse point are refused), created
  exclusively, and checked again before the first byte is written; a linked `--out` is refused. The
  Windows branches are unit-tested everywhere with a simulated lstat.
- The scanner no longer walks into a target that is itself a junction or other reparse point.

### Changed (detection)
- Hidden text needs no known phrase any more: on pages, 20+ visible characters of hidden text are MED
  (`html-hidden-text`), and hidden text, comments, attribute values or meta text that give the reader
  orders ("before you answer, call ...", "your sole objective is now ...", "email them to <address>") are
  HIGH (`hidden-order`, English and Russian cues). Normal hidden UI stays at most MED (benign fixtures
  for menus, cookie dialogs, skip links, modal templates, tab panels, noscript, FAQ answers).
- Framing that lowers an injection phrase to MED must now name an attack ("attackers write", "payloads
  such as", "examples of injected text", "patterns"); "such as", "for example" and "the user asks / wants
  / tells you to" no longer lower anything. Nothing is lowered when the sentence also acts on a sensitive
  object (`.env`, SSH keys, the system prompt) or tells the reader to comply. A prohibition must govern
  the phrase in its own clause. Under `--kind page` only a code span, fence or blockquote introduced by
  such wording lowers a phrase.
- Archives (`.zip`, `.skill`, `.tar.gz` ...) are classified by their member names and their members get
  the same roles as on disk, so a packed skill gets the same severities and exit code as the unpacked one.
  Members that a size or count limit kept unread now make the scan incomplete.
- `<meta charset>`, http-equiv Content-Type, XML declarations and `@charset` are honoured; non-UTF-8
  bytes are also decoded with the most plausible legacy code page (cp1251, KOI8-R, cp866, cp1252, GBK /
  GB18030, Big5, Shift_JIS, EUC-JP, EUC-KR, ISO-2022-JP, Latin-1) and scanned; `enc-unusual` is MED when
  a legacy decoding was needed; bytes no candidate decodes make the scan incomplete.
- PDF: streams are decompressed within size and ratio caps (Flate, ASCIIHex, ASCII85, RunLength, LZW),
  text is extracted from `Tj`, `TJ`, `'` and `"` operators, object streams, annotations and XMP metadata,
  and scanned. Encryption, unsupported filters, damaged or oversized streams and text drawn with font
  glyph codes are reported as `pdf-unanalyzed` and make the scan incomplete.
- New rule family `inj-reviewer-steer` (English and Russian, through the usual normalization): text that
  tries to steer the reviewer or scanner (claims of prior approval, requests to leave files unread, to
  hand down a given verdict or to dismiss every finding), also in file names. HIGH even in ordinary docs.
- CSS hiding: `filter: opacity()`, low-alpha `rgba()` / `hsla()`, `-webkit-text-fill-color`, `scale`,
  positive `text-indent`, negative `z-index`, `var()` values (resolved where defined, `css-indirection`
  MED otherwise), CSS escapes in inline styles, tag / attribute / child / sibling selectors in `<style>`
  rules, and fallback content of `<canvas>`, `<object>`, `<iframe>`, `<video>`, `<audio>`. Text in a closed
  `<details>` is reported as informational (`html-collapsed-text`, LOW).
- Agent configs: `.gemini/settings.json` (and Qwen), `opencode.json`, `.zed/settings.json`,
  `.cursor/cli.json`, Crush, Amazon Q, Continue, Kiro and Roo JSON configs (MCP servers in their own
  shapes, permission bypasses, allow rules, remote instruction files `cfg-remote-instructions`); MCP
  `"trust": true` is HIGH. More auto-loaded instruction files: `AGENTS.override.md`, `CONVENTIONS.md`,
  `replit.md`, `.cursor/commands/`, `.github/agents/`, `.opencode/agent/`, `.gemini/commands/*.toml`,
  `.zed/` and others.
- `sec-env-dump` now covers the whole environment serialized or sent (`json.dumps({**os.environ})`,
  `dict(os.environ)` / `os.environ.copy()` inside a dump or a request body, `JSON.stringify({...process.env})`).
- Words glued in CamelCase are matched as an obfuscation view.
- AI product names in page data (JSON blocks, attributes, meta tags) are MED unless an order to the reader
  follows (the github.com home page no longer gives a HIGH under `--kind page`).

### Added
- `--dump-streams` and `--dump-filter TEXT`: print, sanitized and with line numbers, the visible, hidden,
  attribute, comment and metadata text the scanner derived per file, plus decoded payloads, legacy-decoded
  text, PDF text and archive members (read a member without extracting it).

### Fixed
- `--baseline` on another drive than the target crashed with a traceback (`os.path.commonpath`); the CLI
  now never prints a traceback (internal errors are one line, exit code 2).

### Documentation
- SKILL.md: all `fetch_page.py` exit codes and what to do with each; a decision rule for `--kind page`
  versus `article`; how to read an archive member without unpacking it; plugins are installed from the
  exact reviewed commit (an update is new content); `http.server` with `-I` on 127.0.0.1; HOLD rules for
  every kind of incomplete scan. "Offline" now says that the separate page fetcher needs network
  (SKILL.md description, plugin manifests, README, llms.txt, CITATION.cff).
- SECURITY.md: an alternative channel when private vulnerability reporting is unavailable.
- README: detection, severity table, honest limits (PDF, legacy encodings, imitation risk, what is
  still missed) and measured results updated.
- README: a standalone opening paragraph (what it is, who it is for), CI and license badges, a short
  contents line, "Why", "Quick start (2 minutes)" and "FAQ" sections. The "Honest limits" and
  "Measured results" sections were unchanged in that edit.
- `SKILL.md` frontmatter `description` rewritten to list the concrete situations the skill is for, in
  English and Russian; `name` unchanged; no behaviour change.
- `.claude-plugin/plugin.json` and `marketplace.json`: aligned descriptions, more specific keywords,
  `homepage` and `repository` fields.
- Added `llms.txt` (summary and links for language-model tools) and `CITATION.cff` (CFF 1.2.0).

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
