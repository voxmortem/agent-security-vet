# Threat model

What this skill defends, against whom, and where its knowledge comes from. Every source listed at the
end was retrieved while this file was written; evidence class is given for each.

## The core problem

A language model cannot reliably tell instructions from data once both are in its context. Anything an
agent reads (a web page, a file, a tool result, a tool description) can therefore try to steer it.
OWASP calls this prompt injection and separates the *direct* form (the user's own prompt) from the
*indirect* form (text arriving from external sources) [S1]. The indirect form was named and
demonstrated on real products in 2023 [S3].

Vendors describe the problem as reduced, not solved. Anthropic's own write-up on browser use says that
no browser agent is immune and that even an attack success rate near one percent is meaningful risk
[S9] (vendor-reported figures). Plan for the model sometimes obeying hostile text.

## The lethal trifecta

Data theft through an agent needs three things at the same time [S2]:

1. access to private data,
2. exposure to untrusted content,
3. a way to communicate externally.

Meta's "Rule of Two" states the same constraint as a design rule: in one session an agent should hold
at most two of {untrustworthy inputs, access to sensitive systems or private data, ability to change
state or communicate externally} unless a human approves [S10]. Research systems such as CaMeL try to
enforce the separation by construction rather than by model obedience [S11].

Mode C of this skill is a trifecta inventory: list which tools give which ingredient, then break up
the combinations.

## Attack classes and what this skill does about each

| Class | How it works | Where it hides | Scanner coverage |
|---|---|---|---|
| Indirect prompt injection in pages and documents | text aimed at the reading model | visible prose, HTML comments, CSS-hidden elements, attributes, metadata, JSON data blocks, SVG, link titles | phrase rules per visibility context; hidden occurrences are HIGH |
| Invisible text | Unicode Tags block characters mirror ASCII and render as nothing [S5][S6] | anywhere, including file names | decoded and shown; HIGH |
| Byte smuggling in variation selectors | one variation selector per byte after a visible character [S12] | after emoji or letters | decoded when printable; HIGH |
| Bidirectional controls ("Trojan Source") | displayed order differs from logical order; CVE-2021-42574, look-alike letters CVE-2021-42694 [S4] | source code, config, names | HIGH for overrides; mixed-script words listed [S7] |
| Obfuscated wording | zero-width, format and blank-glyph splits, punctuation inside words, tags that span lines, look-alike letters, fullwidth forms, letter spacing, digit-for-letter, ROT13, reversed text | anywhere | normalized views; a match that exists only after normalization is HIGH |
| Encoded payloads | base64, base32, base85 / Ascii85 / Z85, hex (also byte-separated), quoted-printable, binary digits, percent-encoding, character references, escapes, UTF-7, compressed blobs | docs and code | bounded decode-and-rescan, four layers deep; anything left undecoded is listed as incomplete |
| Tool poisoning | instructions inside an MCP tool description, unseen by the user, read by the model [S13] | server source, tool manifests | tool-description stream, strict severity for `--kind mcp` |
| Rug pull | a server or remote file changes after approval [S13][S14] | unpinned packages, remote MCP servers, "retrieve the latest rules from a URL" wording | unpinned package and remote-server findings; remote-instruction rule |
| Exfiltration by rendering | the model is talked into emitting an image or link whose URL carries data; the client loads it [S8] | pages, docs | beacon-shaped image URLs; placeholder syntax in URLs is HIGH |
| Supply chain: code that runs on install or load | lifecycle scripts, build hooks, load-time shell commands in skills, hooks, monitors, startup files, MCP server start commands run without consent [S17] | manifests, frontmatter, settings | structure-aware checks per file type |
| Project files as an attack on the agent itself | a repository's agent settings run hooks, auto-enable MCP servers or redirect API traffic when the folder is opened; CVE-2025-59536, CVE-2026-21852 [S15]; a previously approved MCP entry silently changed, CVE-2025-54136 [S16]; nested instruction files and skills in subfolders are picked up as the agent works there [S18] | `.claude/settings*.json`, `.mcp.json`, other agents' config, auto-loaded instruction files | settings and MCP analyzers; auto-loaded files scanned as instructions |
| Classic malware behaviour | download-and-run, encoded shell, credential stores, persistence, destructive commands | scripts, docs that tell the agent to run commands | code-behaviour rules and same-file correlations |
| Archive and filesystem tricks | path traversal on extraction, links out of the tree, compiled bytecode shadowing source, deceptive names | archives, the directory tree | archives are listed, never extracted; links are reported, never followed |

## Trust boundaries used by the scanner

- **Instruction files** (what an agent loads as guidance: `SKILL.md`, skill reference docs, commands,
  agent definitions, `CLAUDE.md`, `AGENTS.md`, `GEMINI.md`, editor rule files): visible instruction-override
  wording here is HIGH, because the file *is* the instruction channel [S18]. The same words are MED
  when their own clause names an attack ("attackers write", "payloads such as", an example block
  introduced that way) or a prohibition governs them, unless the sentence also carries a URL, a shell
  command, an action on a sensitive object or compliance wording. Weak cues ("such as", "for example",
  "the user asks you to") lower nothing, because attackers write them too. A bare quoted order stays
  HIGH, and you check every MED by reading.
- **Saved pages and articles**: visible wording is MED under `--kind article` and HIGH under
  `--kind page` (content an agent will read); anything a reader would not see is HIGH when it carries
  instruction wording or orders to the reader, MED otherwise.
- **Anything aimed at the reviewer** ("already vetted", requests to leave files unread or to approve):
  HIGH.
- **Other documentation and code**: MED or LOW when visible, HIGH when hidden or decoded.
- **Tool descriptions**: treated like instruction files.

## What the scanner cannot see

- Meaning. A politely worded, novel instruction with none of the known shapes passes. You must read.
- Logic bugs and intentional backdoors written as ordinary code.
- Text inside images, audio, video or encrypted archives; PDF text drawn with font glyph codes and
  encrypted PDFs (both reported as an incomplete scan).
- Anything retrieved or generated at run time: remote MCP tool lists, scripts downloaded later, pages
  that serve different content to different clients.
- Encodings and languages outside its lists (English and Russian phrase sets; a curated look-alike table,
  not the full Unicode confusables data [S7]).
- Whether the publisher is who they claim to be.

A scan result is an input to the review, never the review.

## Sources

Evidence classes: **standard** (standards body or community standard), **paper** (preprint or
peer-reviewed), **vendor** (first-party vendor statement; numbers are vendor-reported),
**researcher** (independent write-up; author claim unless it cites a CVE).

- [S1] standard - OWASP Gen AI Security Project, "LLM01:2025 Prompt Injection".
  https://genai.owasp.org/llmrisk/llm01-prompt-injection/
- [S2] researcher - Simon Willison, "The lethal trifecta for AI agents: private data, untrusted content,
  and external communication", 16 June 2025. https://simonwillison.net/2025/Jun/16/the-lethal-trifecta/
- [S3] paper - Greshake, Abdelnabi, Mishra, Endres, Holz, Fritz, "Not what you've signed up for:
  Compromising Real-World LLM-Integrated Applications with Indirect Prompt Injection", arXiv:2302.12173
  (2023). https://arxiv.org/abs/2302.12173
- [S4] paper - Boucher and Anderson, "Trojan Source: Invisible Vulnerabilities", arXiv:2111.00169 (2021),
  https://arxiv.org/abs/2111.00169 ; project page listing CVE-2021-42574 and CVE-2021-42694:
  https://trojansource.codes/
- [S5] researcher - Johann Rehberger, "ASCII Smuggler Tool: Crafting Invisible Text and Decoding Hidden
  Codes", 14 January 2024.
  https://embracethered.com/blog/posts/2024/hiding-and-finding-text-with-unicode-tags/
- [S6] standard - Unicode Technical Standard #51, "Unicode Emoji" (defines emoji tag sequences: tag
  characters U+E0020..U+E007E ended by U+E007F). https://www.unicode.org/reports/tr51/
- [S7] standard - Unicode Technical Standard #39, "Unicode Security Mechanisms" (confusables, mixed-script
  detection). https://www.unicode.org/reports/tr39/
- [S8] researcher - Johann Rehberger, "Anthropic Claude Data Exfiltration Vulnerability Fixed",
  1 August 2023 (image-markdown exfiltration).
  https://embracethered.com/blog/posts/2023/anthropic-fixes-claude-data-exfiltration-via-images/
- [S9] vendor - Anthropic, "Mitigating the risk of prompt injections in browser use", 24 November 2025.
  https://www.anthropic.com/research/prompt-injection-defenses
- [S10] vendor - Meta AI, "Agents Rule of Two: A Practical Approach to AI Agent Security",
  31 October 2025. https://ai.meta.com/blog/practical-ai-agent-security/
- [S11] paper - Debenedetti et al., "Defeating Prompt Injections by Design" (CaMeL), arXiv:2503.18813
  (2025). https://arxiv.org/abs/2503.18813
- [S12] researcher - Paul Butler, "Smuggling arbitrary data through an emoji", 8 February 2025.
  https://paulbutler.org/2025/smuggling-arbitrary-data-through-an-emoji/
- [S13] researcher - Invariant Labs, "MCP Security Notification: Tool Poisoning Attacks", 1 April 2025.
  https://invariantlabs.ai/blog/mcp-security-notification-tool-poisoning-attacks
- [S14] researcher - Simon Willison, "Model Context Protocol has prompt injection security problems",
  9 April 2025. https://simonwillison.net/2025/Apr/9/mcp-prompt-injection/
- [S15] researcher - Check Point Research, "Caught in the Hook: RCE and API Token Exfiltration Through
  Claude Code Project Files", 25 February 2026 (CVE-2025-59536, CVE-2026-21852; reported as patched).
  https://research.checkpoint.com/2026/rce-and-api-token-exfiltration-through-claude-code-project-files-cve-2025-59536/
- [S16] researcher - Check Point Research, "MCPoison Cursor IDE: Persistent Code Execution via MCP Trust
  Bypass", 5 August 2025 (CVE-2025-54136). https://research.checkpoint.com/2025/cursor-vulnerability-mcpoison/
- [S17] standard - Model Context Protocol, "Security Best Practices" (local server compromise, consent
  before running start-up commands, SSRF, URL scheme validation).
  https://modelcontextprotocol.io/docs/tutorials/security/security_best_practices
- [S18] vendor - Claude Code documentation, "Security", "Skills" and "How Claude remembers your project"
  (subdirectory `CLAUDE.md`, `AGENTS.md` and `.claude/rules` load on demand; skills in a nested
  `.claude/skills` load the first time a file in that subdirectory is read or edited).
  https://code.claude.com/docs/en/security , https://code.claude.com/docs/en/skills ,
  https://code.claude.com/docs/en/memory
