"""Scan engine: walks the target without following links, classifies each file,
runs every analyzer and applies the severity policy.

Severity policy for instruction-like text ("phrases"):
  hidden / decoded / obfuscated occurrence ........ HIGH
  visible in a file an agent loads as instructions . HIGH (strong rules) / MED (weak rules)
  visible in a saved article or page ............... MED  (may be a quoted example: read in context)
  visible in other docs or code .................... MED / LOW
"""
import hashlib
import html as _html
import ipaddress
import os
import re
import stat
import time
import unicodedata
from urllib.parse import parse_qsl, urlsplit

from . import archives, coderules, configs, decoders, framing, invisible, markup, phrases
from . import textutil as T
from .model import RULES, SEV_RANK, Finding, lower, rule

rule("fs-symlink", "filesystem", "symbolic link or junction (never followed)")
rule("fs-special-file", "filesystem", "device, FIFO or socket (never opened)")
rule("fs-name-trick", "filesystem", "deceptive file name")
rule("fs-vendored-dir", "filesystem", "vendored dependency directory was not scanned")
rule("plugin-bin", "plugin", "plugin ships executables that are added to the shell PATH")
rule("scan-incomplete", "scan", "scan did not cover everything (limit or time budget reached)")
rule("scan-truncated", "scan", "file larger than the size cap: only head and tail were scanned")
rule("enc-unusual", "scan", "unusual text encoding")
rule("bin-executable", "binary", "compiled / native executable that cannot be reviewed as text")
rule("bin-nontext", "binary", "non-text file that cannot be inspected")
rule("bin-type-mismatch", "binary", "file content does not match its extension")
rule("bin-pickle", "binary", "serialized object file whose loading can execute code")
rule("bin-pdf-active", "binary", "PDF with active content markers")
rule("obf-blob", "obfuscation", "long opaque encoded blob")
rule("obf-embedded-binary", "obfuscation", "base64 blob that decodes to an executable/archive")
rule("obf-minified", "obfuscation", "minified or packed code that cannot be reviewed line by line")
rule("obf-long-line", "obfuscation", "extremely long line in a text/instruction file")
rule("decode-budget", "scan", "too many encoded blobs: some were not decoded")
rule("decode-limit", "scan", "encoded content left undecoded (size or nesting-depth limit)")
rule("match-limit", "scan", "too many matches of one phrase rule: later occurrences were not examined")
rule("html-hidden-text", "hidden", "text inside elements that are not rendered")
rule("html-comment-text", "hidden", "comment text that is invisible when rendered")
rule("html-meta-refresh", "markup", "page redirects itself with meta refresh")
rule("html-base-href", "markup", "base href rewrites every relative link")
rule("html-zero-size", "markup", "zero-size or hidden image/frame (tracking or beacon element)")
rule("html-parse-abort", "scan", "markup tokenizer stopped early; remaining text scanned as raw source only")
rule("link-text-mismatch", "markup", "link text shows one host but the link goes to another")
rule("uri-script-scheme", "markup", "javascript:/vbscript: link")
rule("uri-data-scheme", "markup", "data: URI carrying active content")
rule("uri-file-scheme", "markup", "file: URI")
rule("url-userinfo", "network", "URL with user-info part (real host differs from what is displayed)")
rule("url-raw-ip", "network", "URL with a raw public IP address")
rule("url-obfuscated-ip", "network", "URL with an integer / hex / octal encoded IP address")
rule("url-idn-host", "network", "internationalized or punycode host name (look-alike domain risk)")
rule("url-shortener", "network", "URL shortener hides the destination")
rule("beacon-url", "network", "image/frame URL shaped to carry data out when rendered")
rule("corr-secrets-network", "correlation", "same file touches secrets and uses the network")
rule("corr-secret-env-network", "correlation", "same file reads a secret-bearing source and uses the network")
rule("corr-decode-exec", "correlation", "same file decodes data and executes code")

PER_RULE_PER_FILE = 4
MAX_MENTIONS = 2000      # lowered code-rule mentions per rule and file that do not use up the match limit
MAX_DECODE_DEPTH = 4     # nested encoding layers decoded (base64 of base64 of ...)
SKIP_DIRS = frozenset(("node_modules", ".venv", "venv", "site-packages", ".tox", ".mypy_cache", ".ruff_cache",
                       ".pytest_cache", "bower_components", ".gradle", ".terraform"))
MD_EXT = frozenset((".md", ".markdown", ".mdx", ".mdc", ".mdown", ".mkd"))
PROSE_EXT = MD_EXT | frozenset((".txt", ".rst", ".adoc", ".org", ".text"))
HTML_EXT = frozenset((".html", ".htm", ".xhtml", ".svg", ".xml", ".rss", ".atom", ".mhtml", ".xsl", ".xslt"))
CODE_EXT = frozenset(
    ".py .pyw .js .mjs .cjs .ts .mts .cts .tsx .jsx .sh .bash .zsh .fish .ps1 .psm1 .psd1 .bat .cmd .vbs .vbe "
    ".wsf .rb .pl .pm .php .go .rs .java .kt .kts .cs .c .cc .cpp .h .hpp .lua .swift .scala .r .jl .ex .exs "
    ".clj .groovy .gradle .mk .cmake .awk .sed .tcl .nim .zig .dart .sql .applescript .scpt .vue .svelte "
    ".erb .ejs .hbs .pug .command .tf .nix .el .vim".split())
CONFIG_EXT = frozenset(".json .jsonc .json5 .yaml .yml .toml .ini .cfg .conf .env .properties .plist .pth "
                       ".lock .editorconfig .service .timer".split())
CODE_NAMES = frozenset(("makefile", "gnumakefile", "dockerfile", "containerfile", "justfile", "rakefile",
                        "gemfile", "vagrantfile", "procfile", "brewfile", "taskfile", "jenkinsfile"))
GENERATED_NAMES = frozenset(("package-lock.json", "yarn.lock", "pnpm-lock.yaml", "uv.lock", "poetry.lock",
                             "cargo.lock", "go.sum", "composer.lock", "gemfile.lock", "bun.lock", "flake.lock",
                             "pipfile.lock", "npm-shrinkwrap.json", ".gitignore", ".dockerignore",
                             ".npmignore", ".eslintignore", ".prettierignore", ".gitattributes", ".gitkeep"))
GENERATED_SUFFIX = (".min.js", ".min.css", ".min.mjs", ".map", ".bundle.js")
AUTOLOAD_NAMES = frozenset(("claude.md", "claude.local.md", "agents.md", "agent.md", "gemini.md", ".cursorrules",
                            ".windsurfrules", ".clinerules", "copilot-instructions.md", ".goosehints", "llms.txt",
                            "llms-full.txt", "warp.md", "crush.md", "qwen.md", ".rules"))
AUTOLOAD_PATH_RX = re.compile(
    r"(?:^|/)(?:\.cursor/rules/|\.windsurf/rules/|\.github/instructions/|\.github/prompts/|\.github/chatmodes/|"
    r"\.claude/(?:commands|agents|rules|skills|output-styles)/|\.clinerules/|\.roo/rules[^/]{0,30}/|"
    r"\.kiro/steering/|\.amazonq/rules/|\.continue/rules/|\.augment/rules/|\.trae/rules/|"
    r"\.openhands/microagents/|\.agents?/|\.codex/|\.gemini/)[^\n]{1,300}\.(?:md|mdc|txt)$|"
    r"(?:^|/)\.junie/guidelines\.md$")
PLUGIN_COMPONENT_RX = re.compile(r"(?:^|/)(?:commands|agents|output-styles|workflows)/[^\n]{1,300}\.md$")
DOC_NAME_RX = re.compile(
    r"^(?:readme|changelog|changes|history|license|licence|copying|notice|contributing|security|code_of_conduct|"
    r"authors|maintainers|third[_-]party[\w-]{0,30}|news|roadmap|sources)(?:[._-][\w.-]{0,60})?$")
COMMON_COMMANDS = frozenset(
    "git gh npm npx node python python3 pip pip3 uv uvx curl wget ssh scp sudo su ls cat cp mv rm sh bash zsh "
    "pwsh powershell docker kubectl make cargo go java claude code open start echo env which sed awk grep find "
    "tar unzip chmod chown".split())
WIN_RESERVED = re.compile(r"(?i)^(?:con|prn|aux|nul|com[1-9]|lpt[1-9])(?:\.|$)")
EXEC_FINAL_EXT = frozenset(".exe .scr .com .bat .cmd .ps1 .vbs .js .jse .wsf .hta .lnk .msi .jar .sh .app".split())
DECOY_EXT = frozenset(".md .txt .pdf .doc .docx .png .jpg .jpeg .gif .html .json .csv .xlsx".split())
SHORTENERS = frozenset(("bit.ly", "t.co", "tinyurl.com", "goo.gl", "ow.ly", "is.gd", "buff.ly", "rebrand.ly",
                        "cutt.ly", "shorturl.at", "t.ly", "rb.gy", "tiny.cc", "lnkd.in", "s.id", "v.gd", "git.io"))
BENIGN_IMG_HOSTS = ("shields.io", "badgen.net", "github.com", "githubusercontent.com", "githubassets.com",
                    "travis-ci.org", "travis-ci.com", "codecov.io", "coveralls.io", "fury.io", "circleci.com",
                    "gitlab.com", "npmjs.com", "pypi.org", "readthedocs.org", "readthedocs.io", "wikimedia.org",
                    "wikipedia.org", "gravatar.com", "youtube.com", "ytimg.com", "codacy.com", "snyk.io",
                    "sonarcloud.io", "opencollective.com", "contrib.rocks", "star-history.com", "netlify.com",
                    "vercel.com", "herokucdn.com", "appveyor.com", "azure.com", "packagist.org", "crates.io",
                    "docs.rs", "pkg.go.dev", "bestpractices.dev", "securityscorecards.dev", "gitpod.io")
BEACON_PARAM = frozenset(("data", "payload", "secret", "token", "exfil", "leak", "env", "chat", "history", "prompt",
                          "cookie", "session", "b64", "base64", "dump", "content", "conversation", "context",
                          "msg", "message", "canary", "key", "keys", "password", "creds", "credentials"))
_TEMPLATE_RX = re.compile(
    r"(?i)\{\{?[\w .|-]{1,60}\}?\}|\$\{[\w.]{1,60}\}|\$\([^)]{1,60}\)|%7b|<[a-z_ -]{2,40}>|"
    r"\[(?:data|secret|token|key|content|payload|conversation|history|prompt|input|text|here)[\w -]{0,30}\]")
_URL_RX = re.compile(r"(?i)\b(?:https?|wss?|ftp)://[^\s<>\"'`)\]}\\]{3,600}")
_OBF_IP_RX = re.compile(r"(?i)^(?:0x[0-9a-f]{1,8}|\d{8,10}|0\d{1,11}|(?:(?:0x[0-9a-f]{1,2}|0\d{1,3}|\d{1,3})\.){1,3}"
                        r"(?:0x[0-9a-f]{1,8}|0\d{1,10}))$")
_HOSTLIKE_RX = re.compile(r"(?i)^(?:https?://)?((?:[a-z0-9-]{1,63}\.){1,6}[a-z]{2,24})(?:[/:?#][^\s]{0,300})?$")
_HTML_SNIFF = re.compile(r"(?i)<!doctype html|<html[\s>]|<head[\s>]|<body[\s>]|<svg[\s>]|<\?xml\s")
_HAS_TAG = re.compile(r"<[A-Za-z][A-Za-z0-9-]{0,30}[\s>/]")
_SRCMAP_RX = re.compile(r"(?i)sourcemappingurl=data:application/json[^,]{0,40},$")
_ASCII_STR = re.compile(rb"[\x20-\x7e]{12,}")
_PDF_ACTIVE = re.compile(rb"(/JavaScript|/JS|/OpenAction|/Launch|/EmbeddedFile)(?![A-Za-z])")
FILE_EXT_LABELS = frozenset(
    "js mjs cjs ts tsx jsx py rb go rs sh ps1 md txt json yml yaml toml html htm css scss xml csv pdf png jpg "
    "jpeg gif svg zip gz tar exe dll so php java kt cs cpp cc c h hpp lock cfg ini conf log sql vue".split())
_QUOTE_OPEN = "\"'`(" + "".join(chr(c) for c in (0x201C, 0x2018, 0x00AB, 0x201E))
_QUOTE_CLOSE = "\"'`" + "".join(chr(c) for c in (0x201D, 0x2019, 0x00BB, 0x201C))
_UTF16_STR = re.compile(rb"(?:[\x20-\x7e]\x00){12,}")
_ENTITY_REF_RX = re.compile(r"&(?:lt|gt|amp|quot|apos|#[0-9]{2,7}|#[xX][0-9a-fA-F]{2,6});")
# Phrase excerpts come from a lower-cased view in which a key's dashes became spaces, so the regular
# secret masking cannot recognise it: mask every long token that mixes letters and digits.
_VIEW_TOKEN_RX = re.compile(r"(?<![a-z0-9])(?=[a-z]{0,200}[0-9])(?=[0-9]{0,200}[a-z])[a-z0-9]{20,200}(?![a-z0-9])")


def _mask_view_token(m):
    return m.group(0)[:4] + "...[masked %d chars]" % len(m.group(0))

STREAM_LABEL = {
    "comment": "HTML comment", "hidden": "hidden element", "attr": "attribute value", "meta": "meta tag",
    "jsonld": "JSON data block", "script": "inline script", "style": "stylesheet", "svg": "SVG text",
    "md-hidden": "markdown link title / comment definition", "raw": "raw markup (tag or attribute names, "
    "unparsed region)", "tool-description": "tool description",
}
MIRROR_STREAMS = ("meta", "jsonld", "script")
MAGIC = (
    (b"MZ", "exe", "Windows executable"), (b"\x7fELF", "exe", "ELF executable"),
    (b"\xfe\xed\xfa\xce", "exe", "Mach-O"), (b"\xfe\xed\xfa\xcf", "exe", "Mach-O"),
    (b"\xcf\xfa\xed\xfe", "exe", "Mach-O"), (b"\xce\xfa\xed\xfe", "exe", "Mach-O"),
    (b"\xca\xfe\xba\xbe", "exe", "Java class / fat Mach-O"), (b"\x00asm", "exe", "WebAssembly module"),
    (b"dex\n", "exe", "Android DEX"), (b"L\x00\x00\x00\x01\x14\x02\x00", "exe", "Windows shortcut"),
    (b"\xd0\xcf\x11\xe0", "ole", "OLE compound file (MSI / legacy Office)"),
    (b"\x89PNG", "media", "PNG"), (b"\xff\xd8\xff", "media", "JPEG"), (b"GIF8", "media", "GIF"),
    (b"RIFF", "media", "RIFF"), (b"BM", "media", "BMP"), (b"\x00\x00\x01\x00", "media", "ICO"),
    (b"%PDF", "pdf", "PDF"), (b"wOFF", "media", "WOFF"), (b"wOF2", "media", "WOFF2"),
    (b"\x00\x01\x00\x00", "media", "TrueType"), (b"OTTO", "media", "OpenType"), (b"ID3", "media", "MP3"),
    (b"OggS", "media", "Ogg"), (b"fLaC", "media", "FLAC"), (b"SQLite format 3", "data", "SQLite database"),
    (b"\x1aE\xdf\xa3", "media", "Matroska/WebM"),
)
MEDIA_EXT = frozenset(".png .jpg .jpeg .gif .webp .bmp .ico .pdf .woff .woff2 .ttf .otf .mp3 .mp4 .ogg .wav "
                      ".flac .webm .mov .avi .svgz .icns .eot .tiff .tif .heic .avif .psd".split())
PICKLE_EXT = frozenset(".pkl .pickle .joblib .pt .ckpt .npy .npz".split())


_LOCAL_NETS = tuple(ipaddress.ip_network(n) for n in ("10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16",
                                                       "fc00::/7"))


class Budget:
    def __init__(self, seconds):
        self.deadline = time.monotonic() + seconds

    def expired(self):
        return time.monotonic() > self.deadline


class Options:
    def __init__(self, kind="auto", max_bytes=8_000_000, max_files=20_000, file_budget=20.0, total_budget=600.0,
                 scan_archives=True, include_vendored=False):
        self.kind = kind
        self.max_bytes = max_bytes
        self.max_files = max_files
        self.file_budget = file_budget
        self.total_budget = total_budget
        self.scan_archives = scan_archives
        self.include_vendored = include_vendored


class FileCtx:
    __slots__ = ("rel", "rel_lower", "name", "ext", "parent_name", "role", "sha256", "size", "autoload",
                 "is_md_like", "is_html", "single_file", "tags", "in_archive")

    def __init__(self, rel, size=0, single_file=False):
        self.rel = rel
        self.rel_lower = rel.lower()
        base = self.rel_lower.rsplit("/", 1)[-1]
        if "!/" in base:
            base = base.rsplit("!/", 1)[-1]
        self.name = base
        self.ext = "." + base.rsplit(".", 1)[-1] if "." in base[1:] else ""
        parts = rel.replace("!/", "/").split("/")
        self.parent_name = parts[-2] if len(parts) >= 2 else ""
        self.role = "other"
        self.sha256 = ""
        self.size = size
        self.autoload = False
        self.is_md_like = False
        self.is_html = False
        self.single_file = single_file
        self.tags = {}
        self.in_archive = False


def auto_kind(path):
    """Guess what the target is: skill | mcp | repo | article."""
    if os.path.isfile(path):
        name = os.path.basename(path).lower()
        ext = os.path.splitext(name)[1]
        if name == "skill.md":
            return "skill"
        if name in AUTOLOAD_NAMES:
            return "repo"
        if name in (".mcp.json", "mcp.json", "claude_desktop_config.json"):
            return "mcp"
        if ext in HTML_EXT or ext in PROSE_EXT or ext == ".pdf":
            return "article"
        return "repo"
    try:
        entries = {e.name.lower(): e for e in os.scandir(path)}
    except OSError:
        return "repo"
    if "skill.md" in entries or ".claude-plugin" in entries:
        return "skill"
    if ".mcp.json" in entries or "server.json" in entries or "mcp.json" in entries:
        return "mcp"
    for manifest, needles in (("package.json", ("@modelcontextprotocol/sdk", "fastmcp")),
                              ("pyproject.toml", ("\"mcp", "'mcp", "fastmcp", "mcp[")),
                              ("requirements.txt", ("mcp", "fastmcp"))):
        e = entries.get(manifest)
        if e is not None and e.is_file(follow_symlinks=False):
            try:
                with open(e.path, "rb") as fh:
                    head = fh.read(200_000).decode("utf-8", "replace").lower()
            except OSError:
                head = ""
            if manifest == "requirements.txt":
                if re.search(r"(?m)^(?:mcp|fastmcp)\b", head):
                    return "mcp"
            elif any(n in head for n in needles):
                return "mcp"
    # A flat folder of saved pages / documents (what fetch_page.py produces) is an article.
    names = [n for n, e in entries.items() if not n.startswith(".")]
    if names and all(os.path.splitext(n)[1] in (HTML_EXT | PROSE_EXT | {".json", ".bin", ".pdf"}) for n in names) \
            and not any(e.is_dir(follow_symlinks=False) for e in entries.values()) \
            and not any(n in AUTOLOAD_NAMES for n in entries) \
            and any(os.path.splitext(n)[1] in (HTML_EXT | PROSE_EXT | {".bin", ".pdf"}) for n in names):
        return "article"
    return "repo"


class FileScope:
    """Narrow interface handed to configs.analyze for one file."""

    def __init__(self, scan, fc):
        self._s = scan
        self._fc = fc
        self.streams = []

    def add(self, sev, rid, line, snippet, note):
        self._s.add(sev, rid, self._fc, line, snippet, note)

    def repeat(self, rid, n):
        key = (rid, self._fc.rel)
        self._s.repeats[key] = self._s.repeats.get(key, 0) + n

    def inv(self, text):
        self._s.inv(text)

    def host_of(self, url):
        try:
            return (urlsplit(url).hostname or "").lower()
        except ValueError:
            return ""

    def url(self, url, line, origin):
        self._s.note_url(self._fc, url, line, origin)

    def stream(self, name, text, cls):
        self.streams.append((name, text, cls))


class Scan:
    def __init__(self, opts=None):
        self.opts = opts or Options()
        self.kind = self.opts.kind
        self.findings = []
        self.counts = {}
        self.repeats = {}
        self.inventory = []
        self.hosts = {}
        self.host_flags = {}
        self.skipped = []
        self.stats = {"files": 0, "bytes": 0, "binary": 0, "archives": 0, "dirs": 0, "symlinks": 0}
        self.sha = {}
        self.skill_roots = []
        self.plugin_roots = []
        self.all_in_skill = False
        self.total = None
        self.root_name = ""
        self.incomplete = False
        self._phr = {}
        self._url_seen = set()
        self._limits = {}          # (file, kind) -> count of content left unanalyzed by a limit

    safe = staticmethod(T.sanitize)

    # ------------------------------------------------------------ results

    def add(self, sev, rid, fc, line, snippet, note, context=""):
        rel = fc.rel if isinstance(fc, FileCtx) else str(fc)
        if rid not in RULES:
            rule(rid, "misc", rid)
        key = (rid, rel, sev)
        n = self.counts.get(key, 0) + 1
        self.counts[key] = n
        if n > PER_RULE_PER_FILE:
            rk = (rid, rel)
            self.repeats[rk] = self.repeats.get(rk, 0) + 1
            return
        sha = fc.sha256 if isinstance(fc, FileCtx) else ""
        self.findings.append(Finding(sev, rid, T.sanitize(rel, 260), line, T.sanitize(snippet or "", 220),
                                     T.sanitize(note or "", 460), T.sanitize(context, 120), sha))

    def inv(self, text):
        if len(self.inventory) < 400:
            self.inventory.append(T.sanitize(text, 420))

    # ------------------------------------------------------------ walking

    def run(self, target):
        target = os.path.abspath(target)
        if self.kind == "auto":
            self.kind = auto_kind(target)
        self.total = Budget(self.opts.total_budget)
        self.root_name = os.path.basename(target.rstrip("/" + os.sep))
        if os.path.isfile(target) or os.path.islink(target):
            self.root_name = ""
            st = os.lstat(target)
            self.all_in_skill = self.kind == "skill"
            self._scan_entry(target, os.path.basename(target), st, single=True)
        else:
            try:
                top = {e.name.lower() for e in os.scandir(target)}
            except OSError:
                top = set()
            self.all_in_skill = self.kind == "skill" and ("skill.md" in top or ".claude-plugin" not in top)
            if ".claude-plugin" in top:
                self.plugin_roots.append("")
            self._walk(target)
        self._finish()
        return self

    def _walk(self, root):
        stack = [(root, "")]
        while stack:
            dpath, drel = stack.pop()
            try:
                entries = sorted(os.scandir(dpath), key=lambda e: e.name)
            except OSError as exc:
                self.skipped.append("%s (unreadable directory: %s)" % (T.sanitize(drel or ".", 200),
                                                                      type(exc).__name__))
                continue
            self.stats["dirs"] += 1
            names = {e.name.lower() for e in entries}
            if "skill.md" in names:
                self.skill_roots.append(drel + "/" if drel else "")
            if ".claude-plugin" in names and drel:
                self.plugin_roots.append(drel + "/")
            subdirs = []
            for e in entries:
                rel = (drel + "/" + e.name) if drel else e.name
                if self.total.expired() or self.stats["files"] >= self.opts.max_files:
                    if not self.incomplete:
                        self.incomplete = True
                        why = "time budget" if self.total.expired() else "file-count limit (%d)" % self.opts.max_files
                        self.add("HIGH", "scan-incomplete", rel, 0, "",
                                 "scan stopped at this entry: %s reached. Everything after it is UNSCANNED" % why)
                    return
                self._check_name(rel, e.name)
                try:
                    st = e.stat(follow_symlinks=False)
                    is_link = e.is_symlink() or self._is_reparse(e, st)
                except OSError as exc:
                    self.skipped.append("%s (%s)" % (T.sanitize(rel, 200), type(exc).__name__))
                    continue
                if is_link:
                    self._link(e.path, rel)
                    continue
                if stat.S_ISDIR(st.st_mode):
                    low = e.name.lower()
                    if low == ".git":
                        self._git_dir(e.path, rel)
                    elif low in SKIP_DIRS and not self.opts.include_vendored:
                        self.add("MED", "fs-vendored-dir", rel, 0, "",
                                 "directory not scanned: vendored or generated dependencies are unreviewed code "
                                 "(re-run with --include-vendored to scan it)")
                    else:
                        subdirs.append((e.path, rel))
                    continue
                if not stat.S_ISREG(st.st_mode):
                    self.add("MED", "fs-special-file", rel, 0, "", "not a regular file (device/FIFO/socket): not opened")
                    continue
                self._scan_entry(e.path, rel, st)
            stack.extend(reversed(subdirs))

    @staticmethod
    def _is_reparse(entry, st):
        attrs = getattr(st, "st_file_attributes", 0)
        if attrs & 0x400:      # FILE_ATTRIBUTE_REPARSE_POINT: junctions, mount points, cloud placeholders
            return True
        isj = getattr(entry, "is_junction", None)
        try:
            return bool(isj and isj())
        except OSError:
            return False

    def _link(self, path, rel):
        self.stats["symlinks"] += 1
        try:
            target = os.readlink(path)
        except OSError:
            target = "?"
        t = target.replace("\\", "/")
        escapes = t.startswith(("/", "~", "//?/")) or re.match(r"^[A-Za-z]:", t) or ".." in t.split("/")
        self.add("HIGH" if escapes else "MED", "fs-symlink", rel, 0, "-> " + target,
                 "link was not followed%s" % ("; target is absolute or leaves the scanned tree" if escapes else ""))

    def _check_name(self, rel, name):
        if not name.isascii():
            if T.INVISIBLE_RX.search(name) or any(unicodedata.category(c)[0] == "C" for c in name):
                self.add("HIGH", "fs-name-trick", rel, 0, name,
                         "file name contains invisible, control or bidirectional characters")
            skel = unicodedata.normalize("NFKD", name).translate(T.TO_LATIN).lower()
            if skel != name.lower() and skel.isascii() and (skel in AUTOLOAD_NAMES or skel in (
                    "skill.md", "settings.json", "hooks.json", ".mcp.json", "plugin.json", "package.json")):
                self.add("HIGH", "fs-name-trick", rel, 0, name,
                         "file name imitates %s with look-alike characters" % skel)
        low = name.lower()
        parts = low.split(".")
        if len(parts) >= 3 and "." + parts[-1] in EXEC_FINAL_EXT and "." + parts[-2] in DECOY_EXT:
            self.add("MED", "fs-name-trick", rel, 0, name, "double extension hides an executable/script type")
        if name != name.rstrip(". ") or WIN_RESERVED.match(low) or name.startswith("-"):
            self.add("MED", "fs-name-trick", rel, 0, name,
                     "name is a reserved device name, starts with '-' or ends with dot/space")

    def _git_dir(self, path, rel):
        """A copied .git can execute commands through config and hooks; inspect only those."""
        cfg = os.path.join(path, "config")
        try:
            if os.path.isfile(cfg) and not os.path.islink(cfg) and os.path.getsize(cfg) <= 1_000_000:
                with open(cfg, "rb") as fh:
                    data = fh.read()
                fc = FileCtx(rel + "/config", len(data))
                fc.role = "config"
                fc.sha256 = hashlib.sha256(data).hexdigest()
                text = T.normalize_eol(T.decode_bytes(data)[0])
                configs.scan_git_config(FileScope(self, fc), text)
        except OSError:
            pass
        hooks = os.path.join(path, "hooks")
        try:
            live = sorted(e.name for e in os.scandir(hooks) if not e.name.endswith(".sample"))
        except OSError:
            live = []
        if live:
            self.add("HIGH", "repo-git-hook", rel + "/hooks", 0, ", ".join(live[:8]),
                     "%d active git hook(s) inside a copied .git directory: they run on git operations" % len(live))

    # ------------------------------------------------------------ per-file

    def _classify(self, fc, head_text=""):
        name, ext, rel = fc.name, fc.ext, fc.rel_lower
        fc.is_md_like = ext in PROSE_EXT or name in AUTOLOAD_NAMES or (not ext and name in (
            "readme", "license", "notice", "authors", "copying", "changelog"))
        fc.is_html = ext in HTML_EXT or (ext not in CODE_EXT and ext not in CONFIG_EXT and ext not in MD_EXT
                                         and bool(_HTML_SNIFF.search(head_text[:3000])))
        if self.kind in ("article", "page"):
            fc.role = "page"
            return
        if name in GENERATED_NAMES or name.endswith(GENERATED_SUFFIX):
            fc.role = "generated"
            return
        if name in AUTOLOAD_NAMES or AUTOLOAD_PATH_RX.search(rel):
            fc.role = "instruction"
            fc.autoload = True
            fc.is_md_like = True
            return
        in_skill = self.all_in_skill or any(rel.startswith(p.lower()) for p in self.skill_roots)
        in_plugin = any(rel.startswith(p.lower()) for p in self.plugin_roots)
        if fc.is_md_like:
            stem = name.rsplit(".", 1)[0] if ext else name
            if DOC_NAME_RX.match(stem):
                fc.role = "doc"
            elif in_skill or (in_plugin and PLUGIN_COMPONENT_RX.search(rel)):
                fc.role = "instruction"
            else:
                fc.role = "doc"
        elif ext in CODE_EXT or name in CODE_NAMES or name.startswith("dockerfile") or head_text.startswith("#!"):
            fc.role = "code"
        elif ext in CONFIG_EXT or name.startswith(".") and not ext:
            fc.role = "config"
        elif fc.is_html:
            fc.role = "markup"

    def _scan_entry(self, path, rel, st, single=False):
        if stat.S_ISLNK(st.st_mode):
            self._link(path, rel)
            return
        if not stat.S_ISREG(st.st_mode):
            self.add("MED", "fs-special-file", rel, 0, "", "not a regular file: not opened")
            return
        self.stats["files"] += 1
        size = st.st_size
        fc = FileCtx(rel, size, single)
        if not fc.parent_name:
            fc.parent_name = self.root_name
        cap = self.opts.max_bytes
        truncated = False
        try:
            with open(path, "rb") as fh:
                if size <= cap:
                    data = fh.read(cap + 1)
                    h = hashlib.sha256(data)
                else:
                    truncated = True
                    head = fh.read(cap * 3 // 4)
                    h = hashlib.sha256(head)
                    remaining = size - len(head)
                    tail_len = cap // 4
                    hashed_all = size <= 512_000_000
                    if hashed_all:
                        to_skip = remaining - tail_len
                        while to_skip > 0:
                            chunk = fh.read(min(1 << 20, to_skip))
                            if not chunk:
                                break
                            h.update(chunk)
                            to_skip -= len(chunk)
                    else:
                        fh.seek(max(0, size - tail_len))
                    tail = fh.read(tail_len)
                    h.update(tail)
                    data = head + b"\n" + tail
        except OSError as exc:
            self.skipped.append("%s (%s)" % (T.sanitize(rel, 200), type(exc).__name__))
            return
        fc.sha256 = h.hexdigest()
        self.sha[rel] = fc.sha256
        for root in self.plugin_roots:
            prefix = (root + "bin/").lower()
            if fc.rel_lower.startswith(prefix) and "/" not in fc.rel_lower[len(prefix):]:
                stem = fc.name.rsplit(".", 1)[0] if fc.ext in (".exe", ".cmd", ".bat", ".sh", ".ps1") else fc.name
                shadow = stem in COMMON_COMMANDS
                self.add("HIGH" if shadow else "MED", "plugin-bin", fc, 0, fc.name,
                         "plugin puts this executable on the shell PATH%s" % (
                             ": its name shadows a common command, so ordinary commands would run it" if shadow
                             else " (callable by name from any shell command the agent runs)"))
                break
        self.stats["bytes"] += len(data)
        self._scan_data(fc, data, path=path)
        if truncated:
            entry = fc.role == "instruction" or fc.name in ("skill.md", "plugin.json", "hooks.json", ".mcp.json")
            self.add("HIGH" if entry else "MED", "scan-truncated", fc, 0, "",
                     "file is %d bytes; only the first %d and last %d bytes were scanned" % (
                         size, cap * 3 // 4, cap // 4))

    def scan_member(self, parent_fc, member_name, data):
        """Scan an archive member held in memory (called by archives.scan)."""
        fc = FileCtx(parent_fc.rel + "!/" + member_name.replace("\\", "/"), len(data))
        fc.in_archive = True
        fc.sha256 = parent_fc.sha256
        self._scan_data(fc, data, path=None)

    def _scan_data(self, fc, data, path=None):
        budget = Budget(self.opts.file_budget)
        head = data[:512]
        if path and self.opts.scan_archives and not fc.in_archive:
            akind = archives.kind_of(fc.name, head)
            if akind:
                self.stats["archives"] += 1
                self._classify(fc)
                archives.scan(self, fc, path, akind, budget)
                return
        if any(head.startswith(magic) for magic, _k, _l in MAGIC) or T.looks_binary(data):
            self._classify(fc)
            self._binary(fc, data, budget)
            return
        text, enc = T.decode_bytes(data)
        if enc == "utf-8-lossy":
            self.add("LOW", "enc-unusual", fc, 0, "", "file is not valid UTF-8; undecodable bytes were replaced")
        elif enc.startswith(("utf-16", "utf-32")):
            self.add("LOW", "enc-unusual", fc, 0, "", "file is %s encoded (plain-text tools may not show its content)" % enc)
        text = T.normalize_eol(text)
        if "\x00" in text:
            text = text.replace("\x00", " ")
        self._classify(fc, text[:3000])
        try:
            self._scan_text(fc, text, budget)
        except RecursionError:
            self.add("HIGH", "scan-incomplete", fc, 0, "", "analysis aborted (structure too deeply nested); file is UNSCANNED in part")
        self._flush_phrases(fc)
        if budget.expired():
            self.add("HIGH", "scan-incomplete", fc, 0, "",
                     "per-file time budget (%.0fs) reached: this file was only partly analyzed" % self.opts.file_budget)

    # ------------------------------------------------------------ text analysis

    def _vis_class(self, fc):
        if fc.role == "instruction":
            return "instruction"
        if fc.role == "page":
            return "consumed" if self.kind == "page" else "page"
        if self.kind == "mcp" and fc.role in ("code", "config"):
            return "tooldesc"
        return "other"

    @staticmethod
    def _is_quoted(lines, h):
        """True when the matched words directly follow an opening quote on their line and a closing
        quote comes later: "..." / '...' / `...` and their typographic forms."""
        if not h.match or not (0 < h.line <= len(lines)):
            return False
        raw = lines[h.line - 1]
        first = h.match.split(" ", 1)[0].split("\n", 1)[0]
        low = raw.lower()
        i = low.find(first)
        while i != -1:
            j = i
            while j > 0 and raw[j - 1] in "*_ ":
                j -= 1
            if j > 0 and raw[j - 1] in _QUOTE_OPEN and raw[j - 1] != "(":
                rest = raw[i + len(first):] + (" " + lines[h.line] if h.line < len(lines) else "")
                if any(q in rest for q in _QUOTE_CLOSE):
                    return True
            i = low.find(first, i + 1)
        return False

    def _phrase_hit(self, fc, h, cls, label, line_base=0, forced_line=None, mention=None):
        """Queue one phrase hit; later the most severe one per (rule, line) is kept.

        `mention` ('example' / 'prohibition', from framing.phrase_mention) lowers a visible HIGH hit in
        an instruction file to MED: the words are quoted as an example or named as something to refuse."""
        obf = h.mode != "plain"
        eff_cls = "hidden" if obf else cls
        sev = phrases.severity_for(h.tier, eff_cls)
        if h.tier == "himp":
            if cls != "hidden" and cls != "tooldesc":
                return
            if label in ("attribute value", "inline script", "stylesheet"):
                return
            if fc.role == "page" or (fc.role in ("doc", "markup", "other") and self.kind == "repo"):
                sev = "LOW"
        if sev is None:
            return
        line = forced_line if forced_line is not None else h.line + line_base
        ctx = label
        note = RULES[h.rule]["title"]
        if sev == "HIGH" and cls in ("instruction", "consumed") and not obf and mention:
            sev = "MED"
            if mention == "example":
                ctx = label + "; quoted example"
                note += (" - framed as an example or a mention (quoted after 'such as' / 'e.g.', described as "
                         "'a request to ...', or in an example block): read the context")
            else:
                ctx = label + "; under a prohibition"
                note += " - named in a sentence that forbids it ('never', 'do not', 'defend against'): read the context"
        if obf:
            ctx = "%s; %s" % (label, h.mode)
            note += " - found only after undoing %s" % {
                "deobfuscated": "invisible / format characters, look-alike letters or split markup",
                "punct-split": "punctuation inside words", "leetspeak": "digit-for-letter substitution",
                "letter-spaced": "letter spacing", "rot13": "ROT13", "reversed": "reversed text"}.get(h.mode, h.mode)
        elif cls == "page":
            note += " (visible text: may be a quoted example, read it in context)"
        elif cls == "consumed":
            note += " - visible in content an agent would read (--kind page): an instruction to the reader"
        elif cls == "hidden":
            note += " - located in %s, which a reader does not normally see" % label
        key = (h.rule, line)
        old = self._phr.get(key)
        if old is None or SEV_RANK[sev] < SEV_RANK[old[0]]:
            self._phr[key] = (sev, h.rule, line, _VIEW_TOKEN_RX.sub(_mask_view_token, h.excerpt), note, ctx)

    def _flush_phrases(self, fc):
        for key in sorted(self._phr, key=lambda k: (k[1], k[0])):
            sev, rid, line, excerpt, note, ctx = self._phr[key]
            self.add(sev, rid, fc, line, excerpt, note, ctx)
        self._phr = {}

    def note_limit(self, fc, kind, n=1):
        """Record content that a limit left unanalyzed (reported in the report header as incomplete)."""
        rel = fc.rel if isinstance(fc, FileCtx) else str(fc)
        key = (rel, kind)
        self._limits[key] = self._limits.get(key, 0) + n

    def limits(self):
        return [{"file": T.sanitize(f, 260), "kind": k, "count": n} for (f, k), n in sorted(self._limits.items())]

    def _phrase_stream(self, fc, text, cls, label, budget, visible_matches=None, collect=None, forced_line=None):
        hits = phrases.scan_text(text, budget)
        if getattr(hits, "capped", ()):
            self.note_limit(fc, "phrase-match-limit")
            self.add("MED", "match-limit", fc, 0, ", ".join(hits.capped)[:120],
                     "more than %d matches of one phrase rule in %s: later occurrences were not examined, "
                     "read the file" % (phrases.MAX_HITS_PER_RULE, label))
        fctx = framing.Context(text) if hits and cls in ("instruction", "consumed") else None
        lines = text.split("\n") if fctx is not None else None
        for h in hits:
            if collect is not None and h.mode == "plain":
                collect.add((h.rule, h.match))
            if visible_matches is not None and h.mode == "plain" and (h.rule, h.match) in visible_matches:
                # the same words are also visible on the page (title / description / hydration data)
                self._phrase_hit(fc, h, self._vis_class(fc), label + " (mirrors visible text)", 0, forced_line)
                continue
            mention = None
            if fctx is not None and h.mode == "plain" and phrases.severity_for(h.tier, cls) == "HIGH":
                mention = framing.phrase_mention(fctx, h.line, h.match, self._is_quoted(lines, h))
            self._phrase_hit(fc, h, cls, label, 0, forced_line, mention=mention)
        for line, tag in phrases.find_role_tags(text.lower()):
            sev = phrases.severity_for("weak", cls)
            if sev:
                key = ("inj-role-tags", forced_line if forced_line is not None else line)
                old = self._phr.get(key)
                if old is None or SEV_RANK[sev] < SEV_RANK[old[0]]:
                    self._phr[key] = (sev, "inj-role-tags", key[1], tag, RULES["inj-role-tags"]["title"] + (
                        " - located in %s" % label if cls == "hidden" else ""), label)
        return hits

    def _scan_text(self, fc, text, budget):
        role = fc.role
        vis_cls = self._vis_class(fc)
        low = text.lower()

        # 1. invisible characters
        def inv_add(sev, rid, line, snippet, note):
            self.add(sev, rid, fc, line, snippet, note)
        for name, line, payload in invisible.scan(text, inv_add, role, self.kind,
                                                  prose=fc.is_md_like or fc.is_html):
            self._decoded(fc, payload, name, line, budget, 1, "")

        # 2. streams
        html = None
        if fc.is_html:
            html = markup.analyze_html(text, budget)
            visible_matches = set()
            vis_hits = self._phrase_stream(fc, html.streams.get("visible", ""), vis_cls, "visible text", budget,
                                           collect=visible_matches)
            stream_lines = {}
            for h in vis_hits:
                stream_lines.setdefault(h.rule, []).append(h.line)
            for name in sorted(html.streams):
                if name == "visible":
                    continue
                hs = self._phrase_stream(fc, html.streams[name], "hidden", STREAM_LABEL.get(name, name), budget,
                                         visible_matches if name in MIRROR_STREAMS else None)
                for h in hs:
                    stream_lines.setdefault(h.rule, []).append(h.line)
            for h in phrases.scan_raw_markup(text, budget):
                near = stream_lines.get(h.rule, ())
                if not any(abs(h.line - ln) <= 6 for ln in near):
                    self._phrase_hit(fc, h, "hidden", STREAM_LABEL["raw"])
            for line, tag in phrases.find_role_tags(low):
                key = ("inj-role-tags", line)
                sev = phrases.severity_for("weak", vis_cls)
                if sev and key not in self._phr:
                    self._phr[key] = (sev, "inj-role-tags", line, tag, RULES["inj-role-tags"]["title"], "raw markup")
            self._html_facts(fc, html)
        else:
            stream_lines = {}

            def keep(hs):
                for h in hs:
                    stream_lines.setdefault(h.rule, []).append(h.line)
            keep(self._phrase_stream(fc, text, vis_cls, "visible text", budget))
            # In Markdown, markup inside code spans/fences is shown literally: it is not live HTML.
            live = markup.strip_md_code(text) if fc.is_md_like else text
            if "<!--" in live:
                cs = markup.comment_stream(live)
                if cs:
                    keep(self._phrase_stream(fc, cs, "hidden", STREAM_LABEL["comment"], budget))
                    if role == "instruction" and len(cs.strip()) >= 40:
                        self.add("LOW", "html-comment-text", fc, T.line_of(live, live.find("<!--")),
                                 cs.strip()[:160], "%d characters of comment text are invisible when this file is "
                                 "rendered: read them" % len(cs.strip()))
            if fc.is_md_like:
                md = markup.analyze_markdown(live)
                if md.hidden:
                    keep(self._phrase_stream(fc, md.hidden, "hidden", STREAM_LABEL["md-hidden"], budget))
                self._md_facts(fc, md)
                if _HAS_TAG.search(live):
                    html = markup.analyze_html(live, budget)
                    for name in sorted(html.streams):
                        if name in ("visible", "comment"):
                            continue
                        keep(self._phrase_stream(fc, html.streams[name], "hidden", STREAM_LABEL.get(name, name),
                                                 budget))
                    self._html_facts(fc, html, embedded=True)
                    # Raw source with tags kept as words: text parked in tag or attribute names (or in a tag
                    # that spans lines) is invisible when the Markdown is rendered.
                    for h in phrases.scan_raw_markup(live, budget):
                        if not any(abs(h.line - ln) <= 6 for ln in stream_lines.get(h.rule, ())):
                            self._phrase_hit(fc, h, "hidden", STREAM_LABEL["raw"])
        if budget.expired():
            return

        # 3. character-reference obfuscation
        ev = decoders.entity_variants(text)
        if ev:
            base = {(h.rule, h.line) for h in phrases.scan_text(ev[0], budget)}
            for h in phrases.scan_text(ev[1], budget):
                if (h.rule, h.line) not in base:
                    h.mode = "plain"
                    self._phrase_hit(fc, h, "hidden", "letters written as HTML character references")

        # 4. encoded blobs
        if role != "generated":
            self._decode_layer(fc, text, budget, 1)
            # The base85 family uses < > & " ' : in markup these arrive entity-escaped and glued to tags.
            # Decode it again on the parsed streams (entities resolved, tags removed) and, for Markdown,
            # on the entity-decoded text.
            if html is not None:
                for name in sorted(html.streams):
                    self._decode_text_only(fc, html.streams[name], budget, "base85")
            elif fc.is_md_like and _ENTITY_REF_RX.search(text):
                plain = _html.unescape(text)
                if plain.count("\n") == text.count("\n"):
                    self._decode_text_only(fc, plain, budget, "base85")
        if budget.expired():
            return

        # 5. code-behaviour rules
        self._code_rules(fc, text, low, budget)
        if html is not None and role == "page":
            for name in ("comment", "hidden", "attr", "meta", "jsonld", "svg"):
                st = html.streams.get(name)
                if st:
                    self._danger_rules(fc, st, STREAM_LABEL[name], None, budget)

        # 6. URLs
        self._urls(fc, text)

        # 7. structure-aware checks
        if role != "page":
            scope = FileScope(self, fc)
            configs.analyze(scope, fc, text)
            for name, stext, cls in scope.streams:
                self._phrase_stream(fc, stext, cls, STREAM_LABEL.get(name, name), budget, forced_line=1)

        # 8. shape heuristics
        self._shape(fc, text)

        # 9. correlation
        self._correlate(fc)

    # ------------------------------------------------------------ decoded content

    def _decode_layer(self, fc, text, budget, depth):
        stats = {}
        cands, blobs, skipped = decoders.find(text, budget, stats)
        if stats.get("partial"):
            self._decode_partial(fc, stats["partial"])
        for c in cands:
            self._decoded(fc, c.text, "decoded:" + c.kind, c.line, budget, depth, c.prefix)
            if budget.expired():
                break
        if depth == 1:
            role = fc.role
            for line, length, kind in blobs[:6]:
                if kind == "base64-binary-executable":
                    self.add("HIGH" if role != "page" else "MED", "obf-embedded-binary", fc, line, "",
                             "%d-character base64 blob decodes to an executable / archive / WebAssembly header" % length)
                elif role == "instruction":
                    self.add("MED", "obf-blob", fc, line, "", "%d-character opaque %s blob inside an instruction "
                             "file: its content cannot be reviewed by reading" % (length, kind))
                elif role in ("code", "config", "doc", "other", "markup"):
                    self.add("LOW", "obf-blob", fc, line, "", "%d-character opaque %s blob" % (length, kind))
            if skipped:
                self.note_limit(fc, "left undecoded: decode count/size limit", skipped)
                self.add("MED", "decode-budget", fc, 0, "",
                         "%d encoded blob(s) were not decoded (decode limit reached): content partly uninspected" % skipped)

    def _decode_text_only(self, fc, text, budget, only):
        """Decode one family in an extra view of the file (no blob reporting: the raw pass did that)."""
        if not text or len(text) < 20 or budget.expired():
            return
        stats = {}
        cands, _blobs, skipped = decoders.find(text, budget, stats, only=only)
        if stats.get("partial"):
            self._decode_partial(fc, stats["partial"])
        if skipped:
            self.note_limit(fc, "left undecoded: decode count/size limit", skipped)
        for c in cands:
            self._decoded(fc, c.text, "decoded:" + c.kind, c.line, budget, 1, c.prefix)
            if budget.expired():
                break

    def _decode_partial(self, fc, n):
        self.note_limit(fc, "left undecoded: blob larger than the per-blob size limit", n)
        if not any(f.rule == "decode-limit" and f.file == T.sanitize(fc.rel, 260) for f in self.findings[-50:]):
            self.add("MED", "decode-limit", fc, 0, "",
                     "%d encoded blob(s) were decoded only up to the size limit (%d input characters): the rest was "
                     "left undecoded" % (n, decoders.MAX_BLOB_INPUT))

    def _decoded(self, fc, payload, label, line, budget, depth, prefix):
        """Re-scan decoded text. Everything found here was hidden by an encoding layer."""
        for h in phrases.scan_text(payload, budget):
            if h.tier == "himp":
                continue
            h.mode = "plain"
            self._phrase_hit(fc, h, "hidden", label, forced_line=line)
        for _ln, tag in phrases.find_role_tags(payload.lower()):
            key = ("inj-role-tags", line)
            self._phr[key] = ("HIGH", "inj-role-tags", line, tag,
                              RULES["inj-role-tags"]["title"] + " - inside %s" % label, label)
        if not _SRCMAP_RX.search(prefix or ""):
            self._danger_rules(fc, payload, label, line, budget)
        if len(payload) >= 24 and not budget.expired():
            stats = {}
            cands, _blobs, skipped = decoders.find(payload, budget, stats)
            if stats.get("partial"):
                self._decode_partial(fc, stats["partial"])
            if cands and depth >= MAX_DECODE_DEPTH:
                self.note_limit(fc, "left undecoded: nesting depth limit (%d layers)" % MAX_DECODE_DEPTH, len(cands))
                self.add("MED", "decode-limit", fc, line, "",
                         "decoded content (%s) holds %d more encoded layer(s) beyond the nesting limit of %d: "
                         "left undecoded" % (label, len(cands), MAX_DECODE_DEPTH))
                return
            if skipped:
                self.note_limit(fc, "left undecoded: decode count/size limit", skipped)
            if len(cands) > 200:
                self.note_limit(fc, "left undecoded: more than 200 nested blobs", len(cands) - 200)
            for c in cands[:200]:
                self._decoded(fc, c.text, label + ">" + c.kind, line, budget, depth + 1, c.prefix)

    def _danger_rules(self, fc, text, label, line, budget):
        def emit(r, m):
            ln = line if line is not None else T.line_of(text, m.start())
            snip = text[max(0, m.start() - 20):m.end() + 60]
            self.add("HIGH", r.id, fc, ln, snip, "%s - inside %s" % (r.note, label), label)
            fc.tags.setdefault("hidden-danger", []).append(ln)
        coderules.run(text, text.lower(), emit, DANGEROUS, budget)

    # ------------------------------------------------------------ code rules

    def _code_rules(self, fc, text, low, budget):
        role = fc.role
        if role == "generated":
            rules = (coderules.BY_ID["sec-secret-literal"],)
        elif role == "page":
            rules = DANGEROUS
        else:
            rules = coderules.RULES
        prose = fc.is_md_like or role in ("other", "markup")
        fctx = []

        def emit(r, m):
            mention = False
            if role == "page":
                sev = r.page
            elif prose:
                sev = r.prose
                if sev and role == "doc" and r.id != "sec-secret-literal":
                    sev = lower(sev)
                elif sev and role == "instruction" and fc.is_md_like and r.id != "sec-secret-literal":
                    # A defensive skill names what it forbids (a permission-bypass flag after "never", a
                    # reverse-shell one-liner "you defend against"). Inline code spans and negated / defensive
                    # sentences are lowered one step; fenced code blocks and un-negated imperatives
                    # ("now run <download-and-run command>") are not. See framing.code_mention.
                    if not fctx:
                        fctx.extend((framing.Context(text), {}))
                    n_mentions = fctx[1].get(r.id, 0)
                    if n_mentions >= MAX_MENTIONS:
                        if n_mentions == MAX_MENTIONS:
                            fctx[1][r.id] = n_mentions + 1
                            self.note_limit(fc, "code-mention-limit")
                            self.add("MED", "match-limit", fc, 0, r.id,
                                     "more than %d defensive mentions of %s: further matches are counted against "
                                     "the per-rule limit and may go unreported, read the file" % (MAX_MENTIONS, r.id))
                    elif framing.code_mention(fctx[0], m.start(), m.end()):
                        sev, mention = lower(sev), True
                        fctx[1][r.id] = n_mentions + 1
            else:
                sev = r.sev
            if sev is None:
                return
            s = m.start()
            ls = text.rfind("\n", 0, s) + 1
            le = text.find("\n", s)
            if le < 0:
                le = len(text)
            snip = text[ls:le] if le - ls <= 220 else text[max(ls, s - 60):min(le, m.end() + 120)]
            note = r.note
            if r.redact:
                tok = m.group(0)
                kind = (m.lastgroup or "secret").replace("_", "-")
                if T.is_placeholder_secret(tok):
                    sev, note = "LOW", "credential-shaped placeholder (%s)" % kind
                else:
                    note = "%s: %s" % (note, kind)
            line = text.count("\n", 0, s) + 1
            if mention:
                note += " (named in inline code or under a prohibition, not as an order: read the sentence)"
            self.add(sev, r.id, fc, line, snip, note)
            if mention:
                return False        # not counted against the per-rule match limit
            for t in r.tags:
                fc.tags.setdefault(t, []).append(line)
        coderules.run(text, low, emit, rules, budget)

    def _correlate(self, fc):
        if fc.role in ("page", "generated", "doc"):
            return
        tags = fc.tags
        if "secret-src" in tags and "net" in tags:
            self.add("HIGH", "corr-secrets-network", fc, min(tags["secret-src"]), "",
                     "this file both reaches for credentials (line %d) and talks to the network (line %d): "
                     "check for exfiltration" % (min(tags["secret-src"]), min(tags["net"])))
        elif fc.role == "code" and "net" in tags and ("secret-soft" in tags or "secret-named" in tags):
            src = tags.get("secret-soft") or tags.get("secret-named")
            self.add("MED", "corr-secret-env-network", fc, min(src), "",
                     "this file reads a secret-bearing source (line %d) and uses the network (line %d): confirm "
                     "the destination is the service that secret belongs to" % (min(src), min(tags["net"])))
        if "decode" in tags and "exec" in tags:
            near = any(abs(d - e) <= 3 for d in tags["decode"][:60] for e in tags["exec"][:60])
            if near:
                self.add("HIGH", "corr-decode-exec", fc, min(tags["decode"]), "",
                         "decoding and execution within a few lines of each other")
            elif fc.role == "code":
                self.add("MED", "corr-decode-exec", fc, min(tags["decode"]), "",
                         "this file both decodes data at runtime and executes code/commands")

    # ------------------------------------------------------------ URLs and markup facts

    def _urls(self, fc, text):
        if "://" not in text:
            return
        seen = set()
        last_pos, line = 0, 1
        for m in _URL_RX.finditer(text):
            u = m.group(0).rstrip(".,;:!?")
            if u in seen:
                continue
            seen.add(u)
            if len(seen) > 3000:
                break
            line += text.count("\n", last_pos, m.start())
            last_pos = m.start()
            self.note_url(fc, u, line, "text")

    def note_url(self, fc, url, line, origin, is_image=False):
        u = url.strip()
        low = u.lower()
        hard = fc.role in ("instruction", "code", "config") or fc.is_md_like and fc.role != "page"
        if low.startswith(("javascript:", "vbscript:")):
            body = low.split(":", 1)[1].strip().rstrip(";")
            trivial = body in ("", "void(0)", "void 0", "void(0);", "//", "history.back()", "window.print()",
                               "return false", "false", "void(null)")
            if hard:
                self.add("HIGH", "uri-script-scheme", fc, line, u[:160], "script-scheme link in %s" % origin)
            elif not trivial:
                self.add("MED" if fc.role != "page" else "LOW", "uri-script-scheme", fc, line, u[:160],
                         "script-scheme link in %s" % origin)
            return
        if low.startswith("data:"):
            if re.match(r"data:(?:text/html|application/(?:x-)?javascript|text/javascript|image/svg\+xml|"
                        r"application/xhtml)", low):
                self.add("HIGH" if hard else "MED", "uri-data-scheme", fc, line, u[:120],
                         "data: URI with active content in %s" % origin)
            return
        if low.startswith("file:"):
            self.add("MED", "uri-file-scheme", fc, line, u[:160], "file: URI in %s" % origin)
            return
        if "://" not in u:
            return
        try:
            parts = urlsplit(u)
            host = (parts.hostname or "").lower()
            user = parts.username
        except ValueError:
            return
        if not host:
            return
        self.hosts[host] = self.hosts.get(host, 0) + 1
        flags = self.host_flags.setdefault(host, set())
        if parts.scheme.lower() in ("http", "ws", "ftp") and host not in ("localhost", "127.0.0.1"):
            flags.add("plain")
        key = (fc.rel, host, origin if origin != "text" else "")
        first = key not in self._url_seen
        self._url_seen.add(key)
        if first:
            if user is not None:
                deceptive = "." in user and not parts.password
                self.add("HIGH" if deceptive else "MED", "url-userinfo", fc, line, u[:200],
                         "URL has a user-info part before @%s" % (
                             ": the text before @ looks like a host but the real host is " + host if deceptive
                             else " (embedded credentials)"))
            bare = host.strip("[]")
            try:
                ip = ipaddress.ip_address(bare)
            except ValueError:
                ip = None
            if ip is not None:
                local = (ip.is_loopback or ip.is_link_local or ip.is_unspecified
                         or any(ip in net for net in _LOCAL_NETS if net.version == ip.version))
                if not local:
                    flags.add("raw-ip")
                    self.add("LOW" if fc.role == "page" else "MED", "url-raw-ip", fc, line, u[:160],
                             "URL points at a raw non-local IP address instead of a named host")
            elif _OBF_IP_RX.match(bare):
                flags.add("obfuscated-ip")
                self.add("HIGH", "url-obfuscated-ip", fc, line, u[:160],
                         "host is an integer / hex / octal form of an IP address")
            if "xn--" in host or not host.isascii():
                flags.add("idn")
                self.add("MED", "url-idn-host", fc, line, u[:160],
                         "internationalized host name: compare it letter by letter with the name you expect")
            if host in SHORTENERS:
                flags.add("shortener")
                self.add("MED" if fc.role == "instruction" else "LOW", "url-shortener", fc, line, u[:160],
                         "shortened URL: destination unknown until followed")
            if coderules._EXFIL_RX.search(u):
                flags.add("exfil-list")
        beaconish = is_image or origin.split(".")[0] in ("img", "iframe", "embed", "object", "source", "video",
                                                         "audio", "track", "input", "link")
        if beaconish:
            self._beacon(fc, u, parts, host, line, origin)

    def _beacon(self, fc, u, parts, host, line, origin):
        templ = _TEMPLATE_RX.search(u)
        exfil = coderules._EXFIL_RX.search(u)
        if templ or exfil:
            self.add("HIGH", "beacon-url", fc, line, u[:200],
                     "%s URL %s: rendering it sends data to %s" % (
                         origin, "contains a fill-in placeholder" if templ else "points at a known collection host",
                         host))
            return
        if not parts.query or fc.role == "page":
            return
        if any(host == b or host.endswith("." + b) for b in BENIGN_IMG_HOSTS):
            return
        try:
            q = parse_qsl(parts.query, keep_blank_values=True)[:40]
        except ValueError:
            q = []
        names = {k.lower() for k, _ in q}
        if names & BEACON_PARAM or any(len(v) >= 32 for _, v in q):
            self.add("MED", "beacon-url", fc, line, u[:200],
                     "%s URL carries data-shaped query parameters to %s (fetched automatically when rendered)" % (
                         origin, host))

    def _link_mismatch(self, fc, label, href, line):
        m = _HOSTLIKE_RX.match(label.strip())
        if not m or "://" not in href:
            return
        if (m.group(1).rsplit(".", 1)[-1].lower() in FILE_EXT_LABELS
                and not label.strip().lower().startswith(("http://", "https://", "www."))):
            return      # "Color.js", "colormaps.py": a file or library name, not a host
        try:
            real = (urlsplit(href).hostname or "").lower()
        except ValueError:
            return
        shown = m.group(1).lower()
        if not real or not shown:
            return

        def reg(h):
            p = h.split(".")
            if len(p) >= 3 and len(p[-1]) == 2 and p[-2] in ("co", "com", "org", "net", "gov", "ac", "edu"):
                return ".".join(p[-3:])
            return ".".join(p[-2:])
        if reg(shown) != reg(real):
            self.add("MED", "link-text-mismatch", fc, line, "%s -> %s" % (label[:80], href[:120]),
                     "link text shows %s but the link goes to %s" % (shown, real))

    def _md_facts(self, fc, md):
        for line, is_image, label, url, _title in md.links[:2000]:
            self.note_url(fc, url, line, "markdown image" if is_image else "markdown link", is_image)
            if not is_image:
                self._link_mismatch(fc, label, url, line)
        for line, label, url, _title, is_comment in md.refs[:2000]:
            if url and not is_comment:
                self.note_url(fc, url, line, "markdown reference")

    def _html_facts(self, fc, html, embedded=False):
        page = fc.role == "page"
        if html.aborted:
            self.add("MED", "html-parse-abort", fc, 0, "", "markup tokenizer stopped early (%s)" % html.aborted)
        for url, line, origin in html.urls[:4000]:
            self.note_url(fc, url, line, origin)
        for kind, line, detail in html.facts[:4000]:
            if kind == "anchor":
                self._link_mismatch(fc, detail[0], detail[1], line)
            elif kind == "meta-refresh":
                self.add("MED", "html-meta-refresh", fc, line, detail[:160], "page redirects itself")
            elif kind == "base-href":
                self.add("MED", "html-base-href", fc, line, detail[:160], "base href changes where relative links go")
            elif kind == "zero-size":
                tag = detail.split(" ", 1)[0]
                self.add("LOW" if page and tag == "img" else "MED", "html-zero-size", fc, line, detail[:160],
                         "zero-size or hidden <%s>" % tag)
        hidden = html.streams.get("hidden", "")
        if len(hidden.strip()) >= (400 if page else 40):
            reasons = ", ".join("%s x%d" % (k, v) for k, v in sorted(html.hidden_reasons.items())[:6])
            self.add("LOW" if page or fc.role == "markup" else "MED", "html-hidden-text", fc,
                     1 + (len(hidden) - len(hidden.lstrip("\n"))), hidden.strip()[:160],
                     "%d characters of text sit in elements that are not rendered (%s): read them" % (
                         len(hidden.strip()), reasons))
        if not embedded and not page and html.comments:
            pass

    # ------------------------------------------------------------ shape heuristics

    def _shape(self, fc, text):
        n = len(text)
        if n < 4000 or fc.role in ("page", "generated"):
            if fc.role == "generated" and fc.name.endswith((".min.js", ".min.mjs", ".bundle.js")):
                self.add("LOW", "obf-minified", fc, 0, "", "minified vendor file: verify it matches the upstream release")
            return
        lines = text.count("\n") + 1
        longest = max((len(x) for x in text.split("\n", 20000)[:20000]), default=0)
        if fc.role == "code" and (longest > 5000 or n / lines > 400):
            self.add("MED", "obf-minified", fc, 0, "",
                     "minified or packed code (longest line %d chars): cannot be reviewed line by line" % longest)
        elif fc.role in ("instruction", "doc") and longest > 20000:
            self.add("MED" if longest > 200_000 else "LOW", "obf-long-line", fc, 0, "",
                     "line of %d characters in a text file (hard to review in an editor)" % longest)

    # ------------------------------------------------------------ binary

    def _binary(self, fc, data, budget):
        self.stats["binary"] += 1
        head = data[:16]
        kind, label = None, ""
        for magic, k, lab in MAGIC:
            if head.startswith(magic):
                kind, label = k, lab
                break
        ext = fc.ext
        if ext in (".pyc", ".pyo") and kind != "exe":
            flags = int.from_bytes(data[4:8], "little") if len(data) >= 8 else 0
            unchecked = bool(flags & 0x1) and not flags & 0x2
            if unchecked or "__pycache__/" not in fc.rel_lower:
                self.add("HIGH", "bin-executable", fc, 0, "",
                         "Python bytecode %s: it runs instead of any source you reviewed" % (
                             "marked 'unchecked' (loaded without comparing to the .py file)" if unchecked
                             else "shipped without being in __pycache__ (source-less module)"))
            else:
                self.add("MED", "bin-executable", fc, 0, "",
                         "compiled Python bytecode: delete __pycache__ directories before installing, so that only "
                         "reviewed source runs")
        elif kind == "exe" or ext in (".class", ".pyd", ".node"):
            if ext in MEDIA_EXT or ext in PROSE_EXT or ext in CONFIG_EXT:
                self.add("HIGH", "bin-type-mismatch", fc, 0, "",
                         "extension %s but content is %s" % (ext or "(none)", label or "compiled code"))
            self.add("HIGH", "bin-executable", fc, 0, "",
                     "%s: compiled code cannot be reviewed by reading; do not install without provenance" % (
                         label or "compiled code"))
        elif kind == "ole":
            self.add("MED", "bin-executable", fc, 0, "", "%s: may contain macros or installers" % label)
        elif ext in PICKLE_EXT or (ext == ".pth" and head[:2] in (b"PK", b"\x80\x02", b"\x80\x04")):
            self.add("MED", "bin-pickle", fc, 0, "", "serialized object file: loading it can execute code")
        elif kind == "pdf":
            flags = sorted({m.group(1) for m in _PDF_ACTIVE.finditer(data[:4_000_000])})
            if flags:
                self.add("MED", "bin-pdf-active", fc, 0, ", ".join(f.decode() for f in flags),
                         "PDF has active-content markers; compressed text streams are not inspected")
        elif kind in ("media", "data"):
            if ext and ext not in MEDIA_EXT and ext not in (".db", ".sqlite", ".sqlite3", ".webp", ".riff"):
                self.add("MED", "bin-type-mismatch", fc, 0, "", "extension %s but content is %s" % (ext, label))
        else:
            self.add("MED", "bin-nontext", fc, 0, "", "non-text file of unknown type: not inspectable by this scanner")
        # strings pass: metadata and embedded text can still carry instructions
        chunk = data[:2_000_000]
        strs = [m.group(0).decode("ascii", "replace") for m in _ASCII_STR.finditer(chunk)][:20000]
        strs += [m.group(0).decode("utf-16-le", "replace") for m in _UTF16_STR.finditer(chunk)][:5000]
        if strs:
            blob = "\n".join(strs)[:600_000]
            for h in phrases.scan_text(blob, budget):
                if h.tier in ("himp", "soft", "softhi", "tool"):
                    continue
                h.mode = "plain"
                self._phrase_hit(fc, h, "hidden", "strings embedded in a binary file", forced_line=0)
            for _ln, tag in phrases.find_role_tags(blob.lower())[:3]:
                self._phr[("inj-role-tags", 0)] = ("MED", "inj-role-tags", 0, tag,
                                                   RULES["inj-role-tags"]["title"] + " - in binary strings",
                                                   "strings embedded in a binary file")
            self._flush_phrases(fc)

    # ------------------------------------------------------------ wrap-up

    def _finish(self):
        self.findings.sort(key=Finding.sort_key)
        self.inventory = sorted(set(self.inventory))


DANGEROUS = tuple(r for r in coderules.RULES if r.page is not None)
