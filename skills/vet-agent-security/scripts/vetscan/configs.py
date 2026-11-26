"""Structure-aware checks for skills, plugins, MCP configs, agent settings and
repo-level files that execute or auto-load (hooks, lifecycle scripts, CI, devcontainer...).

Everything here only parses text. JSON is parsed with the stdlib json module,
YAML frontmatter and TOML/INI files with small tolerant line parsers.
"""
import json
import re

from . import textutil as T
from .model import rule

rule("skill-frontmatter-hooks", "skill", "skill or agent frontmatter defines hooks (needs explicit user OK)")
rule("skill-allowed-tools", "skill", "frontmatter pre-approves tools without a permission prompt")
rule("skill-shell-injection", "skill", "load-time shell command (runs before the model reads the skill)")
rule("skill-name-shadow", "skill", "skill/command name shadows a built-in or impersonates a vendor")
rule("skill-name-mismatch", "skill", "frontmatter name differs from the directory name")
rule("skill-trigger-coercion", "skill", "description demands the skill be loaded for everything / with priority")
rule("skill-frontmatter-setting", "skill", "frontmatter changes model, context, shell or activation paths")
rule("plugin-manifest", "plugin", "plugin manifest component that executes code (hooks, MCP, LSP, monitors)")
rule("plugin-path-escape", "plugin", "plugin component path leaves the plugin directory")
rule("marketplace-source", "plugin", "marketplace entry with a risky or unpinned source")
rule("hook-definition", "hooks", "hook definition: runs automatically on agent events (needs explicit user OK)")
rule("mcp-remote-server", "mcp", "remote (network) MCP server (needs explicit user OK)")
rule("mcp-stdio-server", "mcp", "local MCP server started as a process")
rule("mcp-shell-command", "mcp", "MCP server command is a shell / inline interpreter")
rule("mcp-unpinned-package", "mcp", "MCP server runs an unpinned package (can change after review)")
rule("mcp-env-passthrough", "mcp", "MCP server receives secret-looking environment values")
rule("mcp-typosquat", "mcp", "package scope/name is one edit away from a well-known publisher")
rule("mcp-auto-approve", "mcp", "MCP config auto-approves tools")
rule("settings-hooks", "agent-config", "agent settings define hooks")
rule("settings-permissions", "agent-config", "agent settings grant broad permissions or a permissive mode")
rule("settings-command-key", "agent-config", "agent settings key that executes a command")
rule("settings-env", "agent-config", "agent settings override a sensitive environment variable")
rule("settings-mcp-autoenable", "agent-config", "agent settings auto-enable project MCP servers or plugins")
rule("settings-sandbox", "agent-config", "agent settings weaken the sandbox")
rule("repo-autoload-file", "repo", "instruction file that an agent loads automatically")
rule("repo-memory-import", "repo", "instruction file imports a path outside the project")
rule("repo-git-hook", "repo", "git hook or hook manager (runs on git operations)")
rule("repo-git-config", "repo", "git configuration that can execute commands")
rule("repo-submodule", "repo", "git submodule")
rule("pkg-lifecycle-script", "repo", "package lifecycle script (runs on install/prepare)")
rule("pkg-nonregistry-dep", "repo", "dependency fetched from a URL or git instead of the registry")
rule("py-build-hook", "repo", "Python build/install-time code execution")
rule("py-startup-file", "repo", "Python file executed automatically at interpreter start")
rule("repo-autoexec-file", "repo", "file that tooling executes automatically when the folder is opened or built")
rule("ci-workflow", "repo", "risky CI workflow construct")
rule("devcontainer-command", "repo", "devcontainer lifecycle command or host mount")
rule("container-privileged", "repo", "container runs privileged or mounts the host")
rule("config-parse-error", "repo", "configuration file could not be parsed (reviewed as plain text only)")
rule("cfg-remote-instructions", "agent-config", "agent config loads instructions from the network or from outside the project")

MAX_CONFIG_BYTES = 2_000_000
SENSITIVE_ENV = re.compile(
    r"(?i)(?:token|secret|password|passwd|api[_-]?key|apikey|credential|private[_-]?key|auth|session|cookie)")
REDIRECT_ENV = re.compile(
    r"(?i)^(?:anthropic_base_url|anthropic_bedrock_base_url|anthropic_vertex_base_url|anthropic_api_url|"
    r"openai_base_url|openai_api_base|.*_base_url|https?_proxy|all_proxy|no_proxy|node_extra_ca_certs|"
    r"node_tls_reject_unauthorized|node_options|ssl_cert_file|requests_ca_bundle|curl_ca_bundle|git_ssh_command|"
    r"git_ssh|git_askpass|ssh_askpass|path|ld_preload|ld_library_path|dyld_insert_libraries|pythonpath|"
    r"pythonstartup|bash_env|env|prompt_command|anthropic_custom_headers|anthropic_api_key|"
    r"anthropic_auth_token|claude_code_api_key_helper_ttl_ms|npm_config_registry|pip_index_url|"
    r"pip_extra_index_url|uv_index_url|uv_extra_index_url|editor|visual|pager|git_pager|browser)$")
BUILTIN_NAMES = frozenset(
    "help clear compact config cost doctor exit init login logout memory model permissions review status "
    "agents hooks mcp plugin plugins skills resume rewind bug context export fast ide install add-dir "
    "terminal-setup vim todos usage security-review pr-comments release-notes statusline output-style bash "
    "read write edit glob grep task agent webfetch websearch skill notebookedit todowrite loop schedule "
    "simplify code-review run".split())
VENDOR_PREFIX = re.compile(r"^(?:claude|anthropic|openai|official|system|admin)[-_:]", re.I)
KNOWN_SCOPES = ("@modelcontextprotocol", "@anthropic-ai", "@playwright", "@upstash", "@cloudflare", "@supabase",
                "@notionhq", "@sentry", "@stripe", "@github", "@microsoft", "@azure", "@aws-sdk", "@google",
                "@openai", "@vercel", "@browserbasehq", "@hubspot", "@atlassian", "@elastic", "@mongodb-js")
HOOK_EVENTS = frozenset(
    "SessionStart Setup UserPromptSubmit UserPromptExpansion PreSkillShellCommand PreToolUse PermissionRequest "
    "PermissionDenied PostToolUse PostToolUseFailure PostToolBatch Notification MessageDisplay SubagentStart "
    "SubagentStop TaskCreated TaskCompleted Stop StopFailure TeammateIdle InstructionsLoaded ConfigChange "
    "CwdChanged DirectoryAdded FileChanged WorktreeCreate WorktreeRemove PreCompact PostCompact PreModelSwitch "
    "PostModelSwitch Elicitation ElicitationResult SessionEnd".split())
LIFECYCLE = ("preinstall", "install", "postinstall", "preuninstall", "postuninstall", "prepare", "prepublish",
             "prepublishOnly", "prepack", "postpack", "dependencies")
COMMAND_KEYS = ("apiKeyHelper", "awsAuthRefresh", "awsCredentialExport", "gcpAuthRefresh", "otelHeadersHelper",
                "fileSuggestion", "statusLine")
_SHELLS = re.compile(r"(?i)^(?:.*[\\/])?(?:sh|bash|zsh|dash|fish|cmd|cmd\.exe|powershell|powershell\.exe|pwsh|"
                     r"pwsh\.exe)$")
_INLINE_FLAGS = ("-c", "-e", "/c", "-command", "-encodedcommand", "--eval", "-enc", "-p")

_FM_RX = re.compile(r"\A---[ \t]*\n(.*?)\n(?:---|\.\.\.)[ \t]*(?:\n|\Z)", re.S)
_FM_KEY = re.compile(r"^([A-Za-z_][\w-]{0,60})[ \t]*:[ \t]*(.*)$")
_BANG_INLINE = re.compile(r"(?m)(?:^|(?<=[ \t]))!`([^`\n]{1,500})`")
_BANG_FENCE = re.compile(r"(?m)^[ \t]{0,3}```!")
_AT_IMPORT = re.compile(r"(?m)(?:^|(?<=[ \t]))@((?:~|\.\./|/)[^\s`'\"<>]{1,300})")
_COERCE = re.compile(
    r"(?i)\b(?:every (?:time|request|message|task|conversation|prompt|response|session)|any conversation|"
    r"all (?:requests|tasks|conversations|sessions)|no matter what|"
    r"before (?:any|every|all) (?:other )?(?:tool|action|response|task|skill|reply)|"
    r"must be (?:used|invoked|loaded|run) (?:first|before)|highest priority|takes? precedence|"
    r"overrides? (?:all )?other|even if the user|do not skip)\b")


def line_of_key(text, key):
    i = text.find('"%s"' % key)
    if i < 0:
        i = text.find(key)
    return T.line_of(text, i) if i >= 0 else 1


def load_jsonc(text):
    """Parse JSON, tolerating // and /* */ comments and trailing commas. Returns (data, error)."""
    if len(text) > MAX_CONFIG_BYTES:
        return None, "too large"
    try:
        return json.loads(text), None
    except (ValueError, RecursionError):
        pass
    if text.count("/*") != text.count("*/"):
        return None, "unbalanced comment"
    tok = re.compile(r"\"(?:\\.|[^\"\\\n]){0,100000}\"|//[^\n]{0,100000}|/\*[\s\S]{0,200000}?\*/|,(?=\s{0,200}[}\]])")
    out, last = [], 0
    for m in tok.finditer(text):
        s = m.group(0)
        out.append(text[last:m.start()])
        if s.startswith('"'):
            out.append(s)
        last = m.end()
    out.append(text[last:])
    try:
        return json.loads("".join(out)), None
    except (ValueError, RecursionError) as exc:
        return None, type(exc).__name__


def _lev(a, b, cap=3):
    if abs(len(a) - len(b)) >= cap:
        return cap
    prev = list(range(len(b) + 1))
    for i, ca in enumerate(a, 1):
        cur = [i]
        for j, cb in enumerate(b, 1):
            cur.append(min(prev[j] + 1, cur[j - 1] + 1, prev[j - 1] + (ca != cb)))
        prev = cur
    return prev[-1]


def _s(v, limit=160):
    return T.sanitize(v if isinstance(v, str) else json.dumps(v, ensure_ascii=True, default=str), limit)


# ---------------------------------------------------------------- frontmatter


def parse_frontmatter(text):
    """Return dict key -> (value, line, continuation_text) for a leading YAML block, or {}."""
    m = _FM_RX.match(text)
    if not m:
        return {}
    out, cur = {}, None
    for idx, ln in enumerate(m.group(1).split("\n")[:400]):
        km = _FM_KEY.match(ln) if ln[:1] not in (" ", "\t", "-", "#") else None
        if km:
            cur = km.group(1)
            out[cur] = [km.group(2).strip(), idx + 2, []]
        elif cur and ln.strip():
            out[cur][2].append(ln)
    res = {}
    for k, (val, line, cont) in out.items():
        if val in ("|", ">", "|-", ">-", "|+", ">+", ""):
            val = " ".join(c.strip() for c in cont)
        elif len(val) >= 2 and val[0] == val[-1] and val[0] in "\"'":
            val = val[1:-1]
        res[k] = (val, line, "\n".join(cont))
    return res


def _tool_list(val, cont):
    items = []
    src = val.strip()
    if src.startswith("[") and src.endswith("]"):
        src = src[1:-1]
    depth, cur = 0, ""
    for ch in src:
        if ch == "(":
            depth += 1
        elif ch == ")":
            depth = max(0, depth - 1)
        if ch == "," and depth == 0:
            items.append(cur)
            cur = ""
        else:
            cur += ch
    items.append(cur)
    for ln in cont.split("\n"):
        ln = ln.strip()
        if ln.startswith("- "):
            items.append(ln[2:])
    return [i.strip().strip("\"'") for i in items if i.strip().strip("\"'")]


_RISKY_BASH = re.compile(
    r"(?i)^bash\((?:curl|wget|rm|sudo|sh|bash|zsh|python[23]?|node|npx|uvx|eval|ssh|scp|nc|ncat|docker|"
    r"powershell|pwsh|cmd|git push|chmod|chown|dd|kill|osascript|open|start|pip|npm|env|export|source)\b")


def scan_skill_file(E, fc, text):
    fm = parse_frontmatter(text)
    is_skill = fc.name == "skill.md"
    if fm:
        shown = []
        for k in ("name", "allowed-tools", "disallowed-tools", "disable-model-invocation", "user-invocable",
                  "context", "agent", "model", "effort", "shell", "background", "paths"):
            if k in fm:
                shown.append("%s=%s" % (k, _s(fm[k][0] or fm[k][2], 80)))
        if shown:
            E.inv("`%s` frontmatter: %s" % (T.sanitize(fc.rel, 120), "; ".join(shown)))
        if "hooks" in fm:
            E.add("HIGH", "skill-frontmatter-hooks", fm["hooks"][1], _s(fm["hooks"][2] or fm["hooks"][0], 160),
                  "frontmatter defines hooks: they register when the skill/agent is invoked and keep running "
                  "for the session; needs explicit user OK")
        if "allowed-tools" in fm:
            val, line, cont = fm["allowed-tools"]
            tools = _tool_list(val, cont)
            broad = [t for t in tools if t in ("Bash", "*", "Bash(*)", "Bash(*:*)", "mcp__*") or t.lower() == "all"]
            risky = [t for t in tools if _RISKY_BASH.match(t) or t in ("Write", "Edit", "MultiEdit", "WebFetch",
                                                                      "NotebookEdit", "Task", "Agent")
                     or t.startswith("mcp__") or t.startswith("WebFetch(")]
            if broad:
                E.add("HIGH", "skill-allowed-tools", line, _s(", ".join(tools), 160),
                      "pre-approves unrestricted tools (%s): commands run without a permission prompt" %
                      _s(", ".join(broad), 60))
            elif risky:
                E.add("MED", "skill-allowed-tools", line, _s(", ".join(tools), 160),
                      "pre-approves side-effect tools (%s)" % _s(", ".join(risky[:6]), 100))
        settings = [k for k in ("context", "agent", "model", "effort", "shell", "background", "paths") if k in fm]
        if settings:
            E.add("LOW", "skill-frontmatter-setting", fm[settings[0]][1],
                  _s("; ".join("%s: %s" % (k, fm[k][0] or fm[k][2]) for k in settings), 160),
                  "frontmatter sets %s (changes how/where the skill runs)" % ", ".join(settings))
        name = fm.get("name", ("", 1, ""))[0].strip()
        if name:
            low = name.lower()
            if low in BUILTIN_NAMES or VENDOR_PREFIX.match(name):
                E.add("MED", "skill-name-shadow", fm["name"][1], _s(name, 80),
                      "name collides with a built-in command/tool name or impersonates a vendor prefix")
            if not name.isascii():
                E.add("MED", "skill-name-shadow", fm["name"][1], _s(name, 80),
                      "non-ASCII characters in the skill name (look-alike names can shadow another skill)")
            if is_skill and fc.parent_name and low != fc.parent_name.lower() and not fc.single_file:
                E.add("LOW", "skill-name-mismatch", fm["name"][1], _s(name, 80),
                      "frontmatter name differs from directory `%s`" % T.sanitize(fc.parent_name, 60))
        desc = " ".join(fm[k][0] for k in ("description", "when_to_use") if k in fm)
        cm = _COERCE.search(desc)
        if cm:
            E.add("MED", "skill-trigger-coercion", fm.get("description", ("", 1, ""))[1], _s(cm.group(0), 80),
                  "description pushes the model to load this skill broadly or with priority")
    hits = list(_BANG_INLINE.finditer(text))[:20]
    sev = "HIGH" if fc.role == "instruction" else "MED"
    for m in hits[:6]:
        E.add(sev, "skill-shell-injection", T.line_of(text, m.start()), _s(m.group(1), 160),
              "inline load-time command: executed when the skill/command loads, before the model sees it")
    if len(hits) > 6:
        E.repeat("skill-shell-injection", len(hits) - 6)
    for m in list(_BANG_FENCE.finditer(text))[:6]:
        E.add(sev, "skill-shell-injection", T.line_of(text, m.start()), "",
              "fenced load-time command block: executed when the skill/command loads")


def scan_memory_imports(E, fc, text):
    for m in list(_AT_IMPORT.finditer(text))[:6]:
        E.add("MED", "repo-memory-import", T.line_of(text, m.start()), _s(m.group(1), 120),
              "instruction file imports a path outside the project into the model context")


# ---------------------------------------------------------------- hooks / MCP


def scan_hooks(E, hooks, text, where, rid="hook-definition"):
    if isinstance(hooks, dict) and isinstance(hooks.get("hooks"), dict) and not (set(hooks) & HOOK_EVENTS):
        hooks = hooks["hooks"]
    if isinstance(hooks, str):
        E.add("HIGH", rid, line_of_key(text, "hooks"), _s(hooks, 120), "%s: hooks loaded from a file" % where)
        return
    if isinstance(hooks, list):
        for h in hooks[:10]:
            scan_hooks(E, h, text, where, rid)
        return
    if not isinstance(hooks, dict):
        return
    n = 0
    for event in sorted(hooks):
        groups = hooks[event]
        if not isinstance(groups, list):
            continue
        for g in groups[:50]:
            if not isinstance(g, dict):
                continue
            handlers = g.get("hooks") if isinstance(g.get("hooks"), list) else [g]
            for h in handlers[:20]:
                if not isinstance(h, dict):
                    continue
                n += 1
                if n > 12:
                    continue
                typ = str(h.get("type", "command"))
                body = h.get("command") or h.get("url") or h.get("prompt") or h.get("tool") or ""
                E.add("HIGH", rid, line_of_key(text, event),
                      _s("%s [%s] %s: %s" % (event, g.get("matcher", "*"), typ, body), 200),
                      "%s: %s hook runs automatically on `%s`; needs explicit user OK" % (
                          where, _s(typ, 20), _s(event, 40)))
    if n > 12:
        E.repeat(rid, n - 12)
    if n:
        E.inv("%s: %d hook handler(s) on events: %s" % (where, n, _s(", ".join(sorted(hooks))[:160], 170)))


def _pkg_from_args(cmd, args):
    base = re.split(r"[\\/]", cmd)[-1].lower() if cmd else ""
    base = re.sub(r"\.(?:cmd|exe|bat|ps1)$", "", base)
    a = [x for x in args if isinstance(x, str)]
    eco = None
    if base in ("npx", "bunx", "pnpx"):
        eco = "npm"
    elif base in ("pnpm", "yarn") and a[:1] == ["dlx"]:
        eco, a = "npm", a[1:]
    elif base == "uvx":
        eco = "pypi"
    elif base == "pipx" and a[:1] == ["run"]:
        eco, a = "pypi", a[1:]
    elif base == "uv" and a[:2] == ["tool", "run"]:
        eco, a = "pypi", a[2:]
    if not eco:
        return None, None
    takes_value = ("-c", "--call", "--with", "--python", "--index-url", "--extra-index-url", "--spec")
    i = 0
    while i < len(a):
        x = a[i]
        if x in ("-p", "--package", "--from") and i + 1 < len(a):
            return eco, a[i + 1]
        if x in takes_value:
            i += 2
            continue
        if x.startswith("-"):
            i += 1
            continue
        return eco, x
    return None, None


def _pinned(eco, spec):
    if spec.startswith((".", "/", "~")) or re.match(r"^[A-Za-z]:[\\/]", spec):
        return True     # local path, not a registry fetch
    if eco == "npm":
        m = re.match(r"^(@[^/@]+/)?[^@]+@(.+)$", spec)
        return bool(m and re.match(r"^\d", m.group(2)))
    if re.search(r"@[0-9a-f]{40}$", spec):
        return True
    return bool(re.search(r"(?:==|@)\d", spec)) and "git+" not in spec


def scan_mcp_servers(E, servers, text, where):
    if not isinstance(servers, dict):
        return
    for name in sorted(servers, key=str)[:200]:
        cfg = servers[name]
        if not isinstance(cfg, dict):
            continue
        line = line_of_key(text, str(name))
        url = cfg.get("url") or cfg.get("serverUrl") or cfg.get("httpUrl")
        cmd = cfg.get("command")
        args = cfg.get("args") if isinstance(cfg.get("args"), list) else []
        env = cfg.get("env") if isinstance(cfg.get("env"), dict) else (
            cfg.get("environment") if isinstance(cfg.get("environment"), dict) else {})
        if isinstance(cmd, list) and cmd:            # opencode: "command": ["npx", "-y", "pkg"]
            cmd, args = str(cmd[0]), [str(a) for a in cmd[1:]] + args
        elif isinstance(cmd, dict):                  # zed: "command": {"path": ..., "args": [...], "env": {...}}
            args = cmd.get("args") if isinstance(cmd.get("args"), list) else args
            env = cmd.get("env") if isinstance(cmd.get("env"), dict) else env
            cmd = cmd.get("path") or cmd.get("command")
        headers = cfg.get("headers") if isinstance(cfg.get("headers"), dict) else {}
        target = url if isinstance(url, str) else " ".join([str(cmd or "")] + [str(a) for a in args][:8])
        E.inv("MCP server `%s` (%s): %s | env keys: %s" % (
            _s(str(name), 60), where, _s(re.sub(r"\?[^\s]*", "?<query>", target), 140),
            _s(", ".join(sorted(map(str, env))) or "none", 120)))
        if isinstance(url, str) and url:
            host = E.host_of(url)
            plain = url.lower().startswith("http://") and host not in ("localhost", "127.0.0.1", "[::1]")
            E.add("HIGH", "mcp-remote-server", line, _s("%s -> %s" % (name, url), 160),
                  "remote MCP server `%s` at host %s%s: tool descriptions and results come from the network "
                  "and can change after approval; needs explicit user OK" % (
                      _s(str(name), 40), _s(host or "?", 60), " over plain HTTP" if plain else ""))
            E.url(url, line, "mcp")
        if isinstance(cmd, str) and cmd:
            joined = " ".join([cmd] + [str(a) for a in args])
            inline = _SHELLS.match(cmd) or any(str(a).lower() in _INLINE_FLAGS for a in args[:3])
            if inline:
                E.add("HIGH", "mcp-shell-command", line, _s(joined, 200),
                      "MCP server `%s` starts through a shell / inline interpreter: arbitrary command at "
                      "agent start-up" % _s(str(name), 40))
            else:
                E.add("MED", "mcp-stdio-server", line, _s(joined, 200),
                      "local MCP server `%s`: this command runs with your user rights each time the agent starts"
                      % _s(str(name), 40))
            eco, spec = _pkg_from_args(cmd, args)
            if spec:
                if not _pinned(eco, spec):
                    E.add("MED", "mcp-unpinned-package", line, _s(spec, 120),
                          "MCP server `%s` runs %s package `%s` without an exact version: what you reviewed is "
                          "not what will run later" % (_s(str(name), 40), eco, _s(spec, 60)))
                scope = spec.split("/")[0].lower() if spec.startswith("@") else ""
                if scope and scope not in KNOWN_SCOPES:
                    near = [k for k in KNOWN_SCOPES if _lev(scope, k) <= 2]
                    if near:
                        E.add("HIGH", "mcp-typosquat", line, _s(spec, 120),
                              "package scope `%s` is within two edits of `%s`" % (_s(scope, 40), near[0]))
            if re.search(r"(?i)\bdocker\b", cmd) and any(
                    re.search(r"(?i):latest$", str(a)) or str(a) in ("--privileged", "--net=host", "--network=host")
                    or "docker.sock" in str(a) for a in args):
                E.add("MED", "mcp-unpinned-package", line, _s(joined, 160),
                      "MCP server container uses :latest, host networking, privileged mode or the Docker socket")
        passed = []
        for k in sorted(map(str, env)):
            v = env.get(k)
            if isinstance(v, str) and (SENSITIVE_ENV.search(k) or re.search(r"\$\{?[A-Za-z_]*(?:TOKEN|SECRET|KEY|"
                                                                           r"PASSWORD)[A-Za-z_]*\}?", v)):
                passed.append(k)
        for k in sorted(map(str, headers)):
            if k.lower() in ("authorization", "x-api-key", "cookie", "proxy-authorization"):
                passed.append("header:" + k)
        if passed:
            E.add("MED", "mcp-env-passthrough", line, _s(", ".join(passed), 160),
                  "MCP server `%s` is handed secret-looking values (names only shown): confirm they belong "
                  "to this server's own service" % _s(str(name), 40))
        if cfg.get("headersHelper"):
            E.add("HIGH", "mcp-shell-command", line, _s(str(cfg["headersHelper"]), 160),
                  "headersHelper runs a shell command to produce request headers")
        if cfg.get("trust") is True:
            E.add("HIGH", "mcp-auto-approve", line, "trust: true",
                  "MCP server `%s` is trusted: every one of its tool calls runs without a confirmation" %
                  _s(str(name), 40))
        elif cfg.get("autoApprove") or cfg.get("alwaysAllow"):
            E.add("MED", "mcp-auto-approve", line, _s(cfg.get("autoApprove") or cfg.get("alwaysAllow")),
                  "MCP server config pre-approves tool calls")


def collect_tool_descriptions(data, limit=400):
    """Find tool-like objects (name + description + schema) and return their description texts."""
    out, stack, seen = [], [data], 0
    while stack and seen < 200_000 and len(out) < limit:
        node = stack.pop()
        seen += 1
        if isinstance(node, dict):
            if (isinstance(node.get("name"), str) and isinstance(node.get("description"), str)
                    and any(k in node for k in ("inputSchema", "input_schema", "parameters", "annotations",
                                                "outputSchema"))):
                texts = [node["description"]]
                sub = [node.get("inputSchema") or node.get("input_schema") or node.get("parameters")]
                steps = 0
                while sub and steps < 2000:
                    s = sub.pop()
                    steps += 1
                    if isinstance(s, dict):
                        for k, v in s.items():
                            if k in ("description", "title", "default", "enum", "examples") and isinstance(v, str):
                                texts.append(v)
                            elif isinstance(v, (dict, list)):
                                sub.append(v)
                    elif isinstance(s, list):
                        sub.extend(x for x in s if isinstance(x, (dict, list, str)))
                    elif isinstance(s, str) and len(s) > 20:
                        texts.append(s)
                out.append((node["name"], "\n".join(texts)))
            stack.extend(v for v in node.values() if isinstance(v, (dict, list)))
        elif isinstance(node, list):
            stack.extend(v for v in node if isinstance(v, (dict, list)))
    return out


# ---------------------------------------------------------------- plugin / marketplace / settings


def scan_plugin_json(E, data, text):
    if not isinstance(data, dict):
        return
    E.inv("plugin manifest: name=%s version=%s components=%s" % (
        _s(str(data.get("name", "?")), 60), _s(str(data.get("version", "?")), 30),
        _s(", ".join(k for k in ("skills", "commands", "agents", "hooks", "mcpServers", "lspServers",
                                 "outputStyles", "workflows", "channels", "dependencies", "userConfig",
                                 "experimental") if k in data) or "defaults only", 160)))
    name = str(data.get("name", ""))
    if VENDOR_PREFIX.match(name):
        E.add("MED", "skill-name-shadow", line_of_key(text, "name"), _s(name, 80),
              "plugin name uses a vendor-reserved prefix")
    if "hooks" in data:
        scan_hooks(E, data["hooks"], text, "plugin.json", "hook-definition")
    if "mcpServers" in data:
        ms = data["mcpServers"]
        if isinstance(ms, dict):
            scan_mcp_servers(E, ms.get("mcpServers", ms) if isinstance(ms.get("mcpServers", ms), dict) else ms,
                             text, "plugin.json")
        else:
            sev = "HIGH" if isinstance(ms, str) and ms.lower().startswith("http") else "MED"
            E.add(sev, "plugin-manifest", line_of_key(text, "mcpServers"), _s(ms, 160),
                  "plugin loads MCP servers from %s" % ("a remote bundle URL" if sev == "HIGH" else "a file"))
    if "lspServers" in data:
        E.add("MED", "plugin-manifest", line_of_key(text, "lspServers"), _s(data["lspServers"], 160),
              "plugin starts language-server processes (run outside the sandbox)")
    exp = data.get("experimental")
    if isinstance(exp, dict) and exp.get("monitors"):
        E.add("HIGH", "plugin-manifest", line_of_key(text, "monitors"), _s(exp["monitors"], 160),
              "plugin monitors run shell commands in the background, outside the sandbox")
    if data.get("channels"):
        E.add("MED", "plugin-manifest", line_of_key(text, "channels"), _s(data["channels"], 120),
              "plugin declares channels (inbound messages into the session)")
    if data.get("dependencies"):
        E.add("LOW", "plugin-manifest", line_of_key(text, "dependencies"), _s(data["dependencies"], 120),
              "plugin pulls in other plugins as dependencies")
    for key in ("skills", "commands", "agents", "hooks", "mcpServers", "lspServers", "outputStyles", "workflows"):
        v = data.get(key)
        paths = [v] if isinstance(v, str) else [p for p in v if isinstance(p, str)] if isinstance(v, list) else []
        for p in paths[:50]:
            if p.lower().startswith(("http://", "https://")):
                continue
            norm = p.replace("\\", "/")
            if ".." in norm.split("/") or norm.startswith(("/", "~")) or re.match(r"^[A-Za-z]:", norm):
                E.add("HIGH", "plugin-path-escape", line_of_key(text, key), _s(p, 120),
                      "component path `%s` points outside the plugin directory" % key)


def scan_marketplace_json(E, data, text):
    plugins = data.get("plugins") if isinstance(data, dict) else None
    if not isinstance(plugins, list):
        return
    E.inv("marketplace manifest: %d plugin entr%s" % (len(plugins), "y" if len(plugins) == 1 else "ies"))
    for p in plugins[:300]:
        if not isinstance(p, dict):
            continue
        name = _s(str(p.get("name", "?")), 60)
        src = p.get("source")
        line = line_of_key(text, str(p.get("name", "source")))
        if isinstance(src, str):
            norm = src.replace("\\", "/")
            if ".." in norm.split("/") or not norm.startswith("./"):
                E.add("HIGH" if ".." in norm.split("/") else "MED", "marketplace-source", line, _s(src, 120),
                      "plugin `%s`: relative source should start with ./ and stay inside the marketplace" % name)
        elif isinstance(src, dict):
            kind = str(src.get("source", "")).lower()
            if kind == "command":
                E.add("HIGH", "marketplace-source", line, _s(src.get("command", ""), 160),
                      "plugin `%s`: `command` source runs a shell command on your machine to fetch the plugin"
                      % name)
            elif kind in ("github", "url", "git-subdir", "git"):
                if not re.match(r"^[0-9a-f]{40}$", str(src.get("sha", ""))):
                    E.add("MED", "marketplace-source", line, _s(src, 160),
                          "plugin `%s`: git source without a full commit sha (a branch/tag can be moved after "
                          "review)" % name)
                u = str(src.get("url", ""))
                if u.lower().startswith(("http://", "git://")):
                    E.add("HIGH", "marketplace-source", line, _s(u, 120),
                          "plugin `%s`: source fetched over an unauthenticated transport" % name)
            elif kind == "npm":
                if not re.match(r"^\d", str(src.get("version", ""))) or src.get("registry"):
                    E.add("MED", "marketplace-source", line, _s(src, 160),
                          "plugin `%s`: npm source without an exact version, or from a custom registry" % name)
            elif kind == "archive":
                u = str(src.get("url", ""))
                sev = "HIGH" if u.lower().startswith("http://") else ("MED" if not src.get("sha256") else None)
                if sev:
                    E.add(sev, "marketplace-source", line, _s(src, 160),
                          "plugin `%s`: archive source without sha256 pin or over plain HTTP" % name)
        if p.get("headersHelper"):
            E.add("HIGH", "marketplace-source", line, _s(p["headersHelper"], 160),
                  "plugin `%s`: headersHelper runs a shell command" % name)
        for key in ("hooks", "mcpServers"):
            if key in p:
                if key == "hooks":
                    scan_hooks(E, p[key], text, "marketplace entry `%s`" % name)
                elif isinstance(p[key], dict):
                    scan_mcp_servers(E, p[key], text, "marketplace entry `%s`" % name)


_BROAD_ALLOW = re.compile(r"^(?:\*|Bash|Bash\(\*\)|Bash\(\*:\*\)|Write|Edit|MultiEdit|WebFetch|WebFetch\(domain:\*\)|"
                          r"mcp__\*|Read\((?:~|/|\*\*)[^)]{0,10}\)|Read|Shell|Shell\(\*{1,2}(?::\*)?\)|"
                          r"Write\(\*{1,2}[^)]{0,10}\)|run_shell_command|ShellTool)$")
# Other agents' project config files that can start MCP servers, widen permissions or load instructions.
AGENT_CONFIG_RX = re.compile(
    r"(?:^|/)(?:\.gemini/settings\.json|\.qwen/settings\.json|\.zed/settings\.json|\.cursor/cli\.json|"
    r"\.cursor/cli-config\.json|(?:\.opencode/)?opencode\.jsonc?|\.?crush\.json|\.amazonq/(?:mcp|default)\.json|"
    r"\.continue/config\.json|\.kiro/settings/[\w.-]{1,60}\.json|\.roo/[\w.-]{1,60}\.json|\.windsurf/[\w.-]{1,60}\.json|"
    r"\.codeium/[\w.-]{1,60}\.json|\.junie/[\w.-]{1,60}\.json|\.augment/[\w.-]{1,60}\.json)$")
_BYPASS_KEYS = ("autoAccept", "yolo", "always_allow_tool_actions", "dangerouslySkipPermissions", "skipPermissions",
                "autoApproveAll", "auto_approve", "dangerously_skip_permissions", "bypassPermissions")


def scan_settings(E, data, text, where):
    if not isinstance(data, dict):
        return
    if "hooks" in data:
        scan_hooks(E, data["hooks"], text, where, "settings-hooks")
    perms = data.get("permissions") if isinstance(data.get("permissions"), dict) else {}
    allow = [a for a in perms.get("allow", []) if isinstance(a, str)] if isinstance(perms.get("allow"), list) else []
    broad = [a for a in allow if _BROAD_ALLOW.match(a)]
    risky = [a for a in allow if _RISKY_BASH.match(a) and a not in broad]
    if broad:
        E.add("HIGH", "settings-permissions", line_of_key(text, "allow"), _s(", ".join(broad), 160),
              "%s: blanket allow rule(s) remove permission prompts for whole tools" % where)
    if risky:
        E.add("MED", "settings-permissions", line_of_key(text, "allow"), _s(", ".join(risky[:8]), 160),
              "%s: allow rule(s) pre-approve powerful shell commands" % where)
    mode = perms.get("defaultMode")
    if isinstance(mode, str):
        if mode in ("bypassPermissions", "dontAsk", "auto"):
            E.add("HIGH", "settings-permissions", line_of_key(text, "defaultMode"), _s(mode, 40),
                  "%s: permission mode `%s` removes or automates approval" % (where, _s(mode, 30)))
        elif mode == "acceptEdits":
            E.add("MED", "settings-permissions", line_of_key(text, "defaultMode"), mode,
                  "%s: file edits are accepted without a prompt" % where)
    dirs = perms.get("additionalDirectories")
    if isinstance(dirs, list) and dirs:
        wide = [d for d in dirs if isinstance(d, str) and (d in ("/", "~", "~/") or d.startswith(("..", "/", "~"))
                                                           or re.match(r"^[A-Za-z]:[\\/]?$", d))]
        E.add("HIGH" if wide else "MED", "settings-permissions", line_of_key(text, "additionalDirectories"),
              _s(", ".join(map(str, dirs[:6])), 160),
              "%s: extends file access to additional directories" % where)
    for k in COMMAND_KEYS:
        if data.get(k):
            E.add("HIGH", "settings-command-key", line_of_key(text, k), _s(data[k], 160),
                  "%s: `%s` executes a command with your user rights" % (where, k))
    env = data.get("env") if isinstance(data.get("env"), dict) else {}
    hot = sorted(k for k in map(str, env) if REDIRECT_ENV.match(k))
    if hot:
        detail = []
        for k in hot[:8]:
            v = str(env.get(k, ""))
            detail.append("%s -> %s" % (k, E.host_of(v) or "(value hidden)") if "://" in v else k)
        E.add("HIGH", "settings-env", line_of_key(text, hot[0]), _s(", ".join(detail), 200),
              "%s: overrides %s (can redirect API traffic, proxies, TLS trust, interpreter start-up or PATH)" % (
                  where, _s(", ".join(hot[:4]), 100)))
    elif env:
        E.inv("%s env keys: %s" % (where, _s(", ".join(sorted(map(str, env))[:20]), 200)))
    if data.get("enableAllProjectMcpServers") is True:
        E.add("HIGH", "settings-mcp-autoenable", line_of_key(text, "enableAllProjectMcpServers"),
              "enableAllProjectMcpServers: true", "%s: every MCP server in the project config is auto-approved" % where)
    if data.get("enabledMcpjsonServers"):
        E.add("MED", "settings-mcp-autoenable", line_of_key(text, "enabledMcpjsonServers"),
              _s(data["enabledMcpjsonServers"], 120), "%s: pre-approves named project MCP servers" % where)
    if data.get("extraKnownMarketplaces") or data.get("enabledPlugins"):
        E.add("MED", "settings-mcp-autoenable", line_of_key(text, "extraKnownMarketplaces"),
              _s(data.get("extraKnownMarketplaces") or data.get("enabledPlugins"), 160),
              "%s: registers plugin marketplaces / enables plugins for everyone who trusts this folder" % where)
    sb = data.get("sandbox") if isinstance(data.get("sandbox"), dict) else {}
    weak = []
    if sb.get("enabled") is False:
        weak.append("enabled=false")
    if sb.get("allowUnsandboxedCommands") is True:
        weak.append("allowUnsandboxedCommands=true")
    if sb.get("excludedCommands"):
        weak.append("excludedCommands")
    net = sb.get("network") if isinstance(sb.get("network"), dict) else {}
    if any(isinstance(d, str) and d.strip() in ("*", "*.*") for d in net.get("allowedDomains", []) or []):
        weak.append("network.allowedDomains=*")
    if weak:
        E.add("HIGH", "settings-sandbox", line_of_key(text, "sandbox"), _s(", ".join(weak), 120),
              "%s: sandbox is disabled or widened" % where)
    if data.get("skipDangerousModePermissionPrompt") is True or data.get("disableSkillShellExecution") is False:
        E.add("MED", "settings-permissions", 1, "",
              "%s: suppresses a safety prompt / explicitly keeps skill shell execution on" % where)
    if isinstance(data.get("mcpServers"), dict):
        scan_mcp_servers(E, data["mcpServers"], text, where)


def _walk_keys(data, depth=0):
    """(key, value) pairs of nested dicts, bounded."""
    if depth > 6 or not isinstance(data, dict):
        return
    for i, (k, v) in enumerate(data.items()):
        if i > 400:
            return
        yield str(k), v
        if isinstance(v, dict):
            yield from _walk_keys(v, depth + 1)


def scan_agent_config(E, data, text, where):
    """Project config of Gemini CLI, Qwen Code, Zed, Cursor CLI, opencode, Crush, Amazon Q, Continue,
    Kiro, Roo and similar agents: MCP servers, permission bypasses and allow rules, instructions loaded
    from elsewhere, hooks."""
    if not isinstance(data, dict):
        return
    for key in ("mcpServers", "servers", "mcp", "context_servers", "mcp_servers"):
        srv = data.get(key)
        if isinstance(srv, dict) and srv and all(isinstance(v, dict) for v in srv.values()):
            scan_mcp_servers(E, srv, text, where)
    for k, v in _walk_keys(data):
        if k in _BYPASS_KEYS and v is True:
            E.add("HIGH", "settings-permissions", line_of_key(text, k), "%s: true" % _s(k, 40),
                  "%s: `%s` lets the agent act without asking (permission prompts off)" % (where, _s(k, 40)))
        elif k in ("approvalMode", "approval_mode", "approval_policy") and isinstance(v, str) and v.lower() in (
                "yolo", "never", "auto", "full-auto", "autoedit", "auto_edit"):
            E.add("HIGH", "settings-permissions", line_of_key(text, k), "%s: %s" % (_s(k, 30), _s(v, 30)),
                  "%s: approval mode `%s` removes or automates approval" % (where, _s(v, 30)))
    perms = data.get("permissions") if isinstance(data.get("permissions"), dict) else None
    if perms is not None:
        allow = [a for a in perms.get("allow", []) if isinstance(a, str)] if isinstance(perms.get("allow"), list) else []
        broad = [a for a in allow if _BROAD_ALLOW.match(a)]
        if broad:
            E.add("HIGH", "settings-permissions", line_of_key(text, "allow"), _s(", ".join(broad), 160),
                  "%s: blanket allow rule(s) remove permission prompts for whole tools" % where)
        elif allow:
            E.add("MED", "settings-permissions", line_of_key(text, "allow"), _s(", ".join(allow[:8]), 160),
                  "%s: allow rule(s) pre-approve tool use" % where)
    perm = data.get("permission")
    if isinstance(perm, dict):                       # opencode: {"bash": "allow", "edit": "allow", ...}
        loose = sorted(str(k) for k, v in perm.items() if v == "allow" or (isinstance(v, dict) and (
            v.get("*") == "allow")))
        if loose:
            hot = [k for k in loose if k in ("bash", "shell", "webfetch", "*", "external_directory")]
            E.add("HIGH" if hot else "MED", "settings-permissions", line_of_key(text, "permission"),
                  _s(", ".join(loose), 120), "%s: permission set to `allow` for %s (no prompt)" % (
                      where, _s(", ".join(loose), 80)))
    elif perm == "allow":
        E.add("HIGH", "settings-permissions", line_of_key(text, "permission"), "permission: allow",
              "%s: every tool is allowed without a prompt" % where)
    instr = data.get("instructions") or data.get("contextFileName") or data.get("rules")
    items = instr if isinstance(instr, list) else [instr] if isinstance(instr, str) else []
    remote = [i for i in items if isinstance(i, str) and re.match(r"(?i)^(?:https?|ftp)://", i.strip())]
    outside = [i for i in items if isinstance(i, str) and i not in remote and (
        i.startswith(("/", "~", "..")) or re.match(r"^[A-Za-z]:[\\/]", i))]
    if remote:
        E.add("HIGH", "cfg-remote-instructions", line_of_key(text, "instructions"), _s(", ".join(remote[:4]), 160),
              "%s: the agent loads its instructions from the network: they can change at any time and were "
              "not part of this review" % where)
        for u in remote[:20]:
            E.url(u, line_of_key(text, "instructions"), "config")
    if outside:
        E.add("MED", "cfg-remote-instructions", line_of_key(text, "instructions"), _s(", ".join(outside[:4]), 160),
              "%s: the agent loads instruction files from outside the project" % where)
    if isinstance(data.get("hooks"), dict) and data["hooks"]:
        scan_hooks(E, data["hooks"], text, where, "settings-hooks")
    env = data.get("env") if isinstance(data.get("env"), dict) else {}
    hot = sorted(k for k in map(str, env) if REDIRECT_ENV.match(k))
    if hot:
        E.add("HIGH", "settings-env", line_of_key(text, hot[0]), _s(", ".join(hot[:6]), 160),
              "%s: overrides %s" % (where, _s(", ".join(hot[:4]), 100)))


# ---------------------------------------------------------------- package / build files

_NONREG = re.compile(r"(?i)^(?:git\+|git://|https?://|file:|github:|gitlab:|bitbucket:|[\w.-]+/[\w.-]+(?:#.*)?$)")


def scan_package_json(E, data, text):
    if not isinstance(data, dict):
        return
    scripts = data.get("scripts") if isinstance(data.get("scripts"), dict) else {}
    for k in LIFECYCLE:
        if isinstance(scripts.get(k), str):
            E.add("MED", "pkg-lifecycle-script", line_of_key(text, k), _s("%s: %s" % (k, scripts[k]), 200),
                  "`%s` runs automatically during install/publish with your user rights" % k)
    n = 0
    for sect in ("dependencies", "devDependencies", "optionalDependencies", "peerDependencies"):
        deps = data.get(sect) if isinstance(data.get(sect), dict) else {}
        for name in sorted(deps, key=str):
            v = deps[name]
            if isinstance(v, str) and _NONREG.match(v) and not v.startswith(("workspace:", "npm:")):
                n += 1
                if n <= 3:
                    E.add("MED", "pkg-nonregistry-dep", line_of_key(text, str(name)), _s("%s: %s" % (name, v), 160),
                          "dependency is fetched from git/URL/path, not a versioned registry release")
    if n > 3:
        E.repeat("pkg-nonregistry-dep", n - 3)
    for key in ("husky", "simple-git-hooks", "pre-commit", "lint-staged"):
        if key in data and key != "lint-staged":
            E.add("MED", "repo-git-hook", line_of_key(text, key), _s(data[key], 160),
                  "package.json configures git hooks (`%s`)" % key)
    deps_all = " ".join(str(k) for s in ("dependencies", "devDependencies") if isinstance(data.get(s), dict)
                        for k in data[s])
    if "@modelcontextprotocol/sdk" in deps_all or "fastmcp" in deps_all:
        E.inv("package.json depends on an MCP SDK (this is an MCP server/client project)")


_PY_BACKENDS = ("setuptools.build_meta", "hatchling.build", "flit_core.buildapi", "poetry.core.masonry.api",
                "pdm.backend", "maturin", "scikit_build_core.build", "mesonpy", "uv_build", "flit.buildapi",
                "setuptools.build_meta:__legacy__", "poetry_dynamic_versioning.backend", "hatchling.ouroboros")


def scan_pyproject(E, text):
    m = re.search(r"(?m)^[ \t]{0,4}build-backend[ \t]{0,4}=[ \t]{0,4}[\"']([^\"'\n]{1,120})[\"']", text)
    if m and m.group(1) not in _PY_BACKENDS:
        E.add("MED", "py-build-hook", T.line_of(text, m.start()), _s(m.group(1), 100),
              "uncommon build backend: it is imported and run at build/install time")
    m = re.search(r"(?m)^[ \t]{0,4}backend-path[ \t]{0,4}=", text)
    if m:
        E.add("MED", "py-build-hook", T.line_of(text, m.start()), "backend-path",
              "in-tree build backend: project code runs at build/install time")
    for rx, note in ((r"(?m)^\[tool\.hatch\.build\.hooks\.custom\]", "custom hatch build hook"),
                     (r"(?m)^\[tool\.setuptools\.cmdclass\]", "setuptools cmdclass override"),
                     (r"(?m)^\[tool\.poetry\.build\]", "poetry build script"),
                     (r"(?m)^\[tool\.pdm\.build\][^\[]{0,400}run-setuptools", "pdm run-setuptools")):
        mm = re.search(rx, text)
        if mm:
            E.add("MED", "py-build-hook", T.line_of(text, mm.start()), note, "%s executes project code at build time" % note)
    mm = re.search(r"(?m)^[^#\n]{0,200}@\s{0,3}(?:git\+|https?://)", text)
    if mm:
        E.add("MED", "pkg-nonregistry-dep", T.line_of(text, mm.start()), _s(mm.group(0), 140),
              "dependency is fetched from git/URL, not a versioned registry release")


_SETUP_EXEC = re.compile(r"(?i)\b(?:urllib|requests|socket|http\.client|base64|exec\s?\(|eval\s?\(|os\.system|"
                         r"subprocess|ctypes|marshal|zlib\.decompress)\b")
_SETUP_CMD = re.compile(r"(?m)^class\s{1,3}\w{1,60}\((?:[\w.]{0,40}\.)?(?:install|develop|build_py|egg_info|sdist|"
                        r"bdist_wheel|build_ext|build)\)|cmdclass\s{0,3}=")


def scan_setup_py(E, text):
    exec_m = _SETUP_EXEC.search(text)
    cmd_m = _SETUP_CMD.search(text)
    if exec_m and re.search(r"(?i)urllib|requests|socket|http\.client|base64|exec\s?\(|eval\s?\(|marshal|zlib",
                            text):
        E.add("HIGH", "py-build-hook", T.line_of(text, exec_m.start()), _s(exec_m.group(0), 60),
              "setup.py uses network, decoding or dynamic execution: it runs at install time")
    elif cmd_m or exec_m:
        mm = cmd_m or exec_m
        E.add("MED", "py-build-hook", T.line_of(text, mm.start()), _s(mm.group(0), 80),
              "setup.py customizes install commands or spawns processes at install time")
    else:
        E.add("LOW", "py-build-hook", 1, "", "setup.py is executed by pip at build/install time")


def scan_requirements(E, text):
    for m in list(re.finditer(r"(?m)^[ \t]{0,4}(?:-i|--index-url|--extra-index-url|--find-links|-f|"
                              r"--trusted-host)[ \t=]{1,4}(\S{1,300})", text))[:3]:
        if "pypi.org" not in m.group(1):
            E.add("MED", "pkg-nonregistry-dep", T.line_of(text, m.start()), _s(m.group(0), 140),
                  "requirements file changes the package index (dependency-confusion risk)")
    m = re.search(r"(?m)^[^#\n]{0,200}(?:git\+|https?://)\S{1,300}", text)
    if m:
        E.add("MED", "pkg-nonregistry-dep", T.line_of(text, m.start()), _s(m.group(0), 140),
              "requirement fetched from git/URL")


# ---------------------------------------------------------------- CI / devcontainer / misc


def scan_workflow(E, text):
    low = text.lower()
    if "pull_request_target" in low and re.search(
            r"(?i)ref\s{0,3}:\s{0,3}[\"']?\$\{\{\s{0,3}github\.(?:event\.pull_request\.head|head_ref)", text):
        i = low.find("pull_request_target")
        E.add("HIGH", "ci-workflow", T.line_of(text, i), "pull_request_target + checkout of PR head",
              "workflow runs untrusted pull-request code with repository secrets")
    m = re.search(r"(?i)\$\{\{\s{0,3}github\.(?:event\.(?:issue|pull_request|comment|review|head_commit|discussion|"
                  r"pages)[\w.\[\]'\"]{0,60}(?:title|body|message|name|label|ref|email)|head_ref)\s{0,3}\}\}", text)
    if m and re.search(r"(?m)^\s{0,40}(?:-\s{1,3})?run\s{0,3}:", text):
        E.add("MED", "ci-workflow", T.line_of(text, m.start()), _s(m.group(0), 120),
              "attacker-controlled event text is interpolated into a workflow (script injection if used in run:)")
    m = re.search(r"(?im)^\s{0,40}permissions\s{0,3}:\s{0,3}write-all", text)
    if m:
        E.add("MED", "ci-workflow", T.line_of(text, m.start()), "permissions: write-all",
              "workflow token has write access to everything")
    m = re.search(r"(?i)(?:echo|printf|curl|wget)[^\n]{0,160}\$\{\{\s{0,3}secrets\.[A-Za-z0-9_]{1,80}", text)
    if m and re.search(r"(?i)(?:echo|printf)\s", m.group(0)[:12]) is not None:
        E.add("HIGH", "ci-workflow", T.line_of(text, m.start()), _s(m.group(0), 140),
              "workflow prints a secret")
    floating, first = 0, None
    for mm in re.finditer(r"(?im)^\s{0,40}(?:-\s{1,3})?uses\s{0,3}:\s{0,3}[\"']?([\w.-]{1,80}/[\w./-]{1,120})@"
                          r"([\w./-]{1,80})", text):
        owner = mm.group(1).split("/")[0].lower()
        if owner in ("actions", "github") or re.match(r"^[0-9a-f]{40}$", mm.group(2)):
            continue
        floating += 1
        first = mm if first is None else first
        if floating > 200:
            break
    if floating:
        branch = bool(re.match(r"(?i)^(?:main|master|head|latest|dev|develop)$", first.group(2)))
        E.add("MED" if branch else "LOW", "ci-workflow", T.line_of(text, first.start()),
              _s(first.group(1) + "@" + first.group(2), 120),
              "%d third-party action(s) not pinned to a commit sha" % floating)


def scan_devcontainer(E, data, text):
    if not isinstance(data, dict):
        return
    if data.get("initializeCommand"):
        E.add("HIGH", "devcontainer-command", line_of_key(text, "initializeCommand"),
              _s(data["initializeCommand"], 160), "initializeCommand runs on the HOST machine before the container starts")
    for k in ("onCreateCommand", "updateContentCommand", "postCreateCommand", "postStartCommand",
              "postAttachCommand"):
        if data.get(k):
            E.add("MED", "devcontainer-command", line_of_key(text, k), _s("%s: %s" % (k, _s(data[k], 140)), 180),
                  "%s runs automatically inside the dev container" % k)
    blob = json.dumps([data.get("mounts"), data.get("runArgs"), data.get("workspaceMount")], default=str).lower()
    if any(x in blob for x in ("docker.sock", "--privileged", "--cap-add", "localenv:home", "localenv:userprofile",
                               ".ssh", "source=/,", "--pid=host", "--network=host")):
        E.add("HIGH", "devcontainer-command", line_of_key(text, "mounts"), _s(blob, 160),
              "dev container mounts host secrets / Docker socket or runs privileged")
    envs = json.dumps([data.get("remoteEnv"), data.get("containerEnv")], default=str)
    if "${localEnv:" in envs:
        E.add("MED", "devcontainer-command", line_of_key(text, "remoteEnv"),
              _s(", ".join(sorted(set(re.findall(r"\$\{localEnv:([A-Za-z0-9_]{1,60})", envs)))[:8]), 160),
              "dev container copies host environment variables (names shown) into the container")


_GIT_EXEC_KEYS = re.compile(
    r"(?im)^\s{0,8}(fsmonitor|sshcommand|hookspath|pager|editor|askpass|gpgprogram|program|helper|textconv|"
    r"clean|smudge|process|driver|command|insteadof|pushinsteadof|path)\s{0,3}=\s{0,3}(\S[^\n]{0,200})")


def scan_git_config(E, text):
    for m in list(_GIT_EXEC_KEYS.finditer(text))[:8]:
        key = m.group(1).lower()
        val = m.group(2)
        if key in ("pager", "editor") and val.strip() in ("less", "more", "cat", "vim", "vi", "nano"):
            continue
        E.add("HIGH", "repo-git-config", T.line_of(text, m.start()), _s("%s = %s" % (key, val), 160),
              "a copied .git/config with `%s` makes git run a command or rewrite URLs" % key)
    for m in list(re.finditer(r"(?m)^\s{0,8}\w[\w-]{0,40}\s{0,3}=\s{0,3}!(\S[^\n]{0,160})", text))[:4]:
        E.add("HIGH", "repo-git-config", T.line_of(text, m.start()), _s(m.group(0), 160),
              "git alias that runs a shell command")


def scan_gitmodules(E, text):
    for m in list(re.finditer(r"(?m)^\s{0,8}url\s{0,3}=\s{0,3}(\S{1,400})", text))[:20]:
        u = m.group(1)
        bad = u.startswith(("ext::", "file://", "-", "../", "fd::")) or u.lower().startswith(("http://", "git://"))
        E.add("HIGH" if bad else "LOW", "repo-submodule", T.line_of(text, m.start()), _s(u, 140),
              "submodule URL%s" % (" uses a dangerous or unauthenticated transport" if bad else
                                   " (fetched code is not part of this scan)"))


# Files that tooling runs or loads automatically. (path regex, severity, note, optional content regex)
SPECIAL_FILES = (
    (r"(?:^|/)\.envrc$", "MED", "direnv file: executed when you enter the directory (if direnv is allowed)", None),
    (r"(?:^|/)\.npmrc$", "MED", ".npmrc changes registry or script settings",
     r"(?im)^\s{0,4}(?:registry|@[\w-]{1,60}:registry|script-shell|ignore-scripts\s{0,3}=\s{0,3}false|//[^\n]{1,200}:_auth)"),
    (r"(?:^|/)\.yarnrc\.yml$", "HIGH", ".yarnrc.yml yarnPath/plugins: yarn executes the referenced file",
     r"(?im)^\s{0,4}(?:yarnpath|plugins)\s{0,3}:"),
    (r"(?:^|/)\.yarnrc$", "HIGH", ".yarnrc yarn-path: yarn executes the referenced file", r"(?im)^\s{0,4}yarn-path\b"),
    (r"(?:^|/)\.pnpmfile\.c?js$", "MED", "pnpmfile hooks run on every install", None),
    (r"(?:^|/)bunfig\.toml$", "MED", "bunfig preload executes code at start-up", r"(?im)^\s{0,4}preload\s{0,3}="),
    (r"(?:^|/)\.cargo/config(?:\.toml)?$", "MED", "cargo config overrides runner / rustc wrapper / linker",
     r"(?im)^\s{0,4}(?:runner|rustc-wrapper|rustc|linker)\s{0,3}="),
    (r"(?:^|/)gradle/wrapper/gradle-wrapper\.properties$", "HIGH",
     "gradle wrapper downloads its distribution from a non-official host",
     r"(?im)^\s{0,4}distributionurl\s{0,3}=\s{0,3}(?!https\\?://services\.gradle\.org/)"),
    (r"(?:^|/)\.mvn/wrapper/maven-wrapper\.properties$", "HIGH",
     "maven wrapper downloads from a non-official host",
     r"(?im)^\s{0,4}(?:distributionurl|wrapperurl)\s{0,3}=\s{0,3}(?!https\\?://repo\.maven\.apache\.org/)"),
    (r"(?:^|/)\.vscode/tasks\.json$", "HIGH", "VS Code task runs automatically when the folder opens",
     r"(?i)\"runon\"\s{0,3}:\s{0,3}\"folderopen\""),
    (r"(?:^|/)\.vscode/settings\.json$", "HIGH", "workspace settings auto-approve agent tools or redirect interpreters",
     r"(?i)autoapprove\"?\s{0,3}:\s{0,3}(?:true|\{|\[)|\"task\.allowautomatictasks\"\s{0,3}:\s{0,3}\"on\"|"
     r"terminal\.integrated\.(?:automationprofile|profiles)|\"python\.defaultinterpreterpath\"|\"git\.path\""),
    (r"(?:^|/)\.aider\.conf\.ya?ml$", "MED", "aider config auto-confirms or auto-loads files",
     r"(?im)^\s{0,4}(?:yes-always|auto-commits|read|load)\s{0,3}:"),
    (r"(?:^|/)\.codex/config\.toml$", "HIGH", "Codex config removes approvals or the sandbox",
     r"(?i)approval_policy\s{0,3}=\s{0,3}\"never\"|sandbox_mode\s{0,3}=\s{0,3}\"danger-full-access\""),
    (r"(?:^|/)\.cursor/environment\.json$", "MED", "Cursor environment install/start commands", None),
    (r"(?:^|/)\.gitpod\.yml$", "MED", "Gitpod tasks run automatically in the workspace", None),
    (r"(?:^|/)(?:flake|shell)\.nix$", "MED", "nix shellHook runs when the dev shell starts", r"(?i)shellhook"),
    (r"(?:^|/)(?:\.mise|mise)\.toml$", "MED", "mise hooks/tasks/env scripts run automatically",
     r"(?im)^\[(?:hooks|tasks)|_\.source|_\.file"),
    (r"(?:^|/)composer\.json$", "MED", "composer scripts run on install/update",
     r"(?i)\"(?:pre|post)-(?:install|update|autoload-dump)-cmd\""),
    (r"(?:^|/)\.pre-commit-config\.ya?ml$", "MED", "pre-commit local hook runs project commands on commit",
     r"(?im)^\s{0,8}-?\s{0,3}repo\s{0,3}:\s{0,3}local"),
    (r"(?:^|/)(?:\.?lefthook(?:-local)?|\.overcommit)\.ya?ml$", "MED", "git hook manager config", None),
    (r"(?:^|/)\.husky/(?!_/)[^/]+$", "MED", "husky git hook script", None),
    (r"(?:^|/)\.githooks/[^/]+$", "MED", "git hook script (active if core.hooksPath points here)", None),
    (r"(?:^|/)docker-compose[\w.-]{0,30}\.ya?ml$|(?:^|/)compose\.ya?ml$", "HIGH",
     "compose service runs privileged or mounts the host",
     r"(?im)privileged\s{0,3}:\s{0,3}true|/var/run/docker\.sock|network_mode\s{0,3}:\s{0,3}[\"']?host|"
     r"pid\s{0,3}:\s{0,3}[\"']?host|^\s{0,12}-\s{0,3}[\"']?(?:/|~/?|\$home/?):/"),
)
_SPECIAL = tuple((re.compile(p), sev, note, re.compile(c) if c else None) for p, sev, note, c in SPECIAL_FILES)
_HOOKISH = re.compile(r"(?:^|/)(?:\.husky/|\.githooks/|\.pre-commit-config|\.?lefthook|\.overcommit)")


def scan_special(E, fc, text):
    for prx, sev, note, crx in _SPECIAL:
        if not prx.search(fc.rel_lower):
            continue
        m = crx.search(text) if crx else None
        if crx and not m:
            continue
        rid = "repo-git-hook" if _HOOKISH.search(fc.rel_lower) else (
            "container-privileged" if "compose" in fc.name else "repo-autoexec-file")
        E.add(sev, rid, T.line_of(text, m.start()) if m else 1, _s(m.group(0), 140) if m else "", note)


def analyze(E, fc, text):
    """Dispatch structure-aware checks for one text file."""
    name, rel = fc.name, fc.rel_lower
    if fc.is_md_like:
        if fc.role == "instruction" or name == "skill.md" or text.startswith("---"):
            scan_skill_file(E, fc, text)
        if fc.autoload:
            scan_memory_imports(E, fc, text)
    if name.endswith((".json", ".jsonc", ".json5", ".mcp.json")) or name in (".mcp.json", ".claude.json"):
        if len(text) <= MAX_CONFIG_BYTES and ("{" in text[:2000] or "[" in text[:2000]):
            data, err = load_jsonc(text)
            if err:
                keys = ("mcpServers", "hooks", "permissions", "postCreateCommand", "initializeCommand", "scripts")
                if any('"%s"' % k in text for k in keys):
                    E.add("MED", "config-parse-error", 1, "", "JSON did not parse (%s): structured checks skipped, "
                          "plain-text rules still applied" % err)
            elif isinstance(data, (dict, list)):
                _json_checks(E, fc, data, text)
    if name == "pyproject.toml":
        scan_pyproject(E, text)
    elif name == "setup.py":
        scan_setup_py(E, text)
    elif re.match(r"^requirements[\w.-]{0,40}\.txt$", name):
        scan_requirements(E, text)
    elif name.endswith(".pth") and re.search(r"(?m)^\s{0,4}import\s", text):
        E.add("HIGH", "py-startup-file", 1, _s(text[:120], 120),
              ".pth file with an import line: executed by every Python start-up once installed")
    elif name in ("sitecustomize.py", "usercustomize.py"):
        E.add("HIGH", "py-startup-file", 1, "", "%s is imported automatically at Python start-up" % name)
    elif name == ".gitmodules":
        scan_gitmodules(E, text)
    elif rel.endswith(".git/config"):
        scan_git_config(E, text)
    if re.search(r"(?:^|/)\.github/workflows/[^/]+\.ya?ml$", rel):
        scan_workflow(E, text)
    if name == "dockerfile" or name.startswith("dockerfile.") or name.endswith(".dockerfile"):
        m = re.search(r"(?im)^\s{0,4}add\s{1,4}https?://\S{1,200}", text)
        if m:
            E.add("MED", "container-privileged", T.line_of(text, m.start()), _s(m.group(0), 140),
                  "Dockerfile ADD from a URL (unpinned remote content in the image)")
    scan_special(E, fc, text)


def _json_checks(E, fc, data, text):
    name, rel = fc.name, fc.rel_lower
    if isinstance(data, dict):
        if AGENT_CONFIG_RX.search(rel):
            scan_agent_config(E, data, text, T.sanitize(fc.rel, 80))
            handled_agent = True
        else:
            handled_agent = False
        if handled_agent:
            pass
        elif rel.endswith(".claude-plugin/plugin.json") or (name == "plugin.json" and "name" in data):
            scan_plugin_json(E, data, text)
        elif name == "marketplace.json":
            scan_marketplace_json(E, data, text)
        elif name in ("hooks.json",):
            scan_hooks(E, data, text, "hooks.json")
        elif re.search(r"(?:^|/)\.claude/settings(?:\.local)?\.json$", rel) or name == "managed-settings.json" or (
                name.startswith("settings") and ("permissions" in data or "hooks" in data)):
            scan_settings(E, data, text, T.sanitize(fc.rel, 80))
        elif name == "package.json":
            scan_package_json(E, data, text)
        elif name in ("devcontainer.json", ".devcontainer.json"):
            scan_devcontainer(E, data, text)
        elif name == "monitors.json":
            E.add("HIGH", "plugin-manifest", 1, _s(data, 160),
                  "plugin monitors run shell commands in the background, outside the sandbox")
        elif name == ".lsp.json":
            E.add("MED", "plugin-manifest", 1, _s(data, 160), "plugin starts language-server processes")
        handled = (handled_agent or name in ("marketplace.json",) or name.startswith("settings")
                   or name == "plugin.json")
        if not handled:
            for key in ("mcpServers", "servers", "mcp_servers"):
                srv = data.get(key)
                if isinstance(srv, dict) and srv and all(isinstance(v, dict) for v in srv.values()) and any(
                        ("command" in v or "url" in v or "httpUrl" in v or "serverUrl" in v) for v in srv.values()):
                    scan_mcp_servers(E, srv, text, T.sanitize(fc.rel, 80))
                    break
            if name not in ("hooks.json",) and isinstance(data.get("hooks"), dict) and (
                    set(data["hooks"]) & HOOK_EVENTS):
                scan_hooks(E, data["hooks"], text, T.sanitize(fc.rel, 80))
    tools = collect_tool_descriptions(data)
    if tools:
        E.inv("%s: %d tool definition(s): %s" % (T.sanitize(fc.rel, 80), len(tools),
                                                 _s(", ".join(t[0] for t in tools[:12]), 160)))
        E.stream("tool-description", "\n".join(t[1] for t in tools), "tooldesc")
