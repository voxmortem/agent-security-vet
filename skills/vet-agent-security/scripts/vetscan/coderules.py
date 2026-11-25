"""Code-behaviour rules: execution, network, secrets, persistence, agent-config tampering, obfuscation.

Each rule has lower-case literal anchors. Its regex runs only over the fixed-size
tiles of the lower-cased text that contain an anchor, so the total work stays
linear in the input even when anchors are dense. Rules shaped "A ... B" are a
compact regex for B plus a cheap predicate for A on the same line.
"""
import re

from . import textutil as T
from .model import rule

WIN_BACK, WIN_FWD, TILE = 320, 420, 4096
MAX_HITS = 60


def _lower_pattern(src):
    """Lower-case a regex source without touching backslash escapes (upper-case classes keep their meaning)."""
    out, i, n = [], 0, len(src)
    while i < n:
        ch = src[i]
        if ch == "\\" and i + 1 < n:
            out.append(src[i:i + 2])
            i += 2
        else:
            out.append(ch.lower())
            i += 1
    return "".join(out)


class CRule:
    """One code-behaviour rule.

    `before` is an optional predicate over the lower-cased text that precedes a match on the same
    line (at most `span` characters). Rules of the shape "A ... B" are written as a compact regex
    for B plus a cheap predicate for A, so that dense repetitions of A cannot make matching slow."""
    __slots__ = ("id", "sev", "prose", "page", "anchors", "rx", "note", "tags", "redact", "before", "span", "raw")

    def __init__(self, rid, cat, sev, anchors, pattern, note, prose="same", page=None, tags=(), redact=False,
                 before=None, span=320):
        rule(rid, cat, note)
        self.before = before
        self.span = span
        # String patterns are matched against the lower-cased text (faster than IGNORECASE);
        # a pre-compiled pattern is case-sensitive and runs on the original text.
        self.raw = hasattr(pattern, "finditer")
        self.id = rid
        self.sev = sev            # severity in code / config / instruction files
        self.prose = sev if prose == "same" else prose    # severity inside markdown prose (None = skip)
        self.page = page          # severity in saved articles/pages when visible (None = skip)
        self.anchors = tuple(anchors)
        self.rx = pattern if self.raw else re.compile(_lower_pattern(pattern), re.M)
        self.note = note
        self.tags = tuple(tags)
        self.redact = redact


EXFIL_HOSTS = (
    "discord.com/api/webhooks", "discordapp.com/api/webhooks", "hooks.slack.com", "api.telegram.org/bot",
    "pastebin.com", "paste.ee", "hastebin.com", "ghostbin.", "rentry.co", "0x0.st", "transfer.sh", "file.io",
    "anonfiles.", "gofile.io", "catbox.moe", "webhook.site", "requestbin.", "requestcatcher.com",
    "pipedream.net", "hookbin.com", "beeceptor.com", "mockbin.", "ngrok.io", "ngrok.app", "ngrok.dev",
    "ngrok-free.app", "ngrok-free.dev", "loca.lt", "localtunnel.me", "serveo.net", "trycloudflare.com",
    "localhost.run", "pagekite.me", "tunnelmole.", "devtunnels.ms", "interact.sh", "oast.fun", "oast.live",
    "oast.pro", "oast.site", "oast.online", "oast.me", "oastify.com", "burpcollaborator.net",
    "canarytokens.com", "canarytokens.org", "dnslog.cn", "ceye.io", "bashupload.com", "termbin.com", "ix.io",
    "sprunge.us", "dpaste.com", "pastes.io", "controlc.com", "privatebin.", "telegra.ph", "smee.io",
)
_EXFIL_RX = re.compile("|".join(re.escape(h) for h in EXFIL_HOSTS), re.I)

_DL = r"(?:curl|wget|iwr|irm|invoke-webrequest|invoke-restmethod|fetch)"
# A shell after the pipe always counts; a general interpreter only when it reads the script from
# stdin (`| python3 -`, `| node`), not when it is a filter such as `| python -m json.tool`.
_SH = (r"(?:sudo\s{1,3})?(?:env\s{1,3})?(?:(?:(?:ba|z|da|k|c|fi|tc)?sh|pwsh|powershell|iex|invoke-expression)\b"
       r"|(?:python[23]?|node|perl|ruby|php)\s{0,3}(?:-\s{0,3})?(?:$|[;&|)\"']))")
_RMFLAGS = r"\brm\s{1,3}(?:-[a-z-]{1,20}\s{1,3}){0,3}-[a-z]{0,6}(?:r[a-z]{0,6}f|f[a-z]{0,6}r)[a-z]{0,6}\s{1,3}(?:--\s{1,3})?[\"']?"
_END = r"(?:\s|$|[\"';&|)])"
_AGENT_CFG = (r"(?:\.claude[\\/]{1,2}(?:settings(?:\.local)?\.json|claude\.md|hooks|commands|agents|rules|plugins|"
              r"\.credentials)|\.claude\.json|claude\.md\b|agents\.md\b|\.cursorrules|\.cursor[\\/]{1,2}(?:rules|"
              r"mcp\.json)|\.codex[\\/]{1,2}config|\.gemini[\\/]{1,2}settings|copilot-instructions\.md|\.mcp\.json|"
              r"claude_desktop_config\.json|\.vscode[\\/]{1,2}(?:settings|tasks)\.json)")
_PROFILE = (r"(?:\.bashrc|\.zshrc|\.bash_profile|\.zprofile|\.profile\b|\.zshenv|config\.fish|"
            r"microsoft\.powershell_profile|\$profile\b)")
_WRITE = r"(?:>>?|\btee\b(?:\s{1,3}-a)?|add-content|out-file|set-content)"

_DL_WORDS = ("curl", "wget", "iwr", "irm", "invoke-webrequest", "invoke-restmethod", "fetch")
_DL_WORD_RX = re.compile(r"\b" + _DL + r"\b")       # predicates receive lower-cased text
_CURL_RX = re.compile(r"\b(?:curl|wget)\s")
_WRITER_WORDS = (">", "tee", "content", "out-file", "cp", "mv", "copy", "move", "ln", "install", "write",
                 "sed", "append", "clone", "rsync")
_WRITER_RX = re.compile(
    r"(?:^|[\s;&|(`$])(?:\d?>>?|tee|set-content|add-content|out-file|cp|mv|copy(?:-item)?|move(?:-item)?|"
    r"ln\s{1,3}-s|install\s{1,3}-|sed\s{1,3}-i|xcopy|robocopy|git\s{1,3}clone|rsync)(?:$|[\s\"'(])"
    r"|write_text|writefile|appendfile")
_PATH_BREAK = " \t\"'<>|;&()"


def _has_downloader(seg):
    return any(w in seg for w in _DL_WORDS) and bool(_DL_WORD_RX.search(seg))


def _downloads_to_file(seg):
    if "-outfile" in seg:
        return True
    return ("curl" in seg or "wget" in seg) and (" -o " in seg or "--output" in seg or ">" in seg)


def _is_powershell(seg):
    return "powershell" in seg or "pwsh" in seg


def _curl_or_wget(seg):
    return ("curl" in seg or "wget" in seg) and bool(_CURL_RX.search(seg))


def _is_redirect_target(seg):
    """True when the text before a file name ends in a write operator: `... >> ~/`, `tee -a ~/`, etc."""
    j = len(seg)
    low_limit = j - 90 if j > 90 else 0
    while j > low_limit and seg[j - 1] not in _PATH_BREAK:
        j -= 1
    head = seg[:j].rstrip(" \t\"'")
    if head.endswith(">"):
        k = len(head) - 1
        while k > 0 and head[k - 1] == ">":
            k -= 1
        return k == 0 or head[k - 1] in " \t0123456789&"
    if head.endswith(("tee", "tee -a", "tee --append")):
        return True
    return "add-content" in seg or "out-file" in seg or "set-content" in seg


def _writes_file(seg):
    return any(w in seg for w in _WRITER_WORDS) and bool(_WRITER_RX.search(seg))


RULES = [
    # ------------------------------------------------------------ execution
    CRule("exec-pipe-shell", "exec", "HIGH", ("|",),
          r"\|\s{0,3}" + _SH,
          "downloads content and pipes it straight into an interpreter", page="MED", tags=("net", "exec"),
          before=_has_downloader),
    CRule("exec-pipe-shell", "exec", "HIGH",
          ("curl", "wget", "iex", "invoke-expression", "downloadstring"),
          r"(?:(?:ba|z|da|k)?sh|source|eval|\.)\s{1,3}(?:-c\s{1,3})?[\"']?(?:<\(|\$\()\s{0,3}(?:curl|wget)\b"
          r"|\b(?:iex|invoke-expression)\b\s{0,3}\(?\s{0,3}\(?\s{0,3}(?:iwr|irm|invoke-webrequest|"
          r"invoke-restmethod|new-object\s{1,3}(?:system\.)?net\.webclient|\[?system\.net\.webclient)"
          r"|\.downloadstring\([^)\n]{0,300}\)\s{0,3}\|\s{0,3}(?:iex|invoke-expression)",
          "downloads content and pipes it straight into an interpreter", page="MED", tags=("net", "exec")),
    CRule("exec-download-run", "exec", "HIGH", ("&&", ";"),
          r"(?:&&|;)\s{0,3}(?:chmod\s{1,3}\+x|(?:ba|z)?sh\s|\./|python[23]?\s|sudo\s|start-process|&\s|\.\\|"
          r"invoke-item)",
          "downloads a file and runs it on the same line", page="MED", tags=("net", "exec"),
          before=_downloads_to_file),
    CRule("exec-ps-encoded", "exec", "HIGH", (" -e", "\t-e"),
          r"\s-(?:e|ec|en|enc|enco|encod|encode|encoded|encodedc[a-z]{0,6})\s{1,3}[\"']?[A-Za-z0-9+/=]{16,}",
          "PowerShell encoded command", page="MED", tags=("exec", "decode"), before=_is_powershell, span=260),
    CRule("exec-lolbin", "exec", "HIGH",
          ("certutil", "bitsadmin", "mshta", "regsvr32", "rundll32", "wmic", "msiexec", "cscript", "wscript",
           "installutil", "odbcconf"),
          r"\bcertutil(?:\.exe)?\s{1,3}[^\n]{0,80}-(?:urlcache|decode|decodehex)\b"
          r"|\bbitsadmin(?:\.exe)?\s{1,3}[^\n]{0,80}/transfer"
          r"|\bmshta(?:\.exe)?\s{1,3}[\"']?(?:https?:|javascript:|vbscript:)"
          r"|\bregsvr32(?:\.exe)?\b[^\n]{0,80}/i:"
          r"|\brundll32(?:\.exe)?\s{1,3}[^\n]{0,80}(?:javascript:|url\.dll|shell32\.dll,\s?shellexec)"
          r"|\bwmic\b[^\n]{0,80}process\s{1,3}call\s{1,3}create"
          r"|\bmsiexec(?:\.exe)?\b[^\n]{0,80}/i\s{1,3}[\"']?https?:"
          r"|\b(?:cscript|wscript)(?:\.exe)?\b[^\n]{0,80}//e:"
          r"|\binstallutil(?:\.exe)?\b[^\n]{0,60}/u\b|\bodbcconf(?:\.exe)?\b[^\n]{0,60}regsvr",
          "living-off-the-land downloader/executor", page="MED", tags=("exec",)),
    CRule("exec-reverse-shell", "exec", "HIGH",
          ("/dev/tcp/", "/dev/udp/", "nc ", "ncat", "mkfifo", "socat", "os.dup2", "pty.spawn", "tcpclient",
           "bash -i"),
          r"/dev/(?:tcp|udp)/[a-z0-9$.{]"
          r"|\bn(?:c|cat)\b[^\n]{0,60}\s-[a-z]{0,3}e\s|\bmkfifo\b[^\n]{0,120}\bn(?:c|cat)\b"
          r"|\bsocat\b[^\n]{0,120}exec:|os\.dup2\(\s{0,2}\w{1,24}\.fileno\(\)\s{0,2},\s{0,2}[012]\s{0,2}\)|pty\.spawn\("
          r"|new-object\s{1,3}(?:system\.)?net\.sockets\.tcpclient|\bbash\s{1,3}-i\s{1,3}>&",
          "reverse-shell / remote-control pattern", page="MED", tags=("net", "exec")),
    CRule("exec-decode-run", "exec", "HIGH",
          ("base64", "xxd", "rev ", "eval", "exec", "frombase64string", "new function", "python"),
          r"base64\s{1,3}(?:-d|--decode|-D)\b[^\n|]{0,120}\|\s{0,3}(?:sudo\s{1,3})?(?:ba|z|da)?sh\b"
          r"|xxd\s{1,3}-r[^\n|]{0,80}\|\s{0,3}(?:ba|z)?sh\b|\brev\b[^\n|]{0,40}\|\s{0,3}(?:ba|z)?sh\b"
          r"|(?<![\w.])(?:eval|exec)\s{0,3}\(\s{0,3}(?:atob|base64_decode|base64\.b64decode|codecs\.decode|"
          r"bytes\.fromhex|zlib\.decompress|marshal\.loads|unescape|decodeuricomponent|string\.fromcharcode|"
          r"__import__\([\"']base64)"
          r"|frombase64string[^\n]{0,200}(?:\|\s{0,3}iex|invoke-expression)"
          r"|new\s{1,3}function\(\s{0,3}atob"
          r"|python[23]?\s{1,3}-c\s{1,3}[\"'][^\n]{0,200}(?:b64decode|fromhex|decompress)",
          "decodes hidden content and executes it", page="MED", tags=("exec", "decode")),
    CRule("exec-decode", "obfuscation", "LOW",
          ("base64", "frombase64string", "atob", "b64decode", "base64_decode", "codecs.decode", "fromhex",
           "binascii", "fromcharcode", "[char]"),
          r"base64\s{1,3}(?:-d|--decode)\b|frombase64string|\batob\s{0,2}\(|b64decode|base64_decode"
          r"|codecs\.decode\([^)\n]{0,80}rot|bytes\.fromhex|binascii\.(?:unhexlify|a2b)|string\.fromcharcode"
          r"|\[char\]\s{0,2}\d",
          "decodes data at runtime", prose="LOW", tags=("decode",)),
    CRule("exec-eval", "exec", "MED",
          ("eval", "exec", "new function", "invoke-expression", "iex", "__import__", "importlib", "pickle",
           "marshal", "yaml.load", "vm.runin", "ctypes", "virtualalloc", "createremotethread",
           "writeprocessmemory"),
          r"(?<![\w.])(?:eval|exec)\s{0,2}\(|new\s{1,3}function\s{0,2}\(|invoke-expression|\biex\s"
          r"|__import__\s{0,2}\(|importlib\.import_module|pickle\.loads?\(|marshal\.loads\("
          r"|yaml\.load\((?![^)\n]{0,80}safe)|vm\.runin(?:new|this)context"
          r"|ctypes\.(?:windll|cdll|cfunctype)|virtualalloc|createremotethread|writeprocessmemory",
          "dynamic code evaluation / unsafe deserialization / native injection API", prose="LOW",
          tags=("exec",)),
    CRule("exec-shell", "exec", "MED",
          ("os.system", "os.popen", "subprocess", "child_process", "execsync", "shell_exec", "passthru",
           "proc_open", "getruntime", "shellexecute", "wscript.shell", "start-process", "cmd", "sh -c",
           "bash -c"),
          r"os\.system\s{0,2}\(|os\.popen\s{0,2}\(|subprocess\.[a-z_]{1,20}\([^)\n]{0,300}shell\s{0,2}=\s{0,2}true"
          r"|child_process[^\n]{0,80}\bexec(?:sync)?\s{0,2}\(|\bexecsync\s{0,2}\(|shell_exec\s{0,2}\("
          r"|passthru\s{0,2}\(|proc_open\s{0,2}\(|runtime\.getruntime\(\)\.exec|shellexecute|wscript\.shell"
          r"|start-process\b|\bcmd(?:\.exe)?\s{1,3}/c\s|(?<![\w-])(?:ba)?sh\s{1,3}-c\s",
          "runs shell command strings", prose="LOW", tags=("exec",)),
    CRule("exec-process", "exec", "LOW",
          ("subprocess", "child_process", "spawn", "execfile", "processbuilder", "os.exec", "process.start"),
          r"\bsubprocess\.(?:run|popen|call|check_output|check_call)|child_process|\bspawn(?:sync)?\s{0,2}\("
          r"|\bexecfile(?:sync)?\s{0,2}\(|processbuilder|os\.exec[lv]p?e?\s{0,2}\(|process\.start\(",
          "spawns processes", prose=None),
    CRule("exec-download", "network", "MED", ("://",),
          r"https?://",
          "downloads or transfers over the network", prose="LOW", tags=("net",), before=_curl_or_wget, span=220),
    CRule("exec-download", "network", "MED",
          ("invoke-webrequest", "invoke-restmethod", "iwr ", "irm ", "urlretrieve", "downloadfile",
           "downloadstring", "start-bitstransfer", "scp ", "rsync"),
          r"\b(?:invoke-webrequest|invoke-restmethod|iwr|irm)\s"
          r"|urlretrieve\s{0,2}\(|\.downloadfile\s{0,2}\(|\.downloadstring\s{0,2}\(|start-bitstransfer"
          r"|\bscp\s{1,3}[^\n]{0,80}@|\brsync\s[^\n]{0,120}@",
          "downloads or transfers over the network", prose="LOW", tags=("net",)),
    CRule("exec-installer", "exec", "LOW",
          ("npx", "bunx", "uvx", "pipx", "npm i", "pip install", "pip3 install", "uv pip", "uv tool",
           "go install", "cargo install", "choco install", "winget install", "brew install", "gem install",
           "pnpm dlx", "yarn dlx", "apt install", "apt-get install"),
          r"\b(?:npx|bunx|uvx)\s{1,3}\S|\bpipx\s{1,3}(?:run|install)\b|\bnpm\s{1,3}(?:i|install)\s{1,3}-g\b"
          r"|\bpip3?\s{1,3}install\b|\buv\s{1,3}(?:pip\s{1,3}install|tool\s{1,3}install)\b"
          r"|\b(?:go|cargo|choco|winget|brew|gem)\s{1,3}install\b|\b(?:pnpm|yarn)\s{1,3}dlx\b"
          r"|\bapt(?:-get)?\s{1,3}install\b",
          "installs or runs packages from a registry", prose="LOW"),
    CRule("exec-destructive", "destructive", "HIGH",
          ("rm ", "no-preserve-root", "remove-item", "del ", "erase ", "rd ", "rmdir", "format ", "mkfs",
           "dd ", "/dev/sd", "/dev/nvme", ":()", "vssadmin", "wevtutil", "cipher", "shred", "chmod", "bcdedit"),
          _RMFLAGS + r"(?:/(?:\*|" + _END + r")|~/?(?:\*|" + _END + r")|\$home\b/?(?:\*|" + _END + r")"
          r"|\$\{home\}/?(?:\*|" + _END + r")|\*" + _END + r"|\." + _END +
          r"|/(?:etc|usr|var|home|boot|bin|lib|opt|root|users)\b/?(?:\*|" + _END + r"))"
          r"|--no-preserve-root"
          r"|\bremove-item\b[^\n]{0,120}-recurse[^\n]{0,120}(?:\$env:userprofile|\$home\b|[a-z]:\\(?:\s|$|\*|users\b|windows\b)|~[\\/]?(?:\s|$))"
          r"|\b(?:del|erase)\s{1,3}/[sfq]\s{1,3}/[sfq][^\n]{0,60}(?:[a-z]:\\\*?(?:\s|$)|%userprofile%|%systemroot%)"
          r"|\b(?:rd|rmdir)\s{1,3}/s\s{1,3}/q\s{1,3}(?:[a-z]:\\(?:\s|$)|%userprofile%|%systemroot%)"
          r"|\bformat\s{1,3}[a-z]:\s{0,3}(?:/[a-z]|$)|\bmkfs(?:\.[a-z0-9]{1,8})?\s{1,3}/dev/"
          r"|\bdd\s{1,3}[^\n]{0,80}of=/dev/(?:sd|nvme|hd|disk|mmcblk)|>\s{0,2}/dev/(?:sd[a-z]|nvme\d)"
          r"|:\(\)\s{0,2}\{\s{0,2}:\s{0,2}\|\s{0,2}:\s{0,2}&\s{0,2}\}"
          r"|\bvssadmin\b[^\n]{0,40}delete\s{1,3}shadows|\bwevtutil\b\s{1,3}cl\b|\bcipher\s{1,3}/w"
          r"|\bshred\s{1,3}-[a-z]{0,6}\s{1,3}/|\bchmod\s{1,3}-r\s{1,3}0?777\s{1,3}/(?:\s|$)|\bbcdedit\b[^\n]{0,60}/delete",
          "destructive command against system, home or whole-tree paths", page="MED", tags=("destructive",)),
    CRule("exec-destructive-soft", "destructive", "MED",
          ("rm -", "git push", "git clean", "git reset", "drop ", "truncate", "history -c", "clear-history",
           "histfile", "taskkill"),
          _RMFLAGS + r"(?:/|\$|~)|\bgit\s{1,3}push\b[^\n]{0,80}(?:--force\b|\s-f\b)|\bgit\s{1,3}clean\s{1,3}-[a-z]{0,4}f"
          r"|\bgit\s{1,3}reset\s{1,3}--hard|\bdrop\s{1,3}(?:database|table|schema)\s|\btruncate\s{1,3}table\b"
          r"|\bhistory\s{1,3}-c\b|\bclear-history\b|unset\s{1,3}histfile|\btaskkill\b[^\n]{0,40}/f\b",
          "irreversible or history-erasing command", prose="LOW"),
    # ------------------------------------------------------------ network
    CRule("net-library", "network", "MED",
          ("requests.", "urllib", "http.client", "aiohttp", "httpx", "fetch", "xmlhttprequest", "axios",
           "websocket", "net.connect", "socket.", "sendbeacon", "http.get", "http.post", "http.request",
           "https.request", "net/http", "reqwest", "webclient", "httpclient", "node-fetch", "undici",
           "smtplib", "ftplib", "paramiko", "telnetlib"),
          r"\brequests\.(?:get|post|put|patch|delete|request|session)\b|urllib\.request|urllib2|http\.client"
          r"|\baiohttp\b|\bhttpx\b|\bfetch\s{0,2}\(|xmlhttprequest|\baxios\b|new\s{1,3}websocket\s{0,2}\("
          r"|net\.connect|socket\.(?:socket|create_connection)|sendbeacon|\bhttp\.(?:get|post|request)\s{0,2}\("
          r"|https\.request|\"net/http\"|\breqwest\b|net\.webclient|\bhttpclient\b|node-fetch|\bundici\b"
          r"|\bsmtplib\b|\bftplib\b|\bparamiko\b|\btelnetlib\b",
          "network client code", prose="LOW", tags=("net",)),
    CRule("net-exfil-host", "network", "HIGH", tuple(EXFIL_HOSTS), "|".join(re.escape(h) for h in EXFIL_HOSTS),
          "known webhook / paste / tunnel / out-of-band host", page="MED", tags=("net", "exfil-host")),
    CRule("net-tls-off", "network", "MED",
          ("node_tls_reject_unauthorized", "verify", "--insecure", "curl", "strict-ssl", "git_ssl_no_verify",
           "pythonhttpsverify", "servercertificatevalidationcallback", "skipcertificatecheck"),
          r"node_tls_reject_unauthorized[\"']?\s{0,2}[:=]\s{0,2}[\"']?0|verify\s{0,2}=\s{0,2}false|--insecure\b"
          r"|\bcurl\s{1,3}[^\n]{0,80}\s-k\s|strict-ssl\s{1,3}false|git_ssl_no_verify|pythonhttpsverify\s{0,2}=\s{0,2}0"
          r"|servercertificatevalidationcallback|-skipcertificatecheck",
          "disables TLS certificate verification", prose="LOW"),
    # ------------------------------------------------------------ secrets
    CRule("sec-cred-path", "secrets", "HIGH",
          (".ssh", "id_rsa", "id_ed25519", "id_ecdsa", "id_dsa", "credentials", ".gnupg", ".kube", ".netrc",
           "gcloud", ".azure", ".docker", "terraform.d", "/etc/shadow", "ntds.dit", "config\\sam",
           "config/sam", "codex/auth", "codex\\auth", "gh/hosts", "gh\\hosts"),
          r"[\\/~]\.ssh(?:[\\/]|\b)|\bid_(?:rsa|ed25519|ecdsa|dsa)\b(?!\.pub)|\.git-credentials\b"
          r"|\.aws[\\/]{1,2}credentials|\.claude[\\/]{1,2}\.credentials|(?<![\w-])\.credentials\.json"
          r"|[\\/~]\.gnupg\b|\.kube[\\/]{1,2}config\b|[\\/~]\.netrc\b|\.config[\\/]{1,2}gcloud"
          r"|application_default_credentials\.json|[\\/~]\.azure[\\/]|\.docker[\\/]{1,2}config\.json"
          r"|terraform\.d[\\/]{1,2}credentials|\.config[\\/]{1,2}gh[\\/]{1,2}hosts|\.codex[\\/]{1,2}auth"
          r"|/etc/shadow\b|\bntds\.dit\b|system32[\\/]{1,2}config[\\/]{1,2}sam\b",
          "touches credential files or key material", page="MED", tags=("secret-src",)),
    CRule("sec-agent-config", "secrets", "MED",
          (".claude.json", "settings.json", "settings.local.json", "mcp.json", "config.toml", "auth.json",
           "claude_desktop_config", ".config/claude", ".config\\claude"),
          r"\.claude\.json|\.claude[\\/]{1,2}settings(?:\.local)?\.json|\.cursor[\\/]{1,2}mcp\.json"
          r"|\.codex[\\/]{1,2}config\.toml|claude_desktop_config\.json|\.gemini[\\/]{1,2}settings\.json"
          r"|\.config[\\/]{1,2}claude",
          "references agent configuration that can hold tokens or MCP secrets", prose="LOW",
          tags=("secret-soft",)),
    CRule("sec-cred-path-soft", "secrets", "MED",
          (".npmrc", ".pypirc", ".env", "/etc/passwd", "_history", "keyring"),
          r"[\\/~]\.npmrc\b|[\\/~]\.pypirc\b"
          r"|\b(?:cat|type|get-content|gc|read|open|load|source|cp|copy|less|more|head|tail|grep)\b[^\n]{0,40}"
          r"(?<![\w.])\.env\b(?!\.(?:example|sample|template|dist))"
          r"|/etc/passwd\b|\.(?:bash|zsh)_history|\bkeyring\.get_password\b",
          "reads files that commonly hold tokens or personal data", prose="LOW", tags=("secret-soft",)),
    CRule("sec-browser-store", "secrets", "HIGH",
          ("login data", "logins.json", "key3.db", "key4.db", "cookies.sqlite", "binarycookies", "user data",
           "cryptunprotectdata", "os_crypt", "local state", "web data"),
          r"(?:chrome|chromium|brave|edge|firefox|mozilla|opera|vivaldi)[^\n]{0,100}[\\/]"
          r"(?:login data|cookies|local state|web data|network[\\/]{1,2}cookies)\b"
          r"|\b(?:login data|logins\.json|key[34]\.db|cookies\.sqlite|cookies\.binarycookies)\b"
          r"|user data[\\/]{1,2}(?:default|profile \d)|cryptunprotectdata|\bos_crypt\b",
          "touches browser credential or cookie stores", page="MED", tags=("secret-src",)),
    CRule("sec-keychain", "secrets", "HIGH",
          ("find-generic-password", "find-internet-password", "dump-keychain", "secret-tool", "kwallet",
           "gnome-keyring", "vaultcmd", "cmdkey", "get-storedcredential", "mimikatz", "lsass", "procdump",
           "sekurlsa", "lazagne", "login.keychain"),
          r"security\s{1,3}(?:find|dump)-(?:generic|internet)-password|security\s{1,3}dump-keychain"
          r"|\bsecret-tool\s{1,3}(?:lookup|search)|\bkwallet(?:-query|manager|d)\b|gnome-keyring"
          r"|\bvaultcmd\b|\bcmdkey\s{1,3}/list|get-storedcredential|mimikatz|\blsass\b|\bprocdump\b"
          r"|sekurlsa|\blazagne\b|login\.keychain",
          "credential-store dumping tool or API", page="MED", tags=("secret-src",)),
    CRule("sec-wallet", "secrets", "HIGH",
          ("wallet.dat", "electrum", "exodus", "nkbihfbeogaeaoehlefnkodbefgpgknn", ".bitcoin", "keystore"),
          r"wallet\.dat\b|[\\/]electrum[\\/]{1,2}wallets|appdata[^\n]{0,40}[\\/]exodus\b"
          r"|nkbihfbeogaeaoehlefnkodbefgpgknn|[\\/]\.bitcoin[\\/]|[\\/]ethereum[\\/]{1,2}keystore",
          "touches cryptocurrency wallet files", page="MED", tags=("secret-src",)),
    CRule("sec-wallet-words", "secrets", "MED", ("seed phrase", "seedphrase", "mnemonic", "recovery phrase"),
          r"seed\s?phrase|\bmnemonic\s{1,3}(?:phrase|seed|words?)|recovery\s?phrase",
          "wallet seed / recovery phrase wording", prose="LOW"),
    CRule("sec-env-dump", "secrets", "MED",
          ("printenv", "env", "get-childitem", "gci ", "dir env:", "getenvironmentvariables", "os.environ",
           "process.env", "/environ"),
          r"\bprintenv\s{0,3}(?:\||>|$)|(?:^|[;&|]\s{0,2})env\s{0,2}(?:\||>)|get-childitem\s{1,3}env:"
          r"|\bgci\s{1,3}env:|\bdir\s{1,3}env:|\[environment\]::getenvironmentvariables\("
          r"|json\.dumps?\(\s{0,2}(?:dict\(\s{0,2})?os\.environ|(?:print|str|repr)\(\s{0,2}(?:dict\(\s{0,2})?os\.environ\s{0,2}\)"
          r"|json\.stringify\(\s{0,2}process\.env\s{0,2}[,)]|console\.log\(\s{0,2}process\.env\s{0,2}\)"
          r"|/proc/(?:self|\d{1,7})/environ",
          "dumps the whole environment (where secrets usually live)", prose="LOW", tags=("secret-src",)),
    CRule("sec-env-read", "secrets", "LOW",
          ("os.environ", "os.getenv", "process.env", "$env:", "getenv(", "env::var"),
          r"os\.environ(?:\.get)?[\[(]|os\.getenv\(|process\.env\.[a-z_]|\$env:[a-z_]{2,}|\bgetenv\(|env::var\(",
          "reads environment variables", prose=None, tags=("env",)),
    CRule("sec-env-named", "secrets", "LOW",
          ("anthropic_api_key", "openai_api_key", "aws_secret_access_key", "aws_session_token", "github_token",
           "gh_token", "npm_token", "hf_token", "slack_bot_token", "stripe_secret_key",
           "google_application_credentials", "azure_client_secret", "claude_code_oauth_token",
           "anthropic_auth_token"),
          r"\b(?:anthropic_api_key|openai_api_key|aws_secret_access_key|aws_session_token|github_token|gh_token|"
          r"npm_token|hf_token|slack_bot_token|stripe_secret_key|google_application_credentials|"
          r"azure_client_secret|claude_code_oauth_token|anthropic_auth_token)\b",
          "names a well-known secret environment variable", prose=None, tags=("secret-named",)),
    CRule("sec-secret-literal", "secrets", "HIGH", T.SECRET_ANCHORS, T.SECRET_RX,
          "embedded credential literal (value masked)", page="HIGH", redact=True),
    CRule("spy-capture", "secrets", "MED",
          ("pynput", "keyboard.", "getasynckeystate", "setwindowshookex", "imagegrab", "pyautogui.screenshot",
           "screencapture", "get-clipboard", "pyperclip", "clipboard.read", "pbpaste", "xclip",
           "videocapture", "sounddevice"),
          r"\bpynput\b|\bkeyboard\.(?:on_press|hook|record)\b|getasynckeystate|setwindowshookex"
          r"|\bimagegrab\.grab|pyautogui\.screenshot|\bscreencapture\s{1,3}-|get-clipboard|pyperclip\.paste"
          r"|clipboard\.readtext|\bpbpaste\b|xclip\s{1,3}-o|cv2\.videocapture\(|sounddevice\.rec",
          "captures keystrokes, screen, clipboard, camera or microphone", prose="LOW", tags=("secret-soft",)),
    # ------------------------------------------------------------ persistence / configuration
    CRule("cfg-persistence", "persistence", "HIGH",
          (".bashrc", ".zshrc", ".bash_profile", ".zprofile", ".profile", ".zshenv", "config.fish",
           "powershell_profile", "$profile", "authorized_keys"),
          _PROFILE + r"|authorized_keys\b",
          "persistence: shell profile, login item, autorun key or SSH authorized_keys", page="MED",
          tags=("persist",), before=_is_redirect_target, span=120),
    CRule("cfg-persistence", "persistence", "HIGH",
          ("currentversion", "startup", "rc.local", "profile.d", "register-wmievent", "launchagents",
           "launchdaemons"),
          r"currentversion\\{1,2}run(?:once)?\b|\\start menu\\programs\\startup|shell:startup"
          r"|/etc/rc\.local|/etc/profile\.d/|register-wmievent|library/launch(?:agents|daemons)/",
          "persistence: shell profile, login item, autorun key or SSH authorized_keys", page="MED",
          tags=("persist",)),
    CRule("cfg-scheduled", "persistence", "HIGH",
          ("schtasks", "crontab", "/etc/cron", "launchctl", "systemctl", "systemd", "reg add", "reg.exe",
           "scheduledtask", "new-service", "sc create", "sc.exe", "setx"),
          r"\bschtasks(?:\.exe)?\s{1,3}/create|\bcrontab\s{1,3}-[a-z]{0,2}\b|\|\s{0,2}crontab\b|/etc/cron\."
          r"|\blaunchctl\s{1,3}(?:load|bootstrap|enable)\b|systemctl\s{1,3}(?:--user\s{1,3})?enable\b"
          r"|\.config/systemd/user|/etc/systemd/system|\breg(?:\.exe)?\s{1,3}add\b|register-scheduledtask"
          r"|new-scheduledtask|new-service\b|\bsc(?:\.exe)?\s{1,3}create\b|\bsetx\s{1,3}\w",
          "scheduled task / service / registry / persistent environment change", prose="MED",
          tags=("persist",)),
    CRule("cfg-agent-bypass", "agent-config", "HIGH",
          ("dangerously-skip-permissions", "dangerouslydisablesandbox", "bypasspermissions", "permission-mode",
           "defaultmode", "skipdangerousmodepermissionprompt", "enableallprojectmcpservers", "--yolo",
           "autoapprove", "--allow-all-tools", "--trust-all-tools", "approval_policy", "sandbox_mode",
           "dangerously-bypass-approvals-and-sandbox"),
          r"--dangerously-skip-permissions|dangerouslydisablesandbox|bypasspermissions"
          r"|--permission-mode\s{1,3}(?:bypass\w{0,20}|dontask)|\"defaultmode\"\s{0,2}:\s{0,2}\"(?:dontask|auto)\""
          r"|skipdangerousmodepermissionprompt|enableallprojectmcpservers\"?\s{0,2}[:=]\s{0,2}true|--yolo\b"
          r"|\"?chat\.tools\.(?:terminal\.)?autoapprove\"?\s{0,2}[:=]\s{0,2}true|--allow-all-tools|--trust-all-tools"
          r"|approval_policy\s{0,2}=\s{0,2}\"never\"|sandbox_mode\s{0,2}=\s{0,2}\"danger-full-access\""
          r"|--dangerously-bypass-approvals-and-sandbox",
          "turns off an agent's permission prompts or sandbox", page="MED", tags=("agent-cfg",)),
    CRule("cfg-agent-write", "agent-config", "HIGH",
          (".claude", "claude.md", "agents.md", ".cursorrules", ".cursor", ".codex", ".gemini",
           "copilot-instructions", ".mcp.json", "claude_desktop_config", ".vscode"),
          _AGENT_CFG,
          "writes agent configuration, instruction files, hooks or MCP registrations", page="MED",
          tags=("agent-cfg",), before=_writes_file, span=180),
    CRule("cfg-agent-write", "agent-config", "HIGH",
          ("claude mcp", "claude config", "claude plugin", "/plugin", "codex mcp", "gemini mcp"),
          r"\bclaude\s{1,3}mcp\s{1,3}add(?:-json)?\b|\bclaude\s{1,3}config\s{1,3}(?:set|add)\b"
          r"|\bclaude\s{1,3}plugin\s{1,3}(?:install|marketplace\s{1,3}add)\b"
          r"|/plugin\s{1,3}(?:install|marketplace\s{1,3}add)\b|\b(?:codex|gemini)\s{1,3}mcp\s{1,3}add\b",
          "writes agent configuration, instruction files, hooks or MCP registrations", page="MED",
          tags=("agent-cfg",)),
    CRule("cfg-agent-skill-install", "agent-config", "MED", (".claude",),
          r"\.claude[\\/]{1,2}skills",
          "copies files into the personal skills directory", prose="LOW", before=_writes_file, span=180),
    CRule("cfg-git-tamper", "agent-config", "MED",
          ("git config", "core.hookspath", "core.sshcommand", "core.fsmonitor", "insteadof", "credential.helper",
           "--no-verify", "husky_skip", "update-index"),
          r"git\s{1,3}config\s{1,3}--(?:global|system)|core\.hookspath|core\.sshcommand|core\.fsmonitor"
          r"|url\.[^\n]{0,80}\.insteadof|credential\.helper|--no-verify\b|husky_skip"
          r"|\bgit\s{1,3}update-index\s{1,3}--(?:assume-unchanged|skip-worktree)",
          "changes git configuration or skips git hooks/verification", prose="LOW"),
    CRule("cfg-security-off", "persistence", "HIGH",
          ("set-mppreference", "add-mppreference", "netsh", "ufw", "setenforce", "spctl", "csrutil",
           "com.apple.quarantine", "executionpolicy", "-ep bypass", "nopasswd", "/etc/sudoers", "enablelua"),
          r"set-mppreference[^\n]{0,80}-disable|add-mppreference\s{1,3}-exclusion"
          r"|netsh\s{1,3}(?:advfirewall|firewall)[^\n]{0,60}(?:off|disable)|\bufw\s{1,3}disable|setenforce\s{1,3}0"
          r"|spctl\s{1,3}--master-disable|csrutil\s{1,3}disable"
          r"|xattr\s{1,3}-[a-z]{0,3}d[a-z]{0,3}\s{1,3}com\.apple\.quarantine"
          r"|set-executionpolicy\s{1,3}(?:-executionpolicy\s{1,3})?(?:bypass|unrestricted)"
          r"|-executionpolicy\s{1,3}bypass|\s-ep\s{1,3}bypass|nopasswd\s{0,2}:|>>?\s{0,3}/etc/sudoers"
          r"|enablelua[^\n]{0,40}\b0\b",
          "disables an OS security control (AV, firewall, Gatekeeper, execution policy, sudo prompt)",
          page="MED", tags=("persist",)),
    # ------------------------------------------------------------ obfuscation
    CRule("obf-escapes", "obfuscation", "MED",
          ("\\x", "\\u", "_0x", "fromcharcode", "chr(", "[char]", "${ifs}", "$ifs", "^", "$'"),
          r"(?:\\x[0-9a-f]{2}){12,}|(?:\\u[0-9a-f]{4}){10,}|\b_0x[0-9a-f]{4,}\b"
          r"|(?:string\.fromcharcode\([^)\n]{0,400}\)\s{0,2}\+?\s{0,2}){2,}|(?:chr\(\d{1,3}\)\s{0,2}[+.]\s{0,2}){5,}"
          r"|(?:\[char\]\s{0,2}(?:0x)?[0-9a-f]{1,4}\s{0,2}\+\s{0,2}){4,}|\$\{ifs\}|\$ifs\$9"
          r"|(?<![\w^])(?:[a-z]\^){4,}[a-z]|\$'(?:\\x[0-9a-f]{2}|\\[0-7]{3}){4,}",
          "escape-encoded or deliberately obfuscated code", prose="MED", tags=("decode",)),
]

BY_ID = {}
for _r in RULES:
    BY_ID.setdefault(_r.id, _r)


def run(text, low, emit, rules=None, budget=None):
    """Call emit(rule, match) for every rule match. `low` must be text.lower() with equal length.
    A match for which emit returns False does not count towards the per-rule limit (MAX_HITS).

    The text is cut into fixed tiles. A rule's regex runs once over (tile + margins) for every
    tile that contains one of its anchors, so the work per rule is bounded by the text size no
    matter how many anchors there are or how densely they repeat."""
    n = len(text)
    if len(low) != n:      # lower() changed the length (rare Unicode case): positions would drift
        low = text.casefold() if len(text.casefold()) == n else "".join(
            c.lower() if len(c.lower()) == 1 else c for c in text)
    for r in (rules or RULES):
        seen = set()
        tiles = set()
        hits = 0
        hay = text if r.raw else low
        for a in r.anchors:
            i = low.find(a)
            while i != -1 and hits < MAX_HITS:
                tile = i // TILE
                if tile not in tiles:
                    tiles.add(tile)
                    ws = tile * TILE - WIN_BACK
                    if ws < 0:
                        ws = 0
                    we = (tile + 1) * TILE + WIN_FWD
                    if we > n:
                        we = n
                    for m in r.rx.finditer(hay, ws, we):
                        if m.start() in seen:
                            continue
                        if m.end() == we and we < n:
                            # the match touched the window edge: re-check with real context after it
                            m = r.rx.match(hay, m.start(), min(n, we + WIN_FWD))
                            if not m:
                                continue
                        seen.add(m.start())
                        if r.before is not None:
                            s0 = m.start()
                            lo = s0 - r.span if s0 > r.span else 0
                            nl = low.rfind("\n", lo, s0)
                            if not r.before(low[(nl + 1 if nl >= 0 else lo):s0]):
                                continue
                        if emit(r, m) is False:
                            continue        # the caller did not count this match (a lowered mention)
                        hits += 1
                        if hits >= MAX_HITS:
                            break
                i = low.find(a, (tile + 1) * TILE)
            if hits >= MAX_HITS:
                break
        if budget and budget.expired():
            return
