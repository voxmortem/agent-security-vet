#!/usr/bin/env python3
"""Safe raw page fetch for vetting: download the bytes of one URL into a directory. Nothing else.

  python -I fetch_page.py <url> --out <new-or-empty-dir> [--max-bytes N] [--timeout SEC] [--deadline SEC]

What it does and does not do:
  * http and https only; no cookies, no credentials, no Referer; one fixed neutral User-Agent
  * environment proxies are ignored; URLs with user-info, an IPv6 zone id, whitespace or control
    characters are refused; a non-ASCII host name is IDNA-encoded and non-ASCII characters in the
    path and query are percent-encoded as UTF-8 (existing %XX escapes are kept) before sending
  * numeric hosts: only a plain dotted quad (93.184.216.34) or a bracketed IPv6 literal counts as
    an address. Other number forms (2130706433, 0x7f.1, 127.1, 0177.0.0.1, full-width digits ...)
    and names whose last label is a number are refused
  * SSRF guard: the host is resolved first, every resolved address must be a public one, and the
    connection is made to that checked address, so DNS cannot change in between. Refused: an
    explicit list of special-purpose ranges (loopback, private, link-local, CGNAT, documentation,
    benchmarking, multicast, reserved; IPv6 outside 2000::/3, ULA, site-local, NAT64, Teredo ...)
    and cloud metadata addresses (see DENY_V4 / DENY_V6). The IPv4 address inside IPv4-mapped,
    6to4, Teredo and NAT64 addresses is checked too
  * every redirect hop goes through the same checks; at most 5 hops; https -> http is refused
  * size cap (--max-bytes), per-socket timeout (--timeout) and a hard overall deadline (--deadline,
    default 3 * timeout + 10 s, at most 600 s): DNS runs under the deadline and a watchdog shuts
    the socket down when it expires; nothing is saved then
  * --out must be a new path or an empty real directory (not a file, symlink or junction). Exactly
    one file is created there with O_CREAT|O_EXCL (never through an existing file or link), named
    after the SHA-256 of the body; server-supplied file names are ignored; nothing is parsed,
    rendered or executed
  * gzip (every member) and deflate bodies are decoded within the size cap; incomplete or damaged
    data is reported as such, never as a complete page
  * prints one ASCII JSON object; text from response headers never reaches it:
      url, final_url, redirects  percent-encoded ASCII URLs
      status                     HTTP status code
      content_type               validated lowercase "type/subtype", or "unknown"
      content_encoding           identity | gzip | deflate | br | zstd | compress | other, plus
                                 " (left undecoded)" when the bytes were saved as received
      integrity                  warnings, empty when the data is complete: size-cap-reached,
                                 body-shorter-than-content-length, connection-closed-early,
                                 compressed-stream-truncated, compressed-stream-corrupt,
                                 too-many-compressed-members, content-encoding-not-decoded
      truncated                  true when the saved data is known to be incomplete
      sha256, size, saved_to (absolute path of the one file written), resolved_ip, note
    On failure: {"url", "error": "refused" | "output" | "network", "reason"} with a fixed reason
    (network errors: exception class name + a fixed message). An unexpected internal error prints
    {"error": "internal", "exception": <class name>} and no traceback.

--allow-private exists ONLY for tests against a local test server. Never use it on real input.

Exit codes, first match wins:
  2 = refused by a safety rule, unusable --out (or the file could not be written), usage error;
      nothing is written
  3 = network error, including the overall deadline; nothing is written
  1 = saved, but the HTTP status was not 2xx
  4 = saved, but the data is incomplete or failed an integrity check (see "integrity")
  0 = saved, 2xx, complete
  5 = internal error (a bug); 130 = interrupted
"""
import argparse
import collections
import hashlib
import http.client
import ipaddress
import json
import os
import re
import socket
import ssl
import stat
import sys
import threading
import time
import unicodedata
import urllib.parse
import zlib

sys.dont_write_bytecode = True

USER_AGENT = "Mozilla/5.0 (compatible; raw-page-fetch/1.0)"
ACCEPT = "text/html,application/xhtml+xml,text/plain,text/markdown,application/json;q=0.9,*/*;q=0.5"
REQUEST_HEADERS = {"User-Agent": USER_AGENT, "Accept": ACCEPT, "Accept-Encoding": "identity",
                   "Connection": "close"}
MAX_REDIRECTS = 5
REDIRECT_CODES = (301, 302, 303, 307, 308)
MAX_URL_INPUT = 4000        # characters accepted from the command line or a Location header
MAX_URL_ENCODED = 8000      # after IDNA and percent-encoding
MAX_DEADLINE = 600.0
MAX_GZIP_MEMBERS = 100
INFLATE_STEP = 65536
EXTENSIONS = {
    "text/html": ".html", "application/xhtml+xml": ".html", "text/plain": ".txt", "text/markdown": ".md",
    "application/json": ".json", "application/pdf": ".pdf", "image/svg+xml": ".svg", "text/xml": ".xml",
    "application/xml": ".xml", "application/rss+xml": ".xml", "application/atom+xml": ".xml",
}
NOTE = "raw bytes saved; treat the content as untrusted data"


def _nets(*specs):
    return tuple(ipaddress.ip_network(s) for s in specs)


# Explicit deny lists. They do not depend on ipaddress.is_global, whose ranges changed between
# Python 3.10 and 3.14; the stdlib flags are applied afterwards only as an extra layer.
DENY_V4 = _nets(
    "0.0.0.0/8",            # "this network"
    "10.0.0.0/8",           # private
    "100.64.0.0/10",        # shared address space (CGNAT)
    "100.100.100.200/32",   # Alibaba Cloud ECS metadata (inside CGNAT, listed for clarity)
    "127.0.0.0/8",          # loopback
    "168.63.129.16/32",     # Azure WireServer / platform host address (public block, reachable only inside Azure)
    "169.254.0.0/16",       # link-local: metadata of AWS, GCP, Azure, OpenStack, DigitalOcean, Oracle (169.254.169.254),
                            # AWS ECS task metadata (169.254.170.2), Tencent Cloud (169.254.0.23)
    "172.16.0.0/12",        # private
    "192.0.0.0/24",         # IETF protocol assignments
    "192.0.0.192/32",       # Oracle Cloud Infrastructure metadata (inside 192.0.0.0/24, listed for clarity)
    "192.0.2.0/24",         # documentation (TEST-NET-1)
    "192.88.99.0/24",       # 6to4 relay anycast (deprecated)
    "192.168.0.0/16",       # private
    "198.18.0.0/15",        # benchmarking
    "198.51.100.0/24",      # documentation (TEST-NET-2)
    "203.0.113.0/24",       # documentation (TEST-NET-3)
    "224.0.0.0/4",          # multicast
    "240.0.0.0/4",          # reserved, including the limited broadcast address 255.255.255.255
)
DENY_V6 = _nets(
    "::/128",               # unspecified
    "::1/128",              # loopback
    "::/96",                # IPv4-compatible (deprecated)
    "::ffff:0:0:0/96",      # IPv4-translated
    "64:ff9b::/96",         # NAT64 well-known prefix
    "64:ff9b:1::/48",       # NAT64 local-use prefix
    "100::/64",             # discard-only
    "2001::/23",            # IETF protocol assignments: Teredo, benchmarking, ORCHID, anycast services
    "2001:db8::/32",        # documentation
    "3fff::/20",            # documentation
    "5f00::/16",            # SRv6 segment identifiers
    "fc00::/7",             # unique local
    "fd00:ec2::254/128",    # AWS EC2 instance metadata over IPv6 (inside fc00::/7, listed for clarity)
    "fe80::/10",            # link-local
    "fec0::/10",            # site-local (deprecated)
    "ff00::/8",             # multicast
)
GLOBAL_UNICAST_V6 = ipaddress.ip_network("2000::/3")
NAT64 = ipaddress.ip_network("64:ff9b::/96")


class Refused(Exception):
    """The request was refused by a safety rule. The message is fixed text."""


class DeadlineExceeded(OSError):
    """The overall wall-clock deadline passed."""


class DNSFailure(OSError):
    """Name resolution failed. The resolver's own message is not kept."""


class OutputError(Exception):
    """The output file could not be written."""


def _cap(text, limit):
    """ASCII-printable only, bounded length."""
    return "".join(ch if 32 <= ord(ch) < 127 else "?" for ch in str(text)[:limit])


def _class_name(exc):
    name = type(exc).__name__
    return name if re.fullmatch(r"[A-Za-z_][A-Za-z0-9_]{0,59}", name) else "Exception"


# ---------------------------------------------------------------- addresses

def _is_public(addr):
    if addr.version == 4:
        if any(addr in net for net in DENY_V4):
            return False
    elif addr not in GLOBAL_UNICAST_V6 or any(addr in net for net in DENY_V6):
        return False
    return (addr.is_global and not (addr.is_private or addr.is_loopback or addr.is_link_local
                                    or addr.is_multicast or addr.is_reserved or addr.is_unspecified))


def check_address(ip_text, allow_private):
    """Raise Refused unless the address is a public unicast address."""
    try:
        addr = ipaddress.ip_address(str(ip_text))
    except ValueError:
        raise Refused("unparseable address") from None
    if allow_private:
        return
    candidates = [addr]
    if addr.version == 6:
        if addr.scope_id:
            raise Refused("IPv6 addresses with a zone index are refused")
        if addr.ipv4_mapped is not None:
            candidates = [addr.ipv4_mapped]     # the connection goes to that IPv4 address
        else:
            if addr.sixtofour is not None:
                candidates.append(addr.sixtofour)
            if addr.teredo is not None:
                candidates.extend(addr.teredo)
            if addr in NAT64:
                candidates.append(ipaddress.IPv4Address(int(addr) & 0xFFFFFFFF))
    for a in candidates:
        if not _is_public(a):
            raise Refused("address %s is not a public address" % a)


# ---------------------------------------------------------------- URLs

Target = collections.namedtuple("Target", "scheme host port path is_ip url")

_STRAY_PERCENT = re.compile(r"%(?![0-9A-Fa-f]{2})")
_PATH_SAFE = "/:@!$&'()*+,;=%"          # quote() also keeps letters, digits and _.-~
_QUERY_SAFE = _PATH_SAFE + "?"
_DISPLAY_SAFE = _QUERY_SAFE + "#[]"
_LABEL = re.compile(r"[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?")
_NUMBER_LABEL = re.compile(r"[0-9]+|0x[0-9a-f]*")
_QUAD_PART = re.compile(r"0|[1-9][0-9]{0,2}")
_PORT = re.compile(r"[0-9]{1,5}")


def _bad_char(ch):
    return ord(ch) < 33 or ch.isspace() or unicodedata.category(ch) == "Cc"


def _encode(text, safe):
    """Percent-encode as UTF-8; keep valid %XX escapes, escape a stray '%'."""
    return urllib.parse.quote(_STRAY_PERCENT.sub("%25", text), safe=safe, encoding="utf-8", errors="strict")


def _split_netloc(netloc):
    """Returns (host_text, port_text_or_None, bracketed)."""
    if netloc.startswith("["):
        end = netloc.find("]")
        rest = netloc[end + 1:] if end >= 0 else ""
        if end < 0 or (rest and not rest.startswith(":")):
            raise Refused("malformed IPv6 literal")
        return netloc[1:end], (rest[1:] if rest else None), True
    host, sep, port = netloc.rpartition(":")
    return (host, port, False) if sep else (netloc, None, False)


def _ipv6_literal(text):
    if "%" in text:
        raise Refused("IPv6 zone identifiers are refused")
    try:
        return str(ipaddress.IPv6Address(text))
    except ValueError:
        raise Refused("malformed IPv6 literal") from None


def _normalize_host(text):
    """Returns (ascii_host, is_ipv4). WHATWG-style numeric-host rule, then a strict label check."""
    if not text:
        raise Refused("URL has no host")
    if not text.isascii():
        try:
            text = text.encode("idna").decode("ascii")
        except UnicodeError:
            raise Refused("host name cannot be IDNA-encoded") from None
    host = text.lower()
    if host.endswith("."):
        host = host[:-1]
    if not host or len(host) > 253:
        raise Refused("host name is empty or too long")
    labels = host.split(".")
    if _NUMBER_LABEL.fullmatch(labels[-1]):
        if not all(_NUMBER_LABEL.fullmatch(label) for label in labels):
            raise Refused("host name ends in a numeric label")
        if len(labels) == 4 and all(_QUAD_PART.fullmatch(p) and int(p) < 256 for p in labels):
            return host, True
        raise Refused("numeric host that is not a plain dotted IP address")
    if not all(_LABEL.fullmatch(label) for label in labels):
        raise Refused("host name has unexpected characters")
    return host, False


def _parse_port(text, scheme):
    if not text:
        return 443 if scheme == "https" else 80
    if not _PORT.fullmatch(text) or not 0 < int(text) < 65536:
        raise Refused("bad port")
    return int(text)


def _normalize(url):
    if not isinstance(url, str):
        raise Refused("malformed URL")
    if len(url) > MAX_URL_INPUT:
        raise Refused("URL is too long")
    if any(_bad_char(ch) for ch in url):
        raise Refused("URL has control characters or whitespace")
    parts = urllib.parse.urlsplit(url)
    scheme = parts.scheme.lower()
    if scheme not in ("http", "https"):
        raise Refused("only http and https are allowed")
    if "@" in parts.netloc:
        raise Refused("URLs with user-info are refused")
    host_text, port_text, bracketed = _split_netloc(parts.netloc)
    if bracketed:
        host, is_ip = _ipv6_literal(host_text), True
        url_host = "[%s]" % host
    else:
        host, is_ip = _normalize_host(host_text)
        url_host = host
    port = _parse_port(port_text, scheme)
    path = _encode(parts.path or "/", _PATH_SAFE)
    if parts.query:
        path += "?" + _encode(parts.query, _QUERY_SAFE)
    default_port = 443 if scheme == "https" else 80
    out = "%s://%s%s%s" % (scheme, url_host, "" if port == default_port else ":%d" % port, path)
    if len(out) > MAX_URL_ENCODED:
        raise Refused("URL is too long")
    return Target(scheme, host, port, path, is_ip, out)


def _target(url):
    """Validate and normalize one absolute http(s) URL. Any problem is a Refused with fixed text."""
    try:
        return _normalize(url)
    except Refused:
        raise
    except (ValueError, UnicodeError, TypeError):
        raise Refused("malformed URL") from None


def parse_url(url):
    """Returns (scheme, host, port, request_target, is_ip); host is ASCII (IDNA / canonical IP)."""
    t = _target(url)
    return t.scheme, t.host, t.port, t.path, t.is_ip


def normalize_url(url):
    """The percent-encoded ASCII form of url that is fetched and reported."""
    return _target(url).url


def _display_url(url):
    """ASCII form of a user-supplied URL for error reports (never raises)."""
    try:
        return _target(url).url
    except Exception:
        pass
    try:
        return urllib.parse.quote(str(url), safe=_DISPLAY_SAFE, errors="replace")[:MAX_URL_ENCODED]
    except Exception:
        return ""


def _next_hop(current, location):
    """Resolve a Location header against the current URL and validate the result."""
    try:
        text = location.encode("latin-1").decode("utf-8")
        joined = urllib.parse.urldefrag(urllib.parse.urljoin(current.url, text))[0]
    except (ValueError, UnicodeError, TypeError, AttributeError):
        raise Refused("malformed redirect Location header") from None
    try:
        nxt = _target(joined)
    except Refused as exc:
        raise Refused("redirect refused: %s" % exc) from None
    if current.scheme == "https" and nxt.scheme == "http":
        raise Refused("redirect from https to http is refused")
    return nxt


# ---------------------------------------------------------------- deadline, DNS, sockets

def default_deadline(timeout):
    return min(timeout * 3 + 10, MAX_DEADLINE)


def _shut(sock):
    """Abort a socket from the watchdog thread. shutdown() wakes a blocked recv on POSIX; on Windows
    only closing the descriptor does, and sock.close() would wait for http.client's file objects,
    so the descriptor is detached and closed directly. Works under an SSLSocket as well."""
    try:
        socket.socket.shutdown(sock, socket.SHUT_RDWR)
    except (OSError, ValueError, TypeError):
        pass
    try:
        socket.close(socket.socket.detach(sock))
    except (OSError, ValueError, TypeError, OverflowError):
        pass


class _Watchdog:
    """Hard wall-clock limit: when it expires, the socket in use is shut down from a timer thread."""

    def __init__(self, seconds):
        self.end = time.monotonic() + seconds
        self.fired = False
        self._lock = threading.Lock()
        self._sock = None
        self._timer = threading.Timer(seconds, self._fire)
        self._timer.daemon = True
        self._timer.start()

    def remaining(self):
        return self.end - time.monotonic()

    def expired(self):
        return self.fired or self.remaining() <= 0

    def check(self):
        if self.expired():
            raise DeadlineExceeded()

    def watch(self, sock):
        with self._lock:
            self._sock = sock
            fired = self.fired
        if fired and sock is not None:
            _shut(sock)

    def _fire(self):
        with self._lock:
            self.fired = True
            sock = self._sock
        if sock is not None:
            _shut(sock)

    def cancel(self):
        self._timer.cancel()


def resolve(host, port, allow_private, dog=None):
    """Resolve and vet. Returns the address to connect to. Every answer must pass the check."""
    box = {}

    def lookup():
        try:
            box["infos"] = socket.getaddrinfo(host, port, type=socket.SOCK_STREAM)
        except Exception:
            box["failed"] = True

    if dog is None:
        lookup()
    else:
        worker = threading.Thread(target=lookup, name="fetch-page-dns", daemon=True)
        worker.start()
        worker.join(max(0.0, dog.remaining()))
        if worker.is_alive():
            raise DeadlineExceeded()
    addrs = []
    for info in box.get("infos") or ():
        ip = info[4][0]
        if ip not in addrs:
            addrs.append(ip)
    if not addrs:
        raise DNSFailure()
    for ip in addrs:
        check_address(ip, allow_private)
    return addrs[0]


def _open_socket(ip, port, timeout, dog):
    dog.check()
    sock = socket.create_connection((ip, port), max(0.01, min(timeout, dog.remaining())))
    try:
        dog.watch(sock)
        sock.settimeout(timeout)
        dog.check()
    except BaseException:
        sock.close()
        raise
    return sock


class _PinnedHTTP(http.client.HTTPConnection):
    def __init__(self, host, port, ip, timeout, dog):
        super().__init__(host, port, timeout=timeout)
        self._pinned_ip = ip
        self._dog = dog

    def connect(self):
        self.sock = _open_socket(self._pinned_ip, self.port, self.timeout, self._dog)


class _PinnedHTTPS(http.client.HTTPSConnection):
    def __init__(self, host, port, ip, timeout, context, dog):
        super().__init__(host, port, timeout=timeout, context=context)
        self._pinned_ip = ip
        self._ctx = context
        self._dog = dog

    def connect(self):
        raw = _open_socket(self._pinned_ip, self.port, self.timeout, self._dog)
        try:
            tls = self._ctx.wrap_socket(raw, server_hostname=self.host, do_handshake_on_connect=False)
        except BaseException:
            raw.close()
            raise
        self.sock = tls
        self._dog.watch(tls)            # the handshake below is covered by the watchdog too
        tls.do_handshake()
        self._dog.check()


# ---------------------------------------------------------------- body

INCOMPLETE = frozenset(("size-cap-reached", "body-shorter-than-content-length", "connection-closed-early",
                        "compressed-stream-truncated", "compressed-stream-corrupt",
                        "too-many-compressed-members"))
_CODINGS = {"": "identity", "identity": "identity", "gzip": "gzip", "x-gzip": "gzip", "deflate": "deflate",
            "br": "br", "zstd": "zstd", "compress": "compress", "x-compress": "compress"}
UNDECODED = " (left undecoded)"
_MEDIA_TYPE = re.compile(r"[a-z0-9][a-z0-9!#$&^_.+-]{0,62}/[a-z0-9][a-z0-9!#$&^_.+-]{0,62}")


def _content_type(header):
    value = (header or "").split(";", 1)[0].strip().lower()
    return value if _MEDIA_TYPE.fullmatch(value) else "unknown"


def _read_body(resp, cap, dog):
    """Read at most cap bytes, one system call at a time. Returns (data, integrity_warnings)."""
    declared = getattr(resp, "length", None)    # Content-Length when valid and not chunked
    chunks, total, warnings = [], 0, []
    while True:
        dog.check()
        try:
            chunk = resp.read1(min(65536, cap + 1 - total))
        except http.client.IncompleteRead:
            dog.check()
            warnings.append("connection-closed-early")
            break
        if not chunk:
            break
        chunks.append(chunk)
        total += len(chunk)
        if total > cap:
            warnings.append("size-cap-reached")
            break
    dog.check()
    if total <= cap and isinstance(declared, int) and total < declared:
        warnings.append("body-shorter-than-content-length")
    return b"".join(chunks)[:cap], warnings


def _inflate(data, wbits, cap, multi):
    """Bounded, linear-time zlib/gzip/raw-deflate decoding. With multi, every gzip member is decoded.

    Input is fed in INFLATE_STEP slices, so the decompressor never copies more than one slice of
    leftover input per member. Returns (output, integrity_warnings)."""
    out, total, members, pos, pending = [], 0, 0, 0, b""
    d = zlib.decompressobj(wbits)
    while True:
        if not pending:
            if pos >= len(data):
                return b"".join(out), ["compressed-stream-truncated"]
            pending = data[pos:pos + INFLATE_STEP]
            pos += INFLATE_STEP
        try:
            piece = d.decompress(pending, cap + 1 - total)
        except zlib.error:
            return b"".join(out)[:cap], ["compressed-stream-corrupt"]
        out.append(piece)
        total += len(piece)
        if total > cap:
            return b"".join(out)[:cap], ["size-cap-reached"]
        if d.eof:
            members += 1
            pending = d.unused_data
            if not pending and pos >= len(data):
                return b"".join(out), []
            if not multi:
                return b"".join(out), ["compressed-stream-corrupt"]     # data after the end of the stream
            if members >= MAX_GZIP_MEMBERS:
                return b"".join(out), ["too-many-compressed-members"]
            d = zlib.decompressobj(wbits)
        else:
            tail = d.unconsumed_tail
            if not piece and len(tail) == len(pending):                  # no progress: never loop
                return b"".join(out), ["compressed-stream-corrupt"]
            pending = tail


def _decode_body(data, header, cap):
    """Undo gzip/deflate if a server sent it anyway. Returns (body, encoding_label, warnings)."""
    label = _CODINGS.get((header or "").strip().lower(), "other")
    if label == "identity" or not data:
        return data, label, []
    if label == "gzip":
        out, warnings = _inflate(data, 16 + zlib.MAX_WBITS, cap, multi=True)
    elif label == "deflate":
        out, warnings = _inflate(data, zlib.MAX_WBITS, cap, multi=False)
        if not out and warnings == ["compressed-stream-corrupt"]:     # raw deflate without zlib header
            out, warnings = _inflate(data, -zlib.MAX_WBITS, cap, multi=False)
    else:
        return data, label + UNDECODED, ["content-encoding-not-decoded"]
    if not out and "compressed-stream-corrupt" in warnings:
        return data, label + UNDECODED, warnings + ["content-encoding-not-decoded"]
    return out, label, warnings


# ---------------------------------------------------------------- output

_OPEN_FLAGS = (os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_BINARY", 0)
               | getattr(os, "O_NOFOLLOW", 0) | getattr(os, "O_CLOEXEC", 0))


def _is_link_or_junction(path):
    try:
        st = os.lstat(path)
    except OSError:
        return False
    return stat.S_ISLNK(st.st_mode) or bool(getattr(st, "st_file_attributes", 0)
                                            & stat.FILE_ATTRIBUTE_REPARSE_POINT)


def check_out_dir(out_dir):
    """Refuse unless out_dir does not exist yet or is an empty real directory. Creates nothing."""
    if not isinstance(out_dir, str) or not out_dir or "\x00" in out_dir:
        raise Refused("--out is not a usable path")
    if not os.path.lexists(out_dir):
        return
    if _is_link_or_junction(out_dir):
        raise Refused("--out is a symlink or junction")
    if not os.path.isdir(out_dir):
        raise Refused("--out exists and is not a directory")
    try:
        with os.scandir(out_dir) as entries:
            not_empty = next(entries, None) is not None
    except OSError:
        raise Refused("--out cannot be listed") from None
    if not_empty:
        raise Refused("--out exists and is not empty")


def _write_new_file(path, data):
    """Create path (never an existing file or link) and write all of data."""
    fd = os.open(path, _OPEN_FLAGS, 0o666)
    try:
        view = memoryview(data)
        while view:
            written = os.write(fd, view)
            if written <= 0:
                raise OSError("short write")
            view = view[written:]
    except BaseException:
        os.close(fd)
        try:
            os.unlink(path)
        except OSError:
            pass
        raise
    os.close(fd)


def _save(out_dir, name, body):
    check_out_dir(out_dir)                  # again, right before writing
    try:
        os.makedirs(out_dir, exist_ok=True)
    except OSError:
        raise OutputError("could not create the output directory") from None
    if _is_link_or_junction(out_dir) or not os.path.isdir(out_dir):
        raise Refused("--out is a symlink or junction")
    path = os.path.join(out_dir, name)
    try:
        _write_new_file(path, body)
    except FileExistsError:
        raise Refused("the output file already exists") from None
    except OSError:
        raise OutputError("could not write the output file") from None
    return os.path.abspath(path)


# ---------------------------------------------------------------- fetch

_Download = collections.namedtuple("_Download", "target chain status ip raw warnings ctype encoding")


def _download(target, max_bytes, timeout, allow_private, dog):
    chain, context, current = [], None, target
    for hop in range(MAX_REDIRECTS + 1):
        dog.check()
        if current.is_ip:
            check_address(current.host, allow_private)
            ip = current.host
        else:
            ip = resolve(current.host, current.port, allow_private, dog)
        if current.scheme == "https":
            if context is None:
                context = ssl.create_default_context()
            conn = _PinnedHTTPS(current.host, current.port, ip, timeout, context, dog)
        else:
            conn = _PinnedHTTP(current.host, current.port, ip, timeout, dog)
        try:
            conn.request("GET", current.path, headers=REQUEST_HEADERS)
            dog.check()
            resp = conn.getresponse()
            dog.check()
            locations = [str(v).strip(" \t") for v in (resp.headers.get_all("Location") or ())]
            if resp.status in REDIRECT_CODES and any(locations):
                chain.append(current.url)
                if hop >= MAX_REDIRECTS:
                    raise Refused("more than %d redirects" % MAX_REDIRECTS)
                if len(locations) != 1:
                    raise Refused("redirect with more than one Location header")
                current = _next_hop(current, locations[0])
                continue
            raw, warnings = _read_body(resp, max_bytes, dog)
            return _Download(current, chain, resp.status, ip, raw, warnings,
                             resp.getheader("Content-Type"), resp.getheader("Content-Encoding"))
        finally:
            dog.watch(None)
            conn.close()
    raise Refused("more than %d redirects" % MAX_REDIRECTS)


def fetch(url, out_dir, max_bytes=5_000_000, timeout=20.0, allow_private=False, deadline=None):
    """Fetch one URL into out_dir. Returns (report_dict, exit_code).

    Raises Refused or OutputError, or OSError / http.client.HTTPException for network errors
    (DeadlineExceeded when the overall deadline passes). Nothing is written unless it returns."""
    target = _target(url)
    check_out_dir(out_dir)
    dog = _Watchdog(default_deadline(timeout) if deadline is None else deadline)
    try:
        got = _download(target, max_bytes, timeout, allow_private, dog)
        body, encoding, more = _decode_body(got.raw, got.encoding, max_bytes)
        dog.check()
    except Refused:
        raise
    except Exception:
        if dog.expired():       # errors caused by the watchdog, or by a timeout clamped to the deadline
            raise DeadlineExceeded() from None
        raise
    finally:
        dog.cancel()
    integrity = list(dict.fromkeys(got.warnings + more))
    ctype = _content_type(got.ctype)
    digest = hashlib.sha256(body).hexdigest()
    saved_to = _save(out_dir, "page-%s%s" % (digest[:16], EXTENSIONS.get(ctype, ".bin")), body)
    report = {
        "url": target.url, "final_url": got.target.url, "redirects": list(got.chain),
        "status": got.status, "content_type": ctype, "content_encoding": encoding,
        "sha256": digest, "size": len(body), "truncated": any(w in INCOMPLETE for w in integrity),
        "integrity": integrity, "resolved_ip": str(ipaddress.ip_address(got.ip)), "saved_to": saved_to,
        "note": NOTE,
    }
    if not 200 <= got.status < 300:
        return report, 1
    return report, (4 if integrity else 0)


# ---------------------------------------------------------------- CLI

_NETWORK_REASONS = (
    (DeadlineExceeded, "overall deadline exceeded"),
    (DNSFailure, "DNS resolution failed"),
    (ssl.SSLCertVerificationError, "TLS certificate verification failed"),
    (ssl.SSLError, "TLS error"),
    (http.client.RemoteDisconnected, "server closed the connection without a response"),
    (TimeoutError, "socket timeout"),
    (ConnectionRefusedError, "connection refused"),
    (ConnectionResetError, "connection reset"),
    (ConnectionAbortedError, "connection aborted"),
    (http.client.BadStatusLine, "malformed status line"),
    (http.client.LineTooLong, "header or chunk line too long"),
    (http.client.IncompleteRead, "incomplete response"),
    (http.client.HTTPException, "HTTP protocol error"),
)


def _network_reason(exc):
    text = next((t for cls, t in _NETWORK_REASONS if isinstance(exc, cls)), "network error")
    return "%s: %s" % (_class_name(exc), text)


def _emit(obj, pretty=False):
    text = json.dumps(obj, ensure_ascii=True, indent=1 if pretty else None, sort_keys=pretty)
    try:
        sys.stdout.write(text + "\n")
        sys.stdout.flush()
    except (OSError, ValueError):
        pass


def _main(argv):
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("url")
    ap.add_argument("--out", required=True, metavar="DIR",
                    help="new or empty directory to save into (created if missing)")
    ap.add_argument("--max-bytes", type=int, default=5_000_000, help="size cap, 1..200000000")
    ap.add_argument("--timeout", type=float, default=20.0, metavar="SEC", help="socket timeout, 0..120")
    ap.add_argument("--deadline", type=float, default=None, metavar="SEC",
                    help="hard overall time limit, 0..600 (default: 3 * timeout + 10)")
    ap.add_argument("--allow-private", action="store_true",
                    help="TESTS ONLY: allow loopback/private addresses (never use on real input)")
    try:
        args = ap.parse_args(argv)
    except SystemExit as exc:
        return 0 if exc.code in (0, None) else 2
    if not (1 <= args.max_bytes <= 200_000_000 and 0 < args.timeout <= 120
            and (args.deadline is None or 0 < args.deadline <= MAX_DEADLINE)):
        sys.stderr.write("error: --max-bytes must be 1..200000000, --timeout 0..120 and --deadline 0..600\n")
        return 2
    if args.allow_private:
        sys.stderr.write("warning: --allow-private disables the SSRF guard; for local tests only\n")
    try:
        report, code = fetch(args.url, args.out, args.max_bytes, args.timeout, args.allow_private,
                             args.deadline)
    except Refused as exc:
        _emit({"url": _display_url(args.url), "error": "refused", "reason": _cap(exc, 200)})
        return 2
    except OutputError as exc:
        _emit({"url": _display_url(args.url), "error": "output", "reason": _cap(exc, 200)})
        return 2
    except (OSError, http.client.HTTPException) as exc:
        _emit({"url": _display_url(args.url), "error": "network", "reason": _network_reason(exc)})
        return 3
    _emit(report, pretty=True)
    return code


def main(argv=None):
    try:
        return _main(argv)
    except KeyboardInterrupt:
        _emit({"error": "interrupted"})
        return 130
    except Exception as exc:    # last resort: no traceback and no exception text, only the class name
        _emit({"error": "internal", "exception": _class_name(exc)})
        return 5


if __name__ == "__main__":
    sys.exit(main())
