"""Command line interface for vetscan."""
import argparse
import json
import os
import sys

from . import __version__, baseline, report
from .engine import Options, Scan

USAGE = """\
Static scanner for third-party agent skills, plugins, MCP configs, repositories
and saved web pages. Reads files only: it never executes, imports, installs or
fetches anything it scans. Findings are leads for a careful reader, not proof.

exit codes: 0 = nothing at or above --fail-on, 1 = findings at or above
--fail-on, 2 = usage or I/O error (or an internal error; never a traceback)
"""


def build_parser():
    ap = argparse.ArgumentParser(prog="scan.py", description=USAGE,
                                 formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("path", nargs="?", help="file or directory to scan")
    ap.add_argument("--kind", choices=["auto", "skill", "article", "page", "repo", "mcp"], default="auto",
                    help="what the target is (default: auto-detect). article = a write-up a human vets "
                         "(visible injection wording is MED: quotes expected); page = content an agent will "
                         "read or act on, such as fetched pages and tool output (visible override, concealment "
                         "and exfiltration wording is HIGH unless framed as an example)")
    ap.add_argument("--format", choices=["md", "json", "sarif"], default="md")
    ap.add_argument("--fail-on", choices=["HIGH", "MED", "LOW", "NONE"], default="HIGH",
                    help="lowest severity that makes the exit code 1 (default: HIGH)")
    ap.add_argument("--baseline", metavar="FILE",
                    help="allow-list of reviewed findings (hash-bound, each with a justification)")
    ap.add_argument("--emit-baseline", action="store_true",
                    help="print a baseline skeleton for the current findings (justifications left empty) and exit")
    ap.add_argument("--max", type=int, default=120, metavar="N", help="max findings shown in the md table")
    ap.add_argument("--max-bytes", type=int, default=8_000_000, metavar="N",
                    help="per-file size fully scanned; larger files get head+tail only (default 8000000)")
    ap.add_argument("--max-files", type=int, default=20_000, metavar="N")
    ap.add_argument("--time-budget", type=float, default=600.0, metavar="SEC", help="whole-run time budget")
    ap.add_argument("--file-budget", type=float, default=20.0, metavar="SEC", help="per-file time budget")
    ap.add_argument("--no-archives", action="store_true", help="do not list/scan archive members")
    ap.add_argument("--include-vendored", action="store_true",
                    help="also scan node_modules, venv and similar dependency directories")
    ap.add_argument("--dump-streams", action="store_true",
                    help="also print, sanitized and with line numbers, the text the scanner derived per file: "
                         "visible / hidden / attribute / comment / metadata streams of pages, archive members, "
                         "decoded payloads, legacy-decoded text and PDF text. Read hidden or encoded content "
                         "this way instead of opening the raw file")
    ap.add_argument("--dump-filter", metavar="TEXT",
                    help="with --dump-streams: only files whose reported path contains TEXT "
                         "(an archive member is reported as archive!/member)")
    ap.add_argument("--list-rules", action="store_true", help="print the rule table and exit")
    ap.add_argument("--version", action="version", version="vetscan " + __version__)
    return ap


def _write(text):
    data = text.encode("utf-8", "replace")
    try:
        sys.stdout.buffer.write(data)
        sys.stdout.buffer.flush()
    except (AttributeError, ValueError):
        sys.stdout.write(text)


def main(argv=None):
    """Never shows a traceback: an unexpected error is reported in one line and exits with 2."""
    try:
        return _main(argv)
    except KeyboardInterrupt:
        sys.stderr.write("error: interrupted\n")
        return 130
    except Exception as exc:     # last resort; the class name only, no message from scanned content
        sys.stderr.write("error: internal error (%s); the scan did not complete\n" % type(exc).__name__)
        return 2


def _inside(path, root):
    """True when path lies inside root. False on different drives or unrelated paths (never raises)."""
    try:
        return os.path.commonpath([path, root]) == root
    except ValueError:            # different drives on Windows, or mixed absolute and relative paths
        return False


def _exists(fn, path):
    try:
        return fn(path)
    except (ValueError, OSError):     # embedded NUL byte, path too long, unencodable name
        return False


def _main(argv=None):
    ap = build_parser()
    try:
        args = ap.parse_args(argv)
    except SystemExit as exc:
        return 0 if exc.code in (0, None) else 2
    if args.list_rules:
        from . import archives, coderules, configs, invisible, phrases  # noqa: F401  (registers rules)
        _write(report.rule_table())
        return 0
    if not args.path:
        ap.print_usage(sys.stderr)
        sys.stderr.write("error: a path is required\n")
        return 2
    if not _exists(os.path.lexists, args.path):
        sys.stderr.write("error: path not found\n")
        return 2
    if args.dump_filter:
        args.dump_streams = True
    if args.max < 1 or args.max_bytes < 1024 or args.max_files < 1 or args.time_budget <= 0 or args.file_budget <= 0:
        sys.stderr.write("error: numeric options must be positive (--max-bytes at least 1024)\n")
        return 2
    opts = Options(kind=args.kind, max_bytes=args.max_bytes, max_files=args.max_files,
                   file_budget=args.file_budget, total_budget=args.time_budget,
                   scan_archives=not args.no_archives, include_vendored=args.include_vendored,
                   dump_streams=args.dump_streams, dump_filter=args.dump_filter)
    try:
        scan = Scan(opts).run(args.path)
    except OSError as exc:
        sys.stderr.write("error: cannot scan target (%s)\n" % type(exc).__name__)
        return 2
    if args.emit_baseline:
        _write(json.dumps(baseline.template([f for f in scan.findings if f.sev != "LOW"]),
                          ensure_ascii=True, indent=1) + "\n")
        return 0
    entries, problems = ([], [])
    if args.baseline:
        if not _exists(os.path.isfile, args.baseline):
            sys.stderr.write("error: baseline file not found\n")
            return 2
        entries, problems = baseline.load(args.baseline)
        base_abs = os.path.abspath(args.baseline)
        root_abs = os.path.abspath(args.path)
        if os.path.isdir(root_abs) and _inside(base_abs, root_abs):
            problems.append("note: the baseline file lives inside the scanned tree. That is fine for your own "
                            "code; never accept a baseline shipped by the thing you are vetting")
    kept, suppressed, stale = baseline.apply(scan.findings, entries, scan.sha)
    summary = report.summarize(scan, kept, suppressed, stale, problems,
                               os.path.basename(args.baseline) if args.baseline else None)
    if entries:
        # Wherever the baseline file lives, an entry bound to a file of this target can hide findings.
        hashes = set(scan.sha.values())
        bound = sum(1 for e in entries if e["sha256"] in hashes)
        if bound:
            msg = ("baseline %s: %d entr%s bound by SHA-256 to files of the scanned target; %d finding(s) "
                   "suppressed. Accept a baseline only if you wrote it for your own code." % (
                       os.path.basename(args.baseline), bound, "y is" if bound == 1 else "ies are", len(suppressed)))
            sys.stderr.write("warning: " + msg + "\n")
            if not suppressed:
                summary["warnings"].append(msg)
    if args.format == "json":
        _write(report.to_json(scan, args.path, kept, suppressed, summary))
    elif args.format == "sarif":
        _write(report.to_sarif(scan, args.path, kept, summary))
    else:
        _write(report.to_markdown(scan, args.path, kept, suppressed, summary, args.max))
    return 1 if report.threshold_reached(summary["totals"], args.fail_on) else 0
