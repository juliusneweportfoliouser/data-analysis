"""
AI Generated
Cowrie SSH Honeypot Log Analyzer

Analyzes JSON log files from a modified Cowrie honeypot, producing
summaries of attacker activity: connections, credential brute-forcing,
successful logins, commands executed, files transferred, and TCP tunneling.
"""

import argparse
import json
import os
import glob
import re
import shlex
import statistics
from collections import Counter, defaultdict
from datetime import datetime
from typing import Optional


DEFAULT_DATA_DIR = os.path.join(os.path.dirname(__file__), "data")


# ---------------------------------------------------------------------------
# Download detection (parsed from cowrie.command.input for cross-backend parity)
#
# The shell backend emits cowrie.session.file_download natively from its
# wget/curl/ftpget/tftp command modules; the LLM backend has no such modules
# and cannot emit this event, so downloads are extracted here from the
# command.input strings. Applying the same parser to both backends gives an
# apples-to-apples comparison.
# ---------------------------------------------------------------------------

_DOWNLOAD_TOOLS = ("wget", "curl", "ftpget", "tftp", "fetch", "aria2c")
_SHELL_SEP_RE = re.compile(r"\s*(?:\|\||&&|[;|&\n])\s*")

# Matches anything that looks like a URL target:
#   - http(s)://... or ftp://...
#   - bare IPv4 (optionally with port and path)
#   - bare domain (e.g. example.com, google.com/path) — must contain at least
#     one dot and an alphabetic TLD of 2+ chars to avoid matching filenames
#     like "file.sh" (TLD starts with a letter so "sh" matches, but we filter
#     out tokens that start with "./" or "/" — those are paths, not hosts).
_URL_ARG_RE = re.compile(
    r"""^(
        https?://[^\s<>"'|;&`()]+
        | ftp://[^\s<>"'|;&`()]+
        | tftp://[^\s<>"'|;&`()]+
        | \d{1,3}(?:\.\d{1,3}){3}(?::\d+)?(?:/[^\s<>"'|;&`()]*)?
        | (?:[A-Za-z0-9-]+\.)+[A-Za-z]{2,}(?::\d+)?(?:/[^\s<>"'|;&`()]*)?
    )$""",
    re.VERBOSE,
)

_GENERIC_OPTION_VALUE_FLAGS = {
    "wget": {
        "-O", "-U", "-e", "--output-document", "--user-agent", "--execute",
        "--header", "--post-data", "--post-file", "--referer",
    },
    "curl": {
        "-o", "-A", "-H", "-b", "-c", "-d", "-e", "-F", "-u", "-X",
        "--output", "--user-agent", "--header", "--cookie", "--cookie-jar",
        "--data", "--data-raw", "--data-binary", "--referer", "--form",
        "--user", "--request", "--connect-timeout", "--max-time",
    },
    "fetch": {"-o", "--output"},
    "aria2c": {"-o", "-d", "--out", "--dir", "--user-agent", "--header"},
}


def _shell_tokens(segment: str) -> list[str]:
    """Split one shell-ish segment, falling back for malformed attacker input."""
    try:
        return shlex.split(segment)
    except ValueError:
        return segment.split()


def _clean_shell_token(token: str) -> str:
    return token.strip().strip("()`\"'")


def _clean_tool_token(token: str) -> str:
    stripped = token.lstrip("({$\"'`").strip()
    stripped = stripped.rsplit("/", 1)[-1]
    return stripped.lower()


def _looks_like_remote_target(arg: str) -> str | None:
    arg = _clean_shell_token(arg)
    if not arg or arg.startswith(("/", "./", "../", "~", "$")):
        return None
    m = _URL_ARG_RE.match(arg)
    return m.group(1) if m else None


def _scheme_for_tool(tool: str) -> str:
    if tool == "ftpget":
        return "ftp"
    if tool == "tftp":
        return "tftp"
    return "http"


def _normalize_download_url(tool: str, target: str, remote_path: str | None = None) -> str:
    target = _clean_shell_token(target)
    if target.startswith(("http://", "https://", "ftp://", "tftp://")):
        url = target
    else:
        url = f"{_scheme_for_tool(tool)}://{target}"
    if remote_path and "/" not in url.split("://", 1)[1]:
        url = url.rstrip("/") + "/" + _clean_shell_token(remote_path).lstrip("/")
    return url


def _flag_consumes_next(tool: str, arg: str) -> bool:
    if "=" in arg:
        return False
    flags = _GENERIC_OPTION_VALUE_FLAGS.get(tool, set())
    return arg in flags


def _extract_generic_download(tool: str, args: list[str]) -> dict | None:
    skip_next = False
    for arg in args:
        if skip_next:
            skip_next = False
            continue
        arg = _clean_shell_token(arg)
        if not arg:
            continue
        if _flag_consumes_next(tool, arg):
            skip_next = True
            continue
        if arg.startswith("-"):
            continue
        target = _looks_like_remote_target(arg)
        if target:
            return {"tool": tool, "url": _normalize_download_url(tool, target)}
    return None


def _extract_ftpget_download(args: list[str]) -> dict | None:
    positional: list[str] = []
    i = 0
    while i < len(args):
        arg = _clean_shell_token(args[i])
        if arg in {"-u", "-p", "-P", "--username", "--password", "--port"}:
            i += 2
            continue
        if arg.startswith("-"):
            i += 1
            continue
        positional.append(arg)
        i += 1

    if not positional:
        return None
    host = _looks_like_remote_target(positional[0])
    if not host:
        return None
    # BusyBox ftpget syntax is: ftpget [opts] HOST LOCAL_FILE REMOTE_FILE.
    remote = positional[2] if len(positional) >= 3 else None
    return {"tool": "ftpget", "url": _normalize_download_url("ftpget", host, remote)}


def _extract_tftp_download(args: list[str]) -> dict | None:
    positional: list[str] = []
    remote: str | None = None
    i = 0
    while i < len(args):
        arg = _clean_shell_token(args[i])
        if arg in {"-r", "--remote-file"} and i + 1 < len(args):
            remote = args[i + 1]
            i += 2
            continue
        if arg in {"-l", "--local-file", "-b", "--blocksize"}:
            i += 2
            continue
        if arg == "-c":
            # Netkit tftp style: tftp HOST -c get REMOTE_FILE
            if i + 2 < len(args) and args[i + 1].lower() == "get":
                remote = args[i + 2]
                i += 3
                continue
            i += 2
            continue
        if arg.startswith("-"):
            i += 1
            continue
        positional.append(arg)
        i += 1

    for arg in positional:
        host = _looks_like_remote_target(arg)
        if host:
            return {"tool": "tftp", "url": _normalize_download_url("tftp", host, remote)}
    return None


def extract_downloads_from_command(cmd: str) -> list[dict]:
    """Parse a command line for wget/curl/ftpget/tftp invocations.

    Splits on shell separators so one line can emit multiple downloads
    (e.g. ``wget http://a; curl http://b``). Bare-IP and bare-domain URLs
    are prefixed with ``http://`` so the returned URL is always scheme-
    qualified.

    Tokenizes each segment with ``shlex`` and finds the first non-option
    token after the download tool that looks like a URL/host. Tool-specific
    handling avoids false positives on output filenames and catches common
    forms like ``curl -O URL`` and ``tftp -g -r FILE HOST``.

    Returns a list of dicts with ``tool`` and ``url`` keys.
    """
    if not cmd:
        return []
    results: list[dict] = []
    for seg in _SHELL_SEP_RE.split(cmd):
        tokens = _shell_tokens(seg)
        for i, tok in enumerate(tokens):
            # Strip leading shell grouping chars so subshells `(wget...)`,
            # command substitutions `$(wget)`, and quoted invocations match.
            tool = _clean_tool_token(tok)
            if tool not in _DOWNLOAD_TOOLS:
                continue
            args = tokens[i + 1:]
            if tool == "ftpget":
                result = _extract_ftpget_download(args)
            elif tool == "tftp":
                result = _extract_tftp_download(args)
            else:
                result = _extract_generic_download(tool, args)
            if result:
                results.append(result)
            # Only the first tool invocation per segment is considered.
            break
    return results


def load_logs(
    data_dir: str = DEFAULT_DATA_DIR,
    start_date: str | None = None,
    end_date: str | None = None,
    include_current: bool = True,
) -> list[dict]:
    """Load all Cowrie JSON log files from the data directory."""
    log_dir = os.path.join(data_dir, "cowrie_logs")
    events = []
    for path in sorted(glob.glob(os.path.join(log_dir, "cowrie.json*"))):
        name = os.path.basename(path)
        m = re.fullmatch(r"cowrie\.json\.(\d{4}-\d{2}-\d{2})", name)
        if name == "cowrie.json":
            if not include_current:
                continue
        elif m:
            day = m.group(1)
            if start_date and day < start_date:
                continue
            if end_date and day > end_date:
                continue
        elif start_date or end_date:
            continue
        with open(path, encoding="utf-8") as f:
            for line in f:
                line = line.strip()
                if line:
                    event = json.loads(line)
                    if start_date or end_date:
                        ts = event.get("timestamp") or ""
                        day = ts[:10] if len(ts) >= 10 else None
                        if not day:
                            continue
                        if start_date and day < start_date:
                            continue
                        if end_date and day > end_date:
                            continue
                    events.append(event)
    events.sort(key=lambda e: e.get("timestamp") or "")
    return events


def load_token_map(data_dir: str = DEFAULT_DATA_DIR) -> Optional[list[dict]]:
    """Load the token-to-session mapping file if it exists."""
    path = os.path.join(data_dir, "token_session_map.json")
    if not os.path.isfile(path):
        return None

    tokens = []
    with open(path, encoding="utf-8") as f:
        for line in f:
            line = line.strip()
            if line:
                tokens.append(json.loads(line))
    return tokens


# ---------------------------------------------------------------------------
# Analysis helpers
# ---------------------------------------------------------------------------

def summarize_connections(events: list[dict]) -> dict:
    """High-level connection statistics."""
    connects = [e for e in events if e["eventid"] == "cowrie.session.connect"]
    unique_ips = {e["src_ip"] for e in connects}
    first_ts = min(e["timestamp"] for e in connects) if connects else None
    last_ts = max(e["timestamp"] for e in connects) if connects else None
    return {
        "total_connections": len(connects),
        "unique_source_ips": len(unique_ips),
        "time_range": f"{first_ts} -> {last_ts}",
    }


def top_source_ips(events: list[dict], n: int = 20) -> list[tuple[str, int]]:
    """Most active source IPs by connection count."""
    ips = [e["src_ip"] for e in events if e["eventid"] == "cowrie.session.connect"]
    return Counter(ips).most_common(n)


def top_credentials(events: list[dict], n: int = 20) -> list[tuple[str, int]]:
    """Most commonly attempted username/password pairs."""
    creds = [
        (e["username"], e["password"])
        for e in events
        if e["eventid"] in ("cowrie.login.failed", "cowrie.login.success")
    ]
    return Counter(creds).most_common(n)


def top_usernames(events: list[dict], n: int = 20) -> list[tuple[str, int]]:
    """Most commonly attempted usernames."""
    names = [
        e["username"]
        for e in events
        if e["eventid"] in ("cowrie.login.failed", "cowrie.login.success")
    ]
    return Counter(names).most_common(n)


def top_passwords(events: list[dict], n: int = 20) -> list[tuple[str, int]]:
    """Most commonly attempted passwords."""
    passwords = [
        e["password"]
        for e in events
        if e["eventid"] in ("cowrie.login.failed", "cowrie.login.success")
    ]
    return Counter(passwords).most_common(n)


def successful_logins(events: list[dict]) -> list[dict]:
    """All successful login events with key details."""
    results = []
    for e in events:
        if e["eventid"] == "cowrie.login.success":
            results.append({
                "timestamp": e["timestamp"],
                "src_ip": e["src_ip"],
                "session": e["session"],
                "username": e["username"],
                "password": e["password"],
            })
    return results


def session_details(events: list[dict]) -> dict[str, dict]:
    """Build a per-session summary: IP, login, commands, downloads, duration."""
    sessions = defaultdict(lambda: {
        "src_ip": None,
        "login": None,
        "commands": [],
        "downloads": [],
        "uploads": [],
        "tcp_forwards": [],
        "client_version": None,
        "hassh": None,
        "duration": None,
        "connected_at": None,
    })

    for e in events:
        sid = e.get("session")
        if not sid:
            continue
        s = sessions[sid]

        eid = e["eventid"]
        if eid == "cowrie.session.connect":
            s["src_ip"] = e["src_ip"]
            s["connected_at"] = e["timestamp"]
        elif eid == "cowrie.session.closed":
            s["duration"] = float(e.get("duration", 0))
        elif eid == "cowrie.client.version":
            s["client_version"] = e.get("version")
        elif eid == "cowrie.client.kex":
            s["hassh"] = e.get("hassh")
        elif eid == "cowrie.login.success":
            s["login"] = {"username": e["username"], "password": e["password"]}
        elif eid == "cowrie.command.input":
            cmd = e["input"]
            s["commands"].append(cmd)
            # Derive downloads from command text for cross-backend consistency
            # (LLM backend doesn't emit cowrie.session.file_download natively)
            for dl in extract_downloads_from_command(cmd):
                s["downloads"].append({
                    "type": "download",
                    "filename": dl["url"],
                    "tool": dl["tool"],
                    "shasum": None,
                })
        elif eid == "cowrie.file.download":
            # SFTP download (primarily canarytoken file reads in both backends)
            s["downloads"].append({
                "type": "download",
                "filename": e.get("filepath") or e.get("filename"),
                "tool": "sftp",
                "shasum": e.get("shasum"),
            })
        elif eid in ("cowrie.session.file_upload", "cowrie.session.upload_attempt"):
            # Shell emits cowrie.session.file_upload; the LLM backend emits
            # cowrie.session.upload_attempt (read-only rejection). Both mean
            # "attacker attempted an SFTP upload" — normalize them together.
            s["uploads"].append({
                "type": "upload",
                "filename": e.get("filename") or e.get("filepath") or e.get("destfile"),
                "shasum": e.get("shasum"),
            })
        elif eid == "cowrie.direct-tcpip.request":
            s["tcp_forwards"].append({
                "dst_ip": e["dst_ip"],
                "dst_port": e["dst_port"],
            })

    return dict(sessions)


def interesting_sessions(events: list[dict]) -> list[dict]:
    """Return sessions that had successful logins, showing their full activity."""
    all_sessions = session_details(events)
    results = []
    for sid, info in all_sessions.items():
        if info["login"]:
            results.append({"session_id": sid, **info})
    results.sort(key=lambda s: s["connected_at"] or "")
    return results


def ssh_client_fingerprints(events: list[dict]) -> list[tuple[str, int]]:
    """HASSH fingerprints ranked by frequency."""
    fingerprints = [e["hassh"] for e in events if e["eventid"] == "cowrie.client.kex"]
    return Counter(fingerprints).most_common()


def ssh_client_versions(events: list[dict]) -> list[tuple[str, int]]:
    """SSH client version strings ranked by frequency."""
    versions = [e["version"] for e in events if e["eventid"] == "cowrie.client.version"]
    return Counter(versions).most_common()


# ---------------------------------------------------------------------------
# SSH client banner classification + hands-on-keyboard detection
#
# The SSH version banner (cowrie.client.version) reveals the library or tool
# the attacker used to connect. Known automation libraries (libssh2, paramiko,
# Go's golang.org/x/crypto/ssh, AsyncSSH, ZGrab, Nmap, etc.) are essentially
# never used interactively — finding one of those banners is a near-certain
# bot signal. Interactive Windows GUI clients (PuTTY, WinSCP, KiTTY, …) are
# the opposite signal in spirit, but their banners are routinely SPOOFED by
# scanners, so we cannot trust an interactive-GUI banner on its own; behavior
# (multiple commands, human typing pace) has to corroborate.
# ---------------------------------------------------------------------------

_AUTOMATED_BANNER_PREFIXES = (
    "libssh2", "libssh_", "paramiko", "AsyncSSH", "Go",
    "ZGrab", "Nmap", "Fingerprintx", "perlssh", "russh",
    "OpenSSH-keyscan", "JSch", "scanssh", "MGLNDD",
)

_INTERACTIVE_BANNER_PREFIXES = (
    "PUTTY", "PuTTY", "WinSCP", "KiTTY", "MobaXterm",
    "SecureCRT", "Termius", "Bitvise",
)


def classify_ssh_client(banner: str | None) -> str:
    """Bucket an SSH client version banner.

    Returns one of:
      ``empty``           — no banner emitted
      ``non_ssh``         — does not start with SSH- (HTTP/RDP probes, etc.)
      ``automated``       — known automation library / scanner
      ``interactive_gui`` — known Windows GUI client (may be spoofed)
      ``openssh_cli``     — OpenSSH command-line (ambiguous)
      ``other``           — unrecognized SSH banner
    """
    if not banner:
        return "empty"
    if banner.startswith("SSH-2.0-"):
        body = banner[len("SSH-2.0-"):]
    elif banner.startswith("SSH-1.5-"):
        body = banner[len("SSH-1.5-"):]
    else:
        return "non_ssh"
    for prefix in _INTERACTIVE_BANNER_PREFIXES:
        if body.startswith(prefix):
            return "interactive_gui"
    for prefix in _AUTOMATED_BANNER_PREFIXES:
        if body.startswith(prefix):
            return "automated"
    if body.startswith(("OpenSSH_", "OPENSSH_")):
        return "openssh_cli"
    return "other"


def _parse_ts(ts: str | None) -> datetime | None:
    """Parse a Cowrie ISO-8601 timestamp; returns None on failure."""
    if not ts:
        return None
    if ts.endswith("Z"):
        ts = ts[:-1] + "+00:00"
    try:
        return datetime.fromisoformat(ts)
    except ValueError:
        return None


def hands_on_keyboard_sessions(
    events: list[dict],
    min_commands: int = 3,
    min_median_gap_s: float = 1.0,
    min_max_to_median_ratio: float = 2.0,
) -> dict:
    """Identify likely hands-on-keyboard (HOK) sessions.

    A session is HOK iff ALL of:
      - SSH client banner is NOT in the known-automation set
        (libssh2 / paramiko / Go / AsyncSSH / ZGrab / Nmap / …).
      - Session emitted >= ``min_commands`` separate command events
        (>= 3 by default so there are >= 2 inter-command gaps and timing
        variance is computable).
      - Median gap between consecutive command timestamps
        >= ``min_median_gap_s`` seconds (excludes rapid-fire scripts).
      - max(gap) / median(gap) >= ``min_max_to_median_ratio`` — i.e. the
        attacker had at least one "thinking pause" meaningfully longer
        than their typical pace. This rejects bots that mimic human pacing
        with a uniform ``sleep N`` between commands (their gaps are all
        equal so the ratio is ~1).

    Banner alone is unreliable — scanners spoof PuTTY/WinSCP banners — so
    the timing + multi-command behavioral check is what carries the weight.
    The banner exclusion only rules out libraries that nobody types into.

    Returns a dict with:
      ``sessions``        list of HOK session detail rows
      ``client_classes``  Counter of banner classification across all sessions
      ``active``          number of sessions with >= 1 command
      ``hok``             number of HOK sessions
      ``rate_active``     HOK as % of active sessions
      ``rate_total``      HOK as % of all sessions
    """
    banner: dict[str, str] = {}
    cmd_times: dict[str, list[datetime]] = defaultdict(list)
    src_ip: dict[str, str] = {}
    login_ok: set[str] = set()
    all_sids: set[str] = set()

    for e in events:
        sid = e.get("session")
        if not sid:
            continue
        eid = e["eventid"]
        if eid == "cowrie.session.connect":
            all_sids.add(sid)
            src_ip[sid] = e.get("src_ip", "")
        elif eid == "cowrie.client.version":
            banner[sid] = e.get("version", "") or ""
        elif eid == "cowrie.login.success":
            login_ok.add(sid)
        elif eid == "cowrie.command.input":
            ts = _parse_ts(e.get("timestamp"))
            if ts:
                cmd_times[sid].append(ts)

    client_classes: Counter[str] = Counter()
    for sid in all_sids:
        client_classes[classify_ssh_client(banner.get(sid))] += 1

    active = sum(1 for sid in all_sids if cmd_times.get(sid))

    hok_rows: list[dict] = []
    for sid in all_sids:
        times = sorted(cmd_times.get(sid, []))
        if len(times) < min_commands:
            continue
        cls = classify_ssh_client(banner.get(sid))
        if cls == "automated":
            continue
        gaps = [(times[i + 1] - times[i]).total_seconds() for i in range(len(times) - 1)]
        median_gap = statistics.median(gaps)
        if median_gap < min_median_gap_s:
            continue
        max_gap = max(gaps)
        # Avoid div-by-zero when median is 0 (degenerate, but guard anyway).
        ratio = (max_gap / median_gap) if median_gap > 0 else float("inf")
        if ratio < min_max_to_median_ratio:
            continue
        hok_rows.append({
            "session_id":    sid,
            "src_ip":        src_ip.get(sid, ""),
            "client_banner": banner.get(sid, ""),
            "client_class":  cls,
            "login_success": sid in login_ok,
            "command_count": len(times),
            "median_gap_s":  round(median_gap, 2),
            "max_gap_s":     round(max_gap, 2),
            "max_to_median": round(ratio, 2),
            "first_cmd_at":  times[0].isoformat(),
            "last_cmd_at":   times[-1].isoformat(),
        })
    hok_rows.sort(key=lambda r: -r["command_count"])

    hok = len(hok_rows)
    return {
        "sessions":       hok_rows,
        "client_classes": client_classes,
        "active":         active,
        "total":          len(all_sids),
        "hok":            hok,
        "rate_active":    (hok / active * 100) if active else 0.0,
        "rate_total":     (hok / len(all_sids) * 100) if all_sids else 0.0,
    }


def commands_executed(events: list[dict]) -> list[tuple[str, int]]:
    """All commands entered by attackers, ranked by frequency."""
    cmds = [e["input"] for e in events if e["eventid"] == "cowrie.command.input"]
    return Counter(cmds).most_common()


def files_transferred(events: list[dict]) -> list[dict]:
    """All file downloads and uploads.

    Downloads (wget/curl/ftpget/tftp) are extracted from cowrie.command.input
    for consistency across backends (the LLM backend does not natively emit
    cowrie.session.file_download). SFTP downloads (cowrie.file.download) and
    upload attempts (cowrie.session.file_upload or cowrie.session.upload_attempt)
    are read from their native events.
    """
    results = []
    for e in events:
        eid = e.get("eventid")
        if eid == "cowrie.command.input":
            for dl in extract_downloads_from_command(e.get("input", "")):
                results.append({
                    "timestamp": e["timestamp"],
                    "src_ip": e.get("src_ip"),
                    "session": e.get("session"),
                    "type": "download",
                    "filename": dl["url"],
                    "tool": dl["tool"],
                    "shasum": None,
                })
        elif eid == "cowrie.file.download":
            results.append({
                "timestamp": e["timestamp"],
                "src_ip": e.get("src_ip"),
                "session": e.get("session"),
                "type": "download",
                "filename": e.get("filepath") or e.get("filename"),
                "tool": "sftp",
                "shasum": e.get("shasum"),
            })
        elif eid in ("cowrie.session.file_upload", "cowrie.session.upload_attempt"):
            results.append({
                "timestamp": e["timestamp"],
                "src_ip": e.get("src_ip"),
                "session": e.get("session"),
                "type": "upload",
                "filename": e.get("filename") or e.get("filepath") or e.get("destfile"),
                "shasum": e.get("shasum"),
            })
    return results


def tcp_tunnel_requests(events: list[dict]) -> list[dict]:
    """All direct-tcpip (SSH tunnel) requests."""
    results = []
    for e in events:
        if e["eventid"] == "cowrie.direct-tcpip.request":
            results.append({
                "timestamp": e["timestamp"],
                "src_ip": e.get("src_ip"),
                "session": e.get("session"),
                "dst_ip": e["dst_ip"],
                "dst_port": e["dst_port"],
            })
    return results


# Regex matching commands that reach out to other servers
_OUTBOUND_CMD_RE = re.compile(
    r"""(?:
        \bssh\s+\S+@                     # ssh user@host
      | \bscp\s                          # scp transfers
      | \bsftp\s                         # sftp transfers
      | \brsync\s                        # rsync to remote
      | \bwget\s                         # wget downloads
      | \bcurl\s                         # curl requests
      | \bnc\b                           # netcat
      | \bncat\b                         # ncat
      | \bnetcat\b                       # netcat alias
      | /dev/tcp/                        # bash built-in TCP
      | \btelnet\s+\S+                   # telnet
      | \bftp\s+\S+                      # ftp
      | \bnmap\s                         # nmap scanning
      | \bmasscan\s                      # masscan scanning
      | \bhydra\s                        # hydra brute-force
      | \bmedusa\s                       # medusa brute-force
      | \bpssh\s                         # parallel ssh
    )""",
    re.IGNORECASE | re.VERBOSE,
)


def outbound_access_commands(events: list[dict]) -> list[dict]:
    """
    Find commands attackers ran that attempt to access other servers.

    Detects outbound tools (ssh, scp, wget, curl, nc, nmap, etc.) and
    /dev/tcp/ usage.  Each result includes the full command, the matched
    tool keyword, and session context.
    """
    results = []
    for e in events:
        if e["eventid"] != "cowrie.command.input":
            continue
        cmd = e["input"]
        match = _OUTBOUND_CMD_RE.search(cmd)
        if match:
            results.append({
                "timestamp": e["timestamp"],
                "src_ip": e.get("src_ip"),
                "session": e.get("session"),
                "command": cmd,
                "matched_tool": match.group().strip(),
            })
    return results


def outbound_access_summary(events: list[dict]) -> dict:
    """
    Comprehensive summary of all attempts to access other servers from the
    honeypot, combining outbound commands and direct-tcpip tunnel requests.

    Returns a dict with:
      - outbound_commands: list of command-based outbound access attempts
      - tcp_tunnels: list of direct-tcpip tunnel requests
      - by_session: per-session breakdown (commands + tunnels together)
      - tool_frequency: Counter of which outbound tools were used
      - targeted_hosts: unique destination hosts from tunnels
    """
    cmds = outbound_access_commands(events)
    tunnels = tcp_tunnel_requests(events)

    # Per-session grouping
    by_session: dict[str, dict] = defaultdict(lambda: {
        "src_ip": None,
        "commands": [],
        "tcp_tunnels": [],
    })
    for c in cmds:
        sid = c["session"]
        by_session[sid]["src_ip"] = c["src_ip"]
        by_session[sid]["commands"].append(c)
    for t in tunnels:
        sid = t["session"]
        by_session[sid]["src_ip"] = t["src_ip"]
        by_session[sid]["tcp_tunnels"].append(t)

    tool_freq = Counter(c["matched_tool"] for c in cmds)
    targeted_hosts = Counter(
        f"{t['dst_ip']}:{t['dst_port']}" for t in tunnels
    )

    return {
        "outbound_commands": cmds,
        "tcp_tunnels": tunnels,
        "by_session": dict(by_session),
        "tool_frequency": tool_freq.most_common(),
        "targeted_hosts": targeted_hosts.most_common(),
    }


def returning_attackers(events: list[dict]) -> list[dict]:
    """
    Find IPs that had a successful login and then returned in later sessions.

    For each such IP, splits sessions into:
      - initial_sessions: sessions up to and including the first successful login
      - return_sessions:  all sessions after the first successful login

    Sorted by number of return sessions (descending).
    """
    all_sessions = session_details(events)

    # Group sessions by source IP
    ip_sessions = defaultdict(list)
    for sid, info in all_sessions.items():
        ip = info.get("src_ip")
        if ip:
            ip_sessions[ip].append({"session_id": sid, **info})

    results = []
    for ip, sessions in ip_sessions.items():
        sessions.sort(key=lambda s: s["connected_at"] or "")

        # Find the first session with a successful login
        first_login_idx = None
        for i, s in enumerate(sessions):
            if s["login"]:
                first_login_idx = i
                break

        if first_login_idx is None:
            continue  # never logged in successfully

        initial_sessions = sessions[:first_login_idx + 1]
        return_sessions = sessions[first_login_idx + 1:]

        first_login = sessions[first_login_idx]
        first_login_time = first_login["connected_at"]

        # Summarize return session activity
        return_logins = [s for s in return_sessions if s["login"]]
        return_commands = []
        return_downloads = []
        return_uploads = []
        return_tcp_forwards = []
        return_hassh = set()
        return_versions = set()

        for s in return_sessions:
            return_commands.extend(s["commands"])
            return_downloads.extend(s["downloads"])
            return_uploads.extend(s["uploads"])
            return_tcp_forwards.extend(s["tcp_forwards"])
            if s["hassh"]:
                return_hassh.add(s["hassh"])
            if s["client_version"]:
                return_versions.add(s["client_version"])

        # Time between first login and last return
        return_timestamps = [s["connected_at"] for s in return_sessions if s["connected_at"]]
        last_return = max(return_timestamps) if return_timestamps else None

        # Check if the attacker changed tools/fingerprint between initial and return
        initial_hassh = {s["hassh"] for s in initial_sessions if s["hassh"]}
        changed_tools = bool(return_hassh and return_hassh != initial_hassh)

        results.append({
            "ip": ip,
            "total_sessions": len(sessions),
            "first_login_time": first_login_time,
            "first_login_creds": first_login["login"],
            "first_login_session": first_login["session_id"],
            "sessions_before_login": first_login_idx,
            "return_sessions": len(return_sessions),
            "return_logins_succeeded": len(return_logins),
            "return_commands": return_commands,
            "return_downloads": return_downloads,
            "return_uploads": return_uploads,
            "return_tcp_forwards": return_tcp_forwards,
            "last_return_time": last_return,
            "return_client_versions": sorted(return_versions),
            "return_hassh": sorted(return_hassh),
            "changed_tools": changed_tools,
            "all_sessions": sessions,
        })

    results.sort(key=lambda r: -r["return_sessions"])
    return results


def _normalize_command(cmd: str) -> str:
    """Normalize a command for grouping by replacing session-specific values.

    Replaces passwords in chpasswd calls, random-looking tokens/hashes, and
    similar parameterized fragments so that structurally identical commands
    from different sessions can be grouped together.
    """
    # Normalize passwords set via chpasswd (e.g. echo "root:XyZ123"|chpasswd)
    cmd = re.sub(r'(echo\s+"[^:]+:)[^"]+(".*chpasswd)', r'\1<PASS>\2', cmd)
    # Normalize passwords set via passwd-style echo piping (e.g. echo 'pass' | passwd)
    cmd = re.sub(r"""(echo\s+['"])[^'"]+(['"]\s*\|\s*passwd)""", r'\1<PASS>\2', cmd)
    return cmd


def group_sessions_by_commands(events: list[dict]) -> list[dict]:
    """
    Group sessions that executed the same sequence of commands.

    Commands are normalized before comparison so that sessions using the
    same script but with different credentials/keys are grouped together.

    Returns a list of groups sorted by number of sessions (descending).
    Each group contains the shared command list and a list of sessions
    that used it.  Only sessions with at least one command are included.
    """
    all_sessions = session_details(events)

    groups: dict[tuple[str, ...], list[dict]] = defaultdict(list)
    for sid, info in all_sessions.items():
        if not info["commands"]:
            continue
        key = tuple(_normalize_command(c) for c in info["commands"])
        groups[key].append({"session_id": sid, **info})

    results = []
    for cmds, sessions in groups.items():
        sessions.sort(key=lambda s: s["connected_at"] or "")
        unique_ips = {s["src_ip"] for s in sessions if s["src_ip"]}
        results.append({
            "commands": list(cmds),
            "session_count": len(sessions),
            "unique_ips": len(unique_ips),
            "ip_list": sorted(unique_ips),
            "sessions": sessions,
        })

    results.sort(key=lambda g: -g["session_count"])
    return results


def correlate_sessions_with_tokens(
    events: list[dict],
    token_map: list[dict],
) -> list[dict]:
    """Join token map entries with their Cowrie session activity."""
    all_sessions = session_details(events)
    # Group tokens by session_id
    tokens_by_session = defaultdict(list)
    for t in token_map:
        tokens_by_session[t["session_id"]].append(t)

    results = []
    for sid, tokens in tokens_by_session.items():
        session_info = all_sessions.get(sid, {})
        results.append({
            "session_id": sid,
            "src_ip": session_info.get("src_ip"),
            "login": session_info.get("login"),
            "connected_at": session_info.get("connected_at"),
            "commands": session_info.get("commands", []),
            "tokens": [
                {"token_id": t["token_id"], "token_type": t["token_type"]}
                for t in tokens
            ],
        })
    results.sort(key=lambda r: r.get("connected_at") or "")
    return results


# ---------------------------------------------------------------------------
# Pretty-printing
# ---------------------------------------------------------------------------

def _header(title: str) -> None:
    print(f"\n{'=' * 70}")
    print(f"  {title}")
    print(f"{'=' * 70}")


def print_report(events: list[dict], token_map: Optional[list[dict]]) -> None:
    """Print a full analysis report to stdout."""

    _header("CONNECTION OVERVIEW")
    overview = summarize_connections(events)
    for k, v in overview.items():
        print(f"  {k}: {v}")

    _header("TOP 20 SOURCE IPs")
    for ip, count in top_source_ips(events, 20):
        print(f"  {ip:40s} {count:>5d} connections")

    _header("RETURNING ATTACKERS (came back after successful login)")
    returners = returning_attackers(events)
    returned = [r for r in returners if r["return_sessions"] > 0]
    no_return = [r for r in returners if r["return_sessions"] == 0]
    print(f"  IPs with successful login:   {len(returners)}")
    print(f"  Returned after login:        {len(returned)}")
    print(f"  Never returned after login:  {len(no_return)}")

    if returned:
        print()
        for r in returned:
            print(f"  {r['ip']}")
            print(f"    First login:       {r['first_login_time']}  "
                  f"{r['first_login_creds']['username']}/{r['first_login_creds']['password']}  "
                  f"(session {r['first_login_session']})")
            print(f"    Brute-force attempts before login: {r['sessions_before_login']}")
            print(f"    Return sessions:   {r['return_sessions']}")
            print(f"    Return logins OK:  {r['return_logins_succeeded']}")
            print(f"    Last return:       {r['last_return_time']}")
            print(f"    Changed tools:     {'YES' if r['changed_tools'] else 'no'}")
            if r["return_client_versions"]:
                print(f"    Return client(s):  {', '.join(r['return_client_versions'])}")
            if r["return_hassh"]:
                print(f"    Return HASSH(es):  {', '.join(r['return_hassh'])}")
            if r["return_commands"]:
                print(f"    Return commands ({len(r['return_commands'])}):")
                for cmd in r["return_commands"]:
                    print(f"      > {cmd}")
            if r["return_downloads"]:
                print(f"    Return downloads ({len(r['return_downloads'])}):")
                for d in r["return_downloads"]:
                    print(f"      {d['filename']}")
            if r["return_uploads"]:
                print(f"    Return uploads ({len(r['return_uploads'])}):")
                for u in r["return_uploads"]:
                    print(f"      {u['filename']}")
            if r["return_tcp_forwards"]:
                print(f"    Return TCP forwards ({len(r['return_tcp_forwards'])}):")
                for t in r["return_tcp_forwards"]:
                    print(f"      -> {t['dst_ip']}:{t['dst_port']}")
            print()

    _header("TOP 20 ATTEMPTED CREDENTIALS (user/pass)")
    for (user, pwd), count in top_credentials(events, 20):
        print(f"  {user}/{pwd:30s} {count:>5d} attempts")

    _header("TOP 20 USERNAMES")
    for name, count in top_usernames(events, 20):
        print(f"  {name:40s} {count:>5d}")

    _header("TOP 20 PASSWORDS")
    for pwd, count in top_passwords(events, 20):
        print(f"  {pwd:40s} {count:>5d}")

    _header("SUCCESSFUL LOGINS")
    logins = successful_logins(events)
    print(f"  Total: {len(logins)}")
    for login in logins:
        print(f"  [{login['timestamp']}] {login['src_ip']:20s} "
              f"session={login['session']}  {login['username']}/{login['password']}")

    _header("SSH CLIENT VERSIONS (top 15)")
    for version, count in ssh_client_versions(events)[:15]:
        print(f"  {version:55s} {count:>5d}")

    _header("HANDS-ON-KEYBOARD DETECTION")
    hok = hands_on_keyboard_sessions(events)
    print(f"  Total sessions:                 {hok['total']}")
    print(f"  Sessions with >=1 command:      {hok['active']}")
    print(f"  Hands-on-keyboard sessions:     {hok['hok']}")
    print(f"  HOK rate (% of active):         {hok['rate_active']:.2f}%")
    print(f"  HOK rate (% of all sessions):   {hok['rate_total']:.2f}%")
    print(f"\n  Client banner distribution:")
    for cls, count in hok["client_classes"].most_common():
        print(f"    {cls:18s} {count:>5}")
    if hok["sessions"]:
        print(f"\n  HOK sessions (top 20 by command count):")
        for s in hok["sessions"][:20]:
            print(f"    {s['session_id']}  {s['src_ip']:18s}  "
                  f"cmds={s['command_count']:>3}  "
                  f"median_gap={s['median_gap_s']:>6.1f}s  "
                  f"banner={s['client_banner']}")

    _header("HASSH FINGERPRINTS (top 15)")
    for hassh, count in ssh_client_fingerprints(events)[:15]:
        print(f"  {hassh}  {count:>5d}")

    _header("COMMANDS EXECUTED BY ATTACKERS")
    cmds = commands_executed(events)
    print(f"  Total unique commands: {len(cmds)}")
    for cmd, count in cmds[:30]:
        display = cmd[:100] + "..." if len(cmd) > 100 else cmd
        print(f"  [{count:>3d}x] {display}")

    _header("FILES TRANSFERRED")
    files = files_transferred(events)
    print(f"  Total: {len(files)}")
    for f in files:
        print(f"  [{f['timestamp']}] {f['type']:8s} {f['src_ip']:20s} "
              f"{f['filename'] or 'N/A'}")

    _header("OUTBOUND ACCESS (commands & tunnels to reach other servers)")
    oa = outbound_access_summary(events)
    print(f"  Outbound commands:       {len(oa['outbound_commands'])}")
    print(f"  TCP tunnel requests:     {len(oa['tcp_tunnels'])}")
    print(f"  Sessions with outbound:  {len(oa['by_session'])}")

    if oa["tool_frequency"]:
        print("\n  Tool frequency:")
        for tool, count in oa["tool_frequency"]:
            print(f"    {tool:20s} {count:>5d}")

    if oa["targeted_hosts"]:
        print("\n  Targeted hosts (via TCP tunnels):")
        for host, count in oa["targeted_hosts"]:
            print(f"    {host:40s} {count:>5d}")

    if oa["by_session"]:
        print("\n  Per-session breakdown:")
        for sid, info in sorted(oa["by_session"].items()):
            print(f"\n  Session: {sid}  (IP: {info['src_ip']})")
            if info["commands"]:
                print(f"    Commands ({len(info['commands'])}):")
                for c in info["commands"]:
                    display = c["command"][:120] + "..." if len(c["command"]) > 120 else c["command"]
                    print(f"      [{c['timestamp']}] {display}")
            if info["tcp_tunnels"]:
                print(f"    TCP Tunnels ({len(info['tcp_tunnels'])}):")
                for t in info["tcp_tunnels"]:
                    print(f"      [{t['timestamp']}] -> {t['dst_ip']}:{t['dst_port']}")

    _header("INTERESTING SESSIONS (successful login + activity)")
    for s in interesting_sessions(events):
        print(f"\n  Session: {s['session_id']}")
        print(f"    IP:       {s['src_ip']}")
        print(f"    Time:     {s['connected_at']}")
        print(f"    Login:    {s['login']}")
        print(f"    Duration: {s['duration']}s")
        print(f"    Client:   {s['client_version']}")
        print(f"    HASSH:    {s['hassh']}")
        if s["commands"]:
            print(f"    Commands ({len(s['commands'])}):")
            for cmd in s["commands"]:
                print(f"      > {cmd}")
        if s["downloads"]:
            print(f"    Downloads ({len(s['downloads'])}):")
            for d in s["downloads"]:
                print(f"      {d['filename']}")
        if s["uploads"]:
            print(f"    Uploads ({len(s['uploads'])}):")
            for u in s["uploads"]:
                print(f"      {u['filename']}")
        if s["tcp_forwards"]:
            print(f"    TCP Forwards ({len(s['tcp_forwards'])}):")
            for t in s["tcp_forwards"]:
                print(f"      -> {t['dst_ip']}:{t['dst_port']}")

    _header("SESSIONS GROUPED BY COMMAND SEQUENCE")
    cmd_groups = group_sessions_by_commands(events)
    groups_with_multiple = [g for g in cmd_groups if g["session_count"] > 1]
    print(f"  Total groups (with commands): {len(cmd_groups)}")
    print(f"  Groups with multiple sessions: {len(groups_with_multiple)}")
    for g in cmd_groups:
        print(f"\n  [{g['session_count']} session(s), {g['unique_ips']} unique IP(s)]")
        print(f"    IPs: {', '.join(g['ip_list'])}")
        print(f"    Commands ({len(g['commands'])}):")
        for cmd in g["commands"]:
            display = cmd[:100] + "..." if len(cmd) > 100 else cmd
            print(f"      > {display}")
        print(f"    Sessions:")
        for s in g["sessions"]:
            print(f"      {s['session_id']}  {s['src_ip']:20s}  {s['connected_at']}")

    if token_map is not None:
        _header("TOKEN-TO-SESSION CORRELATION")
        correlated = correlate_sessions_with_tokens(events, token_map)
        print(f"  Sessions with tokens: {len(correlated)}")
        for c in correlated[:20]:
            token_types = ", ".join(t["token_type"] for t in c["tokens"])
            print(f"  Session {c['session_id']}  IP={c.get('src_ip') or '?':20s} "
                  f"tokens=[{token_types}]")
        if len(correlated) > 20:
            print(f"  ... and {len(correlated) - 20} more sessions")


# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Analyze Cowrie honeypot logs.")
    parser.add_argument(
        "--data-dir",
        default=DEFAULT_DATA_DIR,
        help="Path to the data/ folder containing cowrie_logs/ and optional "
             "token_session_map.json (default: %(default)s)",
    )
    args = parser.parse_args()

    print("Loading Cowrie logs...")
    events = load_logs(args.data_dir)
    print(f"  Loaded {len(events)} events")

    print("Loading token map...")
    token_map = load_token_map(args.data_dir)
    if token_map is None:
        print("  token_session_map.json not found; skipping token correlation")
    else:
        print(f"  Loaded {len(token_map)} token entries")

    print_report(events, token_map)
