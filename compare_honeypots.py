"""
AI Generated
Honeypot Effectiveness Comparison

Computes quantitative metrics across the four Cowrie honeypot variants for
the shared 2026-04-23 to 2026-04-30 capture window, and emits an Excel
workbook (honeypot_comparison.xlsx) for manual graphing.

Variant matrix (modification × backend):
  - mod_shell   modified Cowrie + shell backend  (cowriefinal1)
  - mod_llm     modified Cowrie + LLM backend    (cowriefinal2)
  - van_shell   vanilla  Cowrie + shell backend  (cowriefinalshellvanilla)
  - van_llm     vanilla  Cowrie + LLM backend    (cowriefinalllmvanilla)

Vanilla LLM Cowrie does not emit cowrie.command.input events to the JSON
log; commands are reconstructed from the debug log (cowrie.log).

Metrics are drawn from the honeypot-effectiveness framework of Mphago et al.
(interaction level, data quality) and Krajčík et al. (2025).  Only "hard"
quantitative metrics are included; no stealth/fingerprinting heuristics.

Sheets produced:
  - Summary         one row per metric, one column per variant
  - Sessions_*      one row per session, per variant (four sheets)
  - Daily           one row per (variant, date) for time-series graphs
  - TopCommands     top 30 normalized commands per variant (long format)
  - TokenSummary    per-variant Canarytoken metrics
  - TokenHits       one row per token hit across all variants
"""

import argparse
import json
import os
import re
import statistics
from collections import Counter, defaultdict
from datetime import datetime, timezone

import pandas as pd


# openpyxl rejects these control chars in cell values; Cowrie captures arbitrary
# bytes from attacker-controlled strings (SSH banners, passwords, commands).
_EXCEL_ILLEGAL_RE = re.compile(r"[\x00-\x08\x0b\x0c\x0e-\x1f]")


def _clean_for_excel(value):
    if isinstance(value, str):
        return _EXCEL_ILLEGAL_RE.sub("", value)
    return value


def _sanitize_df(df: pd.DataFrame) -> pd.DataFrame:
    if df.empty:
        return df
    for col in df.select_dtypes(include="object").columns:
        df[col] = df[col].map(_clean_for_excel)
    return df

from analyze_cowrie import (
    load_logs,
    session_details,
    _normalize_command,
    extract_downloads_from_command,
    hands_on_keyboard_sessions,
)


BASE_DIR = os.path.dirname(os.path.abspath(__file__))
CAPTURE_START_DATE = "2026-04-23"
CAPTURE_END_DATE = "2026-04-30"

VARIANTS: dict[str, str] = {
    "mod_shell": "cowriefinal1",
    "mod_llm":   "cowriefinal2",
    "van_shell": "cowriefinalshellvanilla",
    "van_llm":   "cowriefinalllmvanilla",
}

DEFAULT_OUTPUT = os.path.join(BASE_DIR, "honeypot_comparison.xlsx")


# ---------------------------------------------------------------------------
# cowrie.log debug-log parsing (vanilla LLM backend has no command JSON events)
# ---------------------------------------------------------------------------

_DEBUG_NEW_CONN_RE = re.compile(
    r"^\S+Z \[cowrie\.ssh\.factory\.CowrieSSHFactory\] New connection: "
    r"([\d.]+):\d+ .*\[session: (\w+)\]"
)
_DEBUG_TRANSPORT_RE = re.compile(r"^\S+Z \[HoneyPotSSHTransport,(\d+),([\d.]+)\]")
_DEBUG_LLM_REQ_RE = re.compile(
    r"^(\S+Z) \[SSHChannel session \(\d+\) on SSHService .+ on "
    r"HoneyPotSSHTransport,(\d+),([\d.]+)\] LLM request:"
)
_DEBUG_CMD_RE = re.compile(r"The command to execute is: (.*)\"$")
_DEBUG_TS_LINE_RE = re.compile(r"^\S+Z \[")
_DEBUG_LLM_ERROR_RE = re.compile(r"^\S+Z \[HTTP11ClientProtocol .+\] 'LLM API error")


def _timestamp_in_date_window(
    ts: str | None,
    start_date: str | None = None,
    end_date: str | None = None,
) -> bool:
    if not start_date and not end_date:
        return True
    if not ts or len(ts) < 10:
        return False
    day = ts[:10]
    if start_date and day < start_date:
        return False
    if end_date and day > end_date:
        return False
    return True


def _event_sort_key(e: dict) -> str:
    return e.get("timestamp") or ""


def extract_llm_command_events(
    debug_log_path: str,
    start_date: str | None = None,
    end_date: str | None = None,
) -> tuple[list[dict], int]:
    """Reconstruct cowrie.command.input events from a Cowrie debug log.

    The vanilla LLM backend writes commands only as part of LLM API request
    payloads in cowrie.log. This walks the log, maps (PID, src_ip) tuples back
    to session IDs via "New connection" lines, and synthesizes one
    cowrie.command.input event per LLM request whose prompt contains
    'The command to execute is: ...'.

    Optional ``start_date`` / ``end_date`` filters are inclusive ISO dates
    (YYYY-MM-DD). Returns (events, llm_error_count).
    """
    events: list[dict] = []
    llm_errors = 0
    if not os.path.exists(debug_log_path):
        return events, llm_errors

    transport_to_session: dict[tuple[str, str], str] = {}
    pending_session: dict[str, list[str]] = defaultdict(list)
    pending_request: tuple[tuple[str, str], str] | None = None

    with open(debug_log_path, encoding="utf-8", errors="replace") as f:
        for line in f:
            line = line.rstrip("\r\n")

            if (
                _DEBUG_LLM_ERROR_RE.match(line)
                and _timestamp_in_date_window(line, start_date, end_date)
            ):
                llm_errors += 1

            m = _DEBUG_NEW_CONN_RE.match(line)
            if m:
                src_ip, sid = m.group(1), m.group(2)
                pending_session[src_ip].append(sid)
                continue

            m = _DEBUG_LLM_REQ_RE.match(line)
            if m:
                ts, pid, src_ip = m.group(1), m.group(2), m.group(3)
                key = (pid, src_ip)
                if key not in transport_to_session and pending_session.get(src_ip):
                    transport_to_session[key] = pending_session[src_ip].pop(0)
                pending_request = (key, ts)
                continue

            m = _DEBUG_TRANSPORT_RE.match(line)
            if m:
                pid, src_ip = m.group(1), m.group(2)
                key = (pid, src_ip)
                if key not in transport_to_session and pending_session.get(src_ip):
                    transport_to_session[key] = pending_session[src_ip].pop(0)

            if pending_request is not None:
                m = _DEBUG_CMD_RE.search(line)
                if m:
                    cmd_raw = m.group(1)
                    try:
                        cmd = json.loads(f'"{cmd_raw}"')
                    except (json.JSONDecodeError, ValueError):
                        cmd = cmd_raw
                    transport_id, ts = pending_request
                    sid = transport_to_session.get(transport_id)
                    if sid and _timestamp_in_date_window(ts, start_date, end_date):
                        events.append({
                            "eventid":   "cowrie.command.input",
                            "input":     cmd,
                            "timestamp": ts,
                            "session":   sid,
                            "src_ip":    transport_id[1],
                        })
                    pending_request = None
                elif _DEBUG_TS_LINE_RE.match(line):
                    # New log entry started without a command — abort this block.
                    pending_request = None

    return events, llm_errors


# ---------------------------------------------------------------------------
# Per-variant computations
# ---------------------------------------------------------------------------

def _parse_ts(ts: str | None) -> datetime | None:
    if not ts:
        return None
    # Cowrie timestamps are ISO-8601 with Z suffix
    if ts.endswith("Z"):
        ts = ts[:-1] + "+00:00"
    try:
        return datetime.fromisoformat(ts)
    except ValueError:
        return None


def build_per_ip_rows(variant: str, events: list[dict]) -> list[dict]:
    """Per-source-IP behavioural summary, used for matched-cohort analysis.

    Aggregates each IP's activity within one variant: sessions opened,
    successful logins, commands issued (total + unique), upload events,
    and download events. Output rows from multiple variants can be joined
    on src_ip to compare how the same attacker behaves across backends —
    isolating backend effect from auth-gate population effects (a tighter
    auth policy creates more rejected sessions per IP, which inflates
    "per-authenticated-session" denominators in misleading ways).
    """
    sessions: dict[str, set[str]] = defaultdict(set)
    login_ok: Counter[str] = Counter()
    cmds: Counter[str] = Counter()
    uniq_cmds: dict[str, set[str]] = defaultdict(set)
    upload_events: Counter[str] = Counter()
    download_events: Counter[str] = Counter()

    for e in events:
        ip = e.get("src_ip")
        if not ip:
            continue
        eid = e["eventid"]
        sid = e.get("session")
        if eid == "cowrie.session.connect" and sid:
            sessions[ip].add(sid)
        elif eid == "cowrie.login.success":
            login_ok[ip] += 1
        elif eid == "cowrie.command.input":
            cmd = _normalize_command(e.get("input", ""))
            cmds[ip] += 1
            uniq_cmds[ip].add(cmd)
            # IP-keyed sessions may not catch the connect event for sessions
            # whose connect line was rotated out; track via command sids too.
            if sid:
                sessions[ip].add(sid)
        elif eid in ("cowrie.session.file_upload", "cowrie.session.upload_attempt"):
            upload_events[ip] += 1
        elif eid in ("cowrie.command.input",):
            # Downloads derived from command text; counted via per-cmd parse below
            pass
        elif eid == "cowrie.file.download":
            download_events[ip] += 1

    # Add command-derived downloads (cross-backend parity).
    for e in events:
        if e["eventid"] != "cowrie.command.input":
            continue
        ip = e.get("src_ip")
        if not ip:
            continue
        download_events[ip] += len(extract_downloads_from_command(e.get("input", "")))

    all_ips = (
        set(sessions) | set(login_ok) | set(cmds) | set(upload_events) | set(download_events)
    )
    rows = []
    for ip in all_ips:
        rows.append({
            "variant":           variant,
            "src_ip":            ip,
            "sessions":          len(sessions.get(ip, set())),
            "login_ok_sessions": login_ok.get(ip, 0),
            "commands":          cmds.get(ip, 0),
            "unique_commands":   len(uniq_cmds.get(ip, set())),
            "upload_events":     upload_events.get(ip, 0),
            "download_events":   download_events.get(ip, 0),
        })
    return rows


def build_matched_cohort_df(per_ip_rows_by_variant: dict[str, list[dict]]) -> pd.DataFrame:
    """Wide-format per-IP table joining all variants on src_ip.

    One row per IP that appeared in at least one variant. Columns are
    ``<metric>_<variant>`` so a reader can filter to e.g. IPs with both
    ``login_ok_sessions_mod_shell > 0`` AND ``login_ok_sessions_van_shell > 0``
    to recover the matched cohort for that specific pair.
    A leading ``auth_variants`` column gives the count of variants on which
    the IP successfully authenticated, so ``auth_variants >= 2`` filters
    directly to the cross-variant cohort.
    """
    if not per_ip_rows_by_variant:
        return pd.DataFrame()

    # Long-format frame indexed by (variant, src_ip)
    long = pd.concat(
        [pd.DataFrame(rows) for rows in per_ip_rows_by_variant.values()],
        ignore_index=True,
    )
    if long.empty:
        return long

    metric_cols = [
        "sessions", "login_ok_sessions", "commands", "unique_commands",
        "upload_events", "download_events",
    ]
    wide = long.pivot_table(
        index="src_ip",
        columns="variant",
        values=metric_cols,
        fill_value=0,
        aggfunc="sum",
    )
    # Flatten MultiIndex columns: ("commands", "mod_shell") -> "commands_mod_shell"
    wide.columns = [f"{metric}_{variant}" for metric, variant in wide.columns]
    wide = wide.reset_index()

    # Per-variant acceptance rate: fraction of connect-attempt sessions that
    # reached cowrie.login.success. Surfaces the auth-gate's true effect
    # (vanilla ~97%, modified ~23%) directly per IP, so matched-cohort claims
    # can cite the rate via AVERAGEIFS without a derived prose computation.
    # Stored as a fraction in [0, 1]; formatted as percent in write_workbook.
    variants = sorted({
        c[len("login_ok_sessions_"):]
        for c in wide.columns if c.startswith("login_ok_sessions_")
    })
    for v in variants:
        sess_col = f"sessions_{v}"
        ok_col = f"login_ok_sessions_{v}"
        rate_col = f"acceptance_rate_{v}"
        if sess_col in wide.columns and ok_col in wide.columns:
            wide[rate_col] = (wide[ok_col] / wide[sess_col]).where(
                wide[sess_col] > 0, 0.0
            )

    # auth_variants: count of variants where this IP got at least one login_ok
    authok_cols = [c for c in wide.columns if c.startswith("login_ok_sessions_")]
    wide.insert(1, "auth_variants", (wide[authok_cols] > 0).sum(axis=1))

    # Sort: most-cross-cutting IPs first, then by total commands
    cmd_cols = [c for c in wide.columns if c.startswith("commands_")]
    wide["_cmd_total"] = wide[cmd_cols].sum(axis=1)
    wide = wide.sort_values(
        ["auth_variants", "_cmd_total"], ascending=[False, False]
    ).drop(columns="_cmd_total").reset_index(drop=True)

    return wide


def build_session_rows(variant: str, events: list[dict]) -> list[dict]:
    """One row per Cowrie session with all per-session metric inputs."""
    sessions = session_details(events)
    rows = []
    for sid, info in sessions.items():
        login = info.get("login")
        commands = info.get("commands") or []
        unique_cmds = {_normalize_command(c) for c in commands}
        rows.append({
            "variant":            variant,
            "session_id":         sid,
            "src_ip":             info.get("src_ip"),
            "connected_at":       info.get("connected_at"),
            "login_success":      bool(login),
            "username":           (login or {}).get("username"),
            "password":           (login or {}).get("password"),
            "duration_s":         info.get("duration"),
            "command_count":      len(commands),
            "unique_command_count": len(unique_cmds),
            "upload_count":       len(info.get("uploads") or []),
            "download_count":     len(info.get("downloads") or []),
            "client_version":     info.get("client_version"),
            "hassh":              info.get("hassh"),
        })
    return rows


def build_daily_rows(variant: str, events: list[dict]) -> list[dict]:
    """Per-calendar-day counts for time-series plotting."""
    per_day: dict[str, dict] = defaultdict(lambda: {
        "connections": 0,
        "successful_logins": 0,
        "unique_ips": set(),
        "commands": 0,
        "uploads": 0,
        "downloads": 0,
    })
    for e in events:
        dt = _parse_ts(e.get("timestamp"))
        if not dt:
            continue
        day = dt.date().isoformat()
        bucket = per_day[day]
        eid = e["eventid"]
        if eid == "cowrie.session.connect":
            bucket["connections"] += 1
            if e.get("src_ip"):
                bucket["unique_ips"].add(e["src_ip"])
        elif eid == "cowrie.login.success":
            bucket["successful_logins"] += 1
        elif eid == "cowrie.command.input":
            bucket["commands"] += 1
            # Downloads are derived from command text (shell's native
            # cowrie.session.file_download is intentionally ignored so the
            # LLM and shell backends are counted the same way).
            bucket["downloads"] += len(extract_downloads_from_command(e.get("input", "")))
        elif eid == "cowrie.file.download":
            # SFTP download (canarytoken file reads) — count separately.
            bucket["downloads"] += 1
        elif eid in ("cowrie.session.file_upload", "cowrie.session.upload_attempt"):
            # Shell uses file_upload; LLM uses upload_attempt. Both mean
            # "attacker attempted an SFTP upload" — normalize.
            bucket["uploads"] += 1

    rows = []
    for day in sorted(per_day.keys()):
        b = per_day[day]
        rows.append({
            "variant": variant,
            "date": day,
            "connections": b["connections"],
            "successful_logins": b["successful_logins"],
            "unique_ips": len(b["unique_ips"]),
            "commands": b["commands"],
            "uploads": b["uploads"],
            "downloads": b["downloads"],
        })
    return rows


def build_top_commands(variant: str, events: list[dict], n: int = 30) -> list[dict]:
    """Top N normalized commands with frequency, long format."""
    cmds = [
        _normalize_command(e["input"])
        for e in events
        if e["eventid"] == "cowrie.command.input"
    ]
    return [
        {"variant": variant, "rank": i + 1, "command": cmd, "count": count}
        for i, (cmd, count) in enumerate(Counter(cmds).most_common(n))
    ]


def build_all_commands(variant: str, events: list[dict]) -> list[dict]:
    """Every unique normalized command with frequency, long format."""
    cmds = [
        _normalize_command(e["input"])
        for e in events
        if e["eventid"] == "cowrie.command.input"
    ]
    return [
        {"variant": variant, "rank": i + 1, "command": cmd, "count": count}
        for i, (cmd, count) in enumerate(Counter(cmds).most_common())
    ]


def compute_summary(variant: str, events: list[dict], session_rows: list[dict]) -> dict:
    """Aggregate summary metrics for one variant."""
    total_connections = sum(1 for e in events if e["eventid"] == "cowrie.session.connect")
    unique_ips = len({r["src_ip"] for r in session_rows if r["src_ip"]})

    success_sessions = [r for r in session_rows if r["login_success"]]
    successful_logins = len(success_sessions)
    unique_login_ips = {r["src_ip"] for r in success_sessions if r["src_ip"]}

    # Login acceptance is reported as the per-IP mean to match the matched
    # cohort acceptance-rate calculation: each source IP contributes one
    # rate, login_ok_sessions / sessions, instead of high-volume IPs
    # dominating the aggregate.
    sessions_per_ip: Counter[str] = Counter()
    login_successes_per_ip: Counter[str] = Counter()
    for r in session_rows:
        ip = r["src_ip"]
        if not ip:
            continue
        sessions_per_ip[ip] += 1
        if r["login_success"]:
            login_successes_per_ip[ip] += 1
    per_ip_login_success_rate = (
        statistics.mean(
            login_successes_per_ip[ip] / sessions_per_ip[ip]
            for ip in sessions_per_ip
        ) * 100
        if sessions_per_ip else 0.0
    )

    # IPs with >=2 successful login events (count repeat successes per IP)
    success_events_by_ip: Counter[str] = Counter()
    for e in events:
        if e["eventid"] == "cowrie.login.success" and e.get("src_ip"):
            success_events_by_ip[e["src_ip"]] += 1
    repeat_auth_ips = sum(1 for ip, c in success_events_by_ip.items() if c >= 2)
    repeat_auth_pct = (
        repeat_auth_ips / len(unique_login_ips) * 100 if unique_login_ips else 0.0
    )

    # Returning attackers: IPs appearing on >=2 distinct calendar days after first login
    login_days_by_ip: dict[str, set[str]] = defaultdict(set)
    for e in events:
        if e["eventid"] == "cowrie.login.success" and e.get("src_ip"):
            dt = _parse_ts(e.get("timestamp"))
            if dt:
                login_days_by_ip[e["src_ip"]].add(dt.date().isoformat())
    returning_attackers = sum(1 for days in login_days_by_ip.values() if len(days) >= 2)

    # Returning IPs: IPs that successfully logged in once and then came back
    # in at least one *later* session (any kind). Broader than the >=2-day
    # metric — captures same-day repeat visits too.
    sessions_by_ip: dict[str, list[tuple[str, bool]]] = defaultdict(list)
    for r in session_rows:
        if r["src_ip"] and r["connected_at"]:
            sessions_by_ip[r["src_ip"]].append((r["connected_at"], r["login_success"]))
    returning_after_login = 0
    for ip_sessions in sessions_by_ip.values():
        ip_sessions.sort()
        for i, (_ts, ok) in enumerate(ip_sessions):
            if ok and i + 1 < len(ip_sessions):
                returning_after_login += 1
                break
    returning_after_login_pct = (
        returning_after_login / len(unique_login_ips) * 100 if unique_login_ips else 0.0
    )

    all_durations = [r["duration_s"] for r in session_rows if r["duration_s"] is not None]
    success_durations = [
        r["duration_s"] for r in success_sessions if r["duration_s"] is not None
    ]

    total_commands = sum(r["command_count"] for r in session_rows)
    success_cmd_counts = [r["command_count"] for r in success_sessions]

    all_cmds_normalized = {
        _normalize_command(e["input"])
        for e in events
        if e["eventid"] == "cowrie.command.input"
    }

    # Uploads: normalize shell's file_upload and LLM's upload_attempt.
    # Three intelligence tiers per upload, in increasing order of fidelity:
    #   1. Event logged           — we know an upload was attempted
    #   2. Filename / filepath    — we know what the attacker called it
    #   3. Binary hash (shasum)   — we have the actual sample on disk
    # The LLM backends can deliver tier 1-2 but not tier 3 (their FS is
    # synthetic), so reporting only "unique hashes" understates them.
    upload_events = [
        e for e in events
        if e["eventid"] in ("cowrie.session.file_upload", "cowrie.session.upload_attempt")
    ]
    unique_upload_filenames = {
        e.get("filename") or e.get("destfile")
        for e in upload_events
        if (e.get("filename") or e.get("destfile"))
    }
    unique_upload_filepaths = {
        e.get("filepath") or e.get("outfile")
        for e in upload_events
        if (e.get("filepath") or e.get("outfile"))
    }
    # Downloads: derive command-based downloads from cowrie.command.input for
    # cross-backend consistency (the LLM backend does not emit
    # cowrie.session.file_download natively). SFTP downloads
    # (cowrie.file.download) are counted in addition — both backends emit these
    # when an attacker retrieves a canarytoken file via SFTP.
    download_count = sum(
        len(extract_downloads_from_command(e.get("input", "")))
        for e in events
        if e["eventid"] == "cowrie.command.input"
    ) + sum(1 for e in events if e["eventid"] == "cowrie.file.download")
    unique_upload_hashes = {e.get("shasum") for e in upload_events if e.get("shasum")}

    # --- New metrics ---

    # TCP forwarding: requests are attempts; data events indicate successful flow
    tcp_forward_requests = sum(
        1 for e in events if e["eventid"] == "cowrie.direct-tcpip.request"
    )
    tcp_forward_data = sum(
        1 for e in events if e["eventid"] == "cowrie.direct-tcpip.data"
    )

    # Time to first command after session connect (per session)
    connect_ts: dict[str, str] = {}
    first_cmd_ts: dict[str, str] = {}
    for e in events:
        sid = e.get("session")
        if not sid:
            continue
        eid = e["eventid"]
        if eid == "cowrie.session.connect":
            connect_ts[sid] = e.get("timestamp")
        elif eid == "cowrie.command.input" and sid not in first_cmd_ts:
            first_cmd_ts[sid] = e.get("timestamp")
    ttfc_seconds: list[float] = []
    for sid, cmd_ts in first_cmd_ts.items():
        ct = connect_ts.get(sid)
        if not ct or not cmd_ts:
            continue
        c, cm = _parse_ts(ct), _parse_ts(cmd_ts)
        if c and cm:
            delta = (cm - c).total_seconds()
            if delta >= 0:
                ttfc_seconds.append(delta)

    # Mean command length (characters)
    cmd_lens = [
        len(e.get("input", "")) for e in events if e["eventid"] == "cowrie.command.input"
    ]

    # Login attempts (failed + success) per session
    attempts_per_session: Counter[str] = Counter()
    for e in events:
        if e["eventid"] in ("cowrie.login.failed", "cowrie.login.success"):
            sid = e.get("session")
            if sid:
                attempts_per_session[sid] += 1
    attempt_counts = list(attempts_per_session.values())

    sessions_per_ip_vals = list(sessions_per_ip.values())

    # Commands attributed to attacker IPs (commands per IP, login-success IPs)
    cmds_per_login_ip: Counter[str] = Counter()
    for r in session_rows:
        if r["login_success"] and r["src_ip"]:
            cmds_per_login_ip[r["src_ip"]] += r["command_count"]
    cmds_per_ip_vals = list(cmds_per_login_ip.values())

    # Cowrie-side command failures (only emitted by the shell backend)
    failed_cmds = sum(1 for e in events if e["eventid"] == "cowrie.command.failed")
    cmd_failure_rate = (
        failed_cmds / total_commands * 100 if total_commands else 0.0
    )

    # Hands-on-keyboard detection: banner-class exclusion + multi-command +
    # human-paced inter-command gaps. See analyze_cowrie.hands_on_keyboard_sessions.
    hok = hands_on_keyboard_sessions(events)
    cls = hok["client_classes"]
    auto_banner = cls.get("automated", 0)
    gui_banner = cls.get("interactive_gui", 0)
    openssh_banner = cls.get("openssh_cli", 0)
    other_banner = cls.get("other", 0)
    empty_banner = cls.get("empty", 0)
    nonssh_banner = cls.get("non_ssh", 0)

    # ---- Normalized rates (auth-gate confound mitigation) ----
    # Vanilla accepts ~86-95 % of login attempts; modified accepts ~32 %.
    # Comparing raw counts of commands/uploads/etc. across variants is
    # therefore unfair to the modified backends (they have ~3x fewer
    # authenticated sessions to extract from). Express the same volumes as
    # rates per 100 successful logins (the post-gate denominator) and per
    # 100 connections (the pre-gate denominator) so the LLM-vs-shell and
    # modified-vs-vanilla comparisons hold the gate constant.
    def _per_n(num: float, denom: float, scale: float = 1.0) -> float:
        return (num / denom * scale) if denom else 0.0

    total_session_seconds_login_ok = sum(
        r["duration_s"] or 0.0 for r in success_sessions
    )

    def _stat(values, func, default=0.0):
        return func(values) if values else default

    return {
        "variant": variant,
        "Total connections": total_connections,
        "Unique source IPs": unique_ips,
        "Successful logins (sessions)": successful_logins,
        "Login success rate (%)": per_ip_login_success_rate,
        "Unique IPs that logged in": len(unique_login_ips),
        "IPs authenticating multiple times (%)": repeat_auth_pct,
        "Returning attackers (>=2 distinct days)": returning_attackers,
        "Returning IPs (any later session after login)": returning_after_login,
        "Returning IPs (% of IPs that logged in)": returning_after_login_pct,
        "Sessions per IP (mean)": _stat(sessions_per_ip_vals, statistics.mean),
        "Sessions per IP (median)": _stat(sessions_per_ip_vals, statistics.median),
        "Login attempts per session (mean)": _stat(attempt_counts, statistics.mean),
        "Login attempts per session (median)": _stat(attempt_counts, statistics.median),
        "Session duration mean (s) [all]": _stat(all_durations, statistics.mean),
        "Session duration median (s) [all]": _stat(all_durations, statistics.median),
        "Session duration max (s) [all]": _stat(all_durations, max),
        "Session duration mean (s) [login ok]": _stat(success_durations, statistics.mean),
        "Session duration median (s) [login ok]": _stat(success_durations, statistics.median),
        "Session duration max (s) [login ok]": _stat(success_durations, max),
        "Time to first command median (s)": _stat(ttfc_seconds, statistics.median),
        "Time to first command mean (s)": _stat(ttfc_seconds, statistics.mean),
        "Total commands": total_commands,
        "Commands per session mean [login ok]": _stat(success_cmd_counts, statistics.mean),
        "Commands per session median [login ok]": _stat(success_cmd_counts, statistics.median),
        "Commands per attacker IP mean [login ok]": _stat(cmds_per_ip_vals, statistics.mean),
        "Commands per attacker IP median [login ok]": _stat(cmds_per_ip_vals, statistics.median),
        "Unique commands (normalized)": len(all_cmds_normalized),
        "Command length mean (chars)": _stat(cmd_lens, statistics.mean),
        "Command length median (chars)": _stat(cmd_lens, statistics.median),
        "Failed commands (cowrie.command.failed)": failed_cmds,
        "Command failure rate (%)": cmd_failure_rate,
        "Sessions with automation banner": auto_banner,
        "Automation banner share (%)": _per_n(auto_banner, total_connections, 100),
        "Sessions with interactive-GUI banner": gui_banner,
        "Interactive-GUI banner share (%)": _per_n(gui_banner, total_connections, 100),
        "Sessions with OpenSSH-CLI banner": openssh_banner,
        "OpenSSH-CLI banner share (%)": _per_n(openssh_banner, total_connections, 100),
        "Sessions with 'other' SSH banner": other_banner,
        "Sessions with empty banner": empty_banner,
        "Sessions with non-SSH banner": nonssh_banner,
        "Hands-on-keyboard sessions": hok["hok"],
        "HOK rate (% of sessions with cmds)": hok["rate_active"],
        "HOK rate (% of all sessions)": hok["rate_total"],
        # ----- Normalized rates -----
        # Per 100 successful logins (post-auth-gate, fair across backends)
        "[NORM/auth] Commands per 100 auth sessions":
            _per_n(total_commands, successful_logins, 100),
        "[NORM/auth] Unique commands per 100 auth sessions":
            _per_n(len(all_cmds_normalized), successful_logins, 100),
        "[NORM/auth] Total session-seconds per auth session":
            _per_n(total_session_seconds_login_ok, successful_logins),
        "[NORM/auth] Upload events per 100 auth sessions":
            _per_n(len(upload_events), successful_logins, 100),
        "[NORM/auth] Unique upload filenames per 100 auth sessions":
            _per_n(len(unique_upload_filenames), successful_logins, 100),
        "[NORM/auth] Unique upload binary hashes per 100 auth sessions":
            _per_n(len(unique_upload_hashes), successful_logins, 100),
        "[NORM/auth] Downloads per 100 auth sessions":
            _per_n(download_count, successful_logins, 100),
        "[NORM/auth] HOK per 1000 auth sessions":
            _per_n(hok["hok"], successful_logins, 1000),
        # Per 100 connections (pre-auth-gate, captures gate efficiency too)
        "[NORM/conn] Commands per 100 connections":
            _per_n(total_commands, total_connections, 100),
        "[NORM/conn] Upload events per 100 connections":
            _per_n(len(upload_events), total_connections, 100),
        "[NORM/conn] Downloads per 100 connections":
            _per_n(download_count, total_connections, 100),
        "[NORM/conn] Unique commands per 100 connections":
            _per_n(len(all_cmds_normalized), total_connections, 100),
        "[NORM/conn] Unique upload binary hashes per 100 connections":
            _per_n(len(unique_upload_hashes), total_connections, 100),
        # Per authenticating IP (collapses repeat-connector noise)
        "[NORM/ip] Commands per authenticating IP":
            _per_n(total_commands, len(unique_login_ips)),
        "[NORM/ip] Unique upload binary hashes per 10 authenticating IPs":
            _per_n(len(unique_upload_hashes), len(unique_login_ips), 10),
        "TCP forwarding requests": tcp_forward_requests,
        "TCP forwarding data events (success indicator)": tcp_forward_data,
        "Total file uploads (events)": len(upload_events),
        "Unique upload filenames": len(unique_upload_filenames),
        "Unique upload filepaths": len(unique_upload_filepaths),
        "Unique uploaded file hashes (binaries persisted)": len(unique_upload_hashes),
        "Upload events with persisted binary (%)": _per_n(
            sum(1 for e in upload_events if e.get("shasum")),
            len(upload_events),
            100,
        ),
        "Total file downloads": download_count,
    }


# ---------------------------------------------------------------------------
# Token history (optional, when token_history.json exists per variant)
# ---------------------------------------------------------------------------

def load_token_history(variant_dir: str) -> list[dict] | None:
    """Return parsed token_history.json contents, or None if absent."""
    path = os.path.join(variant_dir, "token_history.json")
    if not os.path.exists(path):
        return None
    with open(path, encoding="utf-8") as f:
        return json.load(f)


def compute_token_summary(variant: str, history: list[dict]) -> dict:
    """Per-variant Canarytoken metrics."""
    triggered = [r for r in history if r["summary"]["total_hits"] > 0]
    unique_ips: set[str] = set()
    for r in triggered:
        for ip_info in r["summary"]["source_ips"]:
            unique_ips.add(ip_info["ip"])

    by_type_triggered: Counter[str] = Counter()
    for r in triggered:
        by_type_triggered[r["token_type"]] += 1

    row = {
        "variant": variant,
        "Tokens triggered": len(triggered),
        "Unique triggering IPs": len(unique_ips),
    }
    for ttype in ("AWS", "DNS", "Kubeconfig", "Wireguard", "Word"):
        row[f"Triggered {ttype}"] = by_type_triggered.get(ttype, 0)
    return row


def build_token_hits(variant: str, history: list[dict]) -> list[dict]:
    """Flatten all hits across all tokens for a variant into tidy rows."""
    rows = []
    for r in history:
        for h in r.get("hits", []):
            geo = h.get("geo_info") or {}
            ts = h.get("time_of_hit")
            iso_ts = (
                datetime.fromtimestamp(ts, tz=timezone.utc).isoformat()
                if isinstance(ts, (int, float))
                else None
            )
            rows.append({
                "variant":    variant,
                "token_id":   r["token_id"],
                "token_type": r["token_type"],
                "session_id": r["session_id"],
                "src_ip":     h.get("src_ip"),
                "country":    geo.get("country"),
                "city":       geo.get("city"),
                "org":        geo.get("org"),
                "input_channel": h.get("input_channel"),
                "timestamp":  iso_ts,
                "time_of_hit": ts,
            })
    return rows


# ---------------------------------------------------------------------------
# Orchestration
# ---------------------------------------------------------------------------

def process_variant(variant: str, variant_dir: str) -> dict:
    """Load and analyze one variant; returns a dict of DataFrames/rows."""
    print(f"\n[{variant}] loading logs from {variant_dir}")
    events = load_logs(
        variant_dir,
        start_date=CAPTURE_START_DATE,
        end_date=CAPTURE_END_DATE,
        include_current=True,
    )
    print(f"[{variant}]   {len(events)} events from cowrie.json "
          f"({CAPTURE_START_DATE}..{CAPTURE_END_DATE})")

    # Vanilla LLM backend doesn't emit cowrie.command.input — reconstruct from
    # cowrie.log debug log. Parser is a no-op for variants without that file.
    debug_log = os.path.join(variant_dir, "cowrie_logs", "cowrie.log")
    cmd_events, llm_errors = extract_llm_command_events(
        debug_log,
        start_date=CAPTURE_START_DATE,
        end_date=CAPTURE_END_DATE,
    )
    if cmd_events:
        events.extend(cmd_events)
        events.sort(key=_event_sort_key)
        print(f"[{variant}]   reconstructed {len(cmd_events)} command events from cowrie.log "
              f"({llm_errors} LLM API errors)")

    session_rows = build_session_rows(variant, events)
    daily_rows = build_daily_rows(variant, events)
    top_cmds = build_top_commands(variant, events)
    all_cmds = build_all_commands(variant, events)
    summary = compute_summary(variant, events, session_rows)
    summary["LLM API errors (debug log)"] = llm_errors

    hok_rows = [
        {"variant": variant, **s}
        for s in hands_on_keyboard_sessions(events)["sessions"]
    ]

    per_ip_rows = build_per_ip_rows(variant, events)

    history = load_token_history(variant_dir)
    if history is None:
        print(f"[{variant}]   no token_history.json — skipping token metrics")
        token_summary = None
        token_hits = []
    else:
        print(f"[{variant}]   loaded {len(history)} token histories")
        token_summary = compute_token_summary(variant, history)
        token_hits = build_token_hits(variant, history)

    return {
        "summary": summary,
        "session_rows": session_rows,
        "daily_rows": daily_rows,
        "top_cmds": top_cmds,
        "all_cmds": all_cmds,
        "hok_sessions": hok_rows,
        "per_ip_rows": per_ip_rows,
        "token_summary": token_summary,
        "token_hits": token_hits,
    }


def write_workbook(per_variant: dict[str, dict], output_path: str) -> None:
    """Write the combined Excel workbook."""
    # Summary sheet: metric rows, variant columns
    summary_df = pd.DataFrame([per_variant[v]["summary"] for v in per_variant])
    summary_df = summary_df.set_index("variant").T
    summary_df.index.name = "Metric"

    # Daily: concat across variants
    daily_df = pd.DataFrame(
        [row for v in per_variant for row in per_variant[v]["daily_rows"]]
    )

    # Top commands
    top_cmd_df = pd.DataFrame(
        [row for v in per_variant for row in per_variant[v]["top_cmds"]]
    )

    # All unique commands per variant (full list, not just top 30)
    all_cmd_df = pd.DataFrame(
        [row for v in per_variant for row in per_variant[v]["all_cmds"]]
    )

    # Hands-on-keyboard sessions across all variants
    hok_df = pd.DataFrame(
        [row for v in per_variant for row in per_variant[v]["hok_sessions"]]
    )

    # Matched-cohort: wide table joining per-IP behaviour across variants.
    matched_cohort_df = build_matched_cohort_df({
        v: per_variant[v]["per_ip_rows"] for v in per_variant
    })

    # Token summary: rows for variants that have token history
    token_summary_rows = [
        per_variant[v]["token_summary"]
        for v in per_variant
        if per_variant[v]["token_summary"] is not None
    ]
    token_summary_df = pd.DataFrame(token_summary_rows) if token_summary_rows else pd.DataFrame()

    # Token hits
    token_hit_rows = [
        row for v in per_variant for row in per_variant[v]["token_hits"]
    ]
    token_hits_df = pd.DataFrame(token_hit_rows) if token_hit_rows else pd.DataFrame()

    print(f"\nWriting workbook to {output_path}")
    with pd.ExcelWriter(output_path, engine="openpyxl") as writer:
        _sanitize_df(summary_df).to_excel(writer, sheet_name="Summary")
        for variant in per_variant:
            sessions_df = pd.DataFrame(per_variant[variant]["session_rows"])
            _sanitize_df(sessions_df).to_excel(
                writer, sheet_name=f"Sessions_{variant}", index=False
            )
        _sanitize_df(daily_df).to_excel(writer, sheet_name="Daily", index=False)
        _sanitize_df(top_cmd_df).to_excel(writer, sheet_name="TopCommands", index=False)
        _sanitize_df(all_cmd_df).to_excel(writer, sheet_name="AllCommands", index=False)
        if not hok_df.empty:
            _sanitize_df(hok_df).to_excel(writer, sheet_name="HOK_Sessions", index=False)
        if not matched_cohort_df.empty:
            _sanitize_df(matched_cohort_df).to_excel(
                writer, sheet_name="MatchedCohort", index=False
            )
        if not token_summary_df.empty:
            _sanitize_df(token_summary_df).to_excel(
                writer, sheet_name="TokenSummary", index=False
            )
        if not token_hits_df.empty:
            _sanitize_df(token_hits_df).to_excel(
                writer, sheet_name="TokenHits", index=False
            )

        # Convert percentage rows in the Summary sheet from "value-already-in-%"
        # (e.g. 1.11 meaning 1.11%) to fractions (0.0111) and apply Excel's
        # Percent number format. Without this, applying Excel's built-in
        # Percent format on top double-multiplies and produces values like
        # 111% from 1.11. Detect by the presence of "(%" anywhere in the
        # label — covers both simple suffix "(%)" and explanatory
        # "(% of <something>)" forms. Strip only the redundant simple-suffix
        # form; keep the parenthesized explanations intact.
        ws = writer.sheets["Summary"]
        for row_idx in range(2, ws.max_row + 1):
            label_cell = ws.cell(row=row_idx, column=1)
            label = label_cell.value
            if not isinstance(label, str) or "(%" not in label:
                continue
            label_cell.value = label.replace(" (%)", "")
            for col_idx in range(2, ws.max_column + 1):
                c = ws.cell(row=row_idx, column=col_idx)
                if isinstance(c.value, (int, float)):
                    c.value = c.value / 100.0
                    c.number_format = "0.00%"

        # MatchedCohort: apply Percent format to acceptance_rate_<variant>
        # columns so they display as e.g. 23.20% rather than 0.232. Values
        # are already fractions in [0, 1]; only the cell number_format
        # changes. Detect by column-header prefix.
        if "MatchedCohort" in writer.sheets:
            mc = writer.sheets["MatchedCohort"]
            header_row = next(mc.iter_rows(min_row=1, max_row=1))
            rate_col_indices = [
                cell.column for cell in header_row
                if isinstance(cell.value, str)
                and cell.value.startswith("acceptance_rate_")
            ]
            for row_idx in range(2, mc.max_row + 1):
                for col_idx in rate_col_indices:
                    mc.cell(row=row_idx, column=col_idx).number_format = "0.00%"


def main() -> None:
    parser = argparse.ArgumentParser(description="Compare Cowrie honeypot variant effectiveness.")
    parser.add_argument(
        "--only",
        choices=list(VARIANTS.keys()),
        help="Process only one variant (for quick dry-run verification).",
    )
    parser.add_argument(
        "--output",
        default=DEFAULT_OUTPUT,
        help=f"Output .xlsx path (default: {DEFAULT_OUTPUT})",
    )
    args = parser.parse_args()

    variants = {args.only: VARIANTS[args.only]} if args.only else VARIANTS

    per_variant = {}
    for variant, subdir in variants.items():
        variant_dir = os.path.join(BASE_DIR, subdir)
        if not os.path.isdir(variant_dir):
            print(f"[{variant}] WARNING: directory missing at {variant_dir} — skipping")
            continue
        per_variant[variant] = process_variant(variant, variant_dir)

    if not per_variant:
        print("No variants processed — nothing to write.")
        return

    write_workbook(per_variant, args.output)

    # TCP forwarding verification (user-requested explicit check)
    print("\n" + "=" * 70)
    print("  TCP FORWARDING VERIFICATION")
    print("=" * 70)
    any_forwarding = False
    for v, data in per_variant.items():
        req = data["summary"]["TCP forwarding requests"]
        dat = data["summary"]["TCP forwarding data events (success indicator)"]
        print(f"  {v:12s}  requests={req:>4d}   data events={dat:>4d}")
        if req or dat:
            any_forwarding = True
    if not any_forwarding:
        print("\n  RESULT: zero TCP forwarding requests and zero data events across "
              "all variants — no successful TCP forwarding interactions.")
    else:
        print("\n  RESULT: TCP forwarding activity DETECTED — review the "
              "Sessions_* sheets for affected sessions.")

    print("\nDone.")


if __name__ == "__main__":
    main()
