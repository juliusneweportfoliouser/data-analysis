"""
AI Generated
Merge Canarytoken auth tokens into a Cowrie token_session_map.json file.

Cowrie's token_session_map.json is a JSON-lines file with one token record per
line. If the map contains redacted token_auth values, this script replaces them
from a Canarytoken server export that is also JSON-lines, with records like:

    {"token_id": "...", "auth_token": "..."}

Usage examples:

    python merge_token_creds.py cowriefinal2
    python merge_token_creds.py cowriefinal2 canarytoken_creds.jsonl
    python merge_token_creds.py --token-map cowriefinal2/token_session_map.json \
        --creds-file cowriefinal2/canarytoken_creds.jsonl

When no credentials file is given, the script looks for exactly one top-level
JSON/JSONL/NDJSON/TXT file in the data directory that contains token_id plus
auth_token or token_auth fields. The token_session_map.json file is updated in
place and a .bak copy is written first unless --no-backup is used.
"""

from __future__ import annotations

import argparse
import json
import os
import shutil
import sys
import tempfile
from datetime import datetime
from pathlib import Path
from typing import Iterable


AUTH_FIELDS = ("auth_token", "token_auth")
CANDIDATE_SUFFIXES = {".json", ".jsonl", ".ndjson", ".txt"}


class MergeError(Exception):
    """Raised for user-facing merge failures."""


def iter_json_lines(path: Path) -> Iterable[tuple[int, dict]]:
    """Yield ``(line_number, object)`` from a JSON-lines file."""
    with path.open("r", encoding="utf-8") as f:
        for line_number, line in enumerate(f, start=1):
            stripped = line.strip()
            if not stripped:
                continue
            try:
                record = json.loads(stripped)
            except json.JSONDecodeError as exc:
                raise MergeError(
                    f"{path}:{line_number}: invalid JSON: {exc.msg}"
                ) from exc
            if not isinstance(record, dict):
                raise MergeError(
                    f"{path}:{line_number}: expected a JSON object, "
                    f"got {type(record).__name__}"
                )
            yield line_number, record


def get_auth_value(record: dict) -> str | None:
    """Return the auth token value from a Canarytoken export record."""
    for field in AUTH_FIELDS:
        value = record.get(field)
        if value is not None:
            return value
    return None


def load_credentials(path: Path) -> dict[str, str]:
    """Load token_id -> auth token from the Canarytoken JSON-lines export."""
    credentials: dict[str, str] = {}
    first_seen: dict[str, int] = {}

    for line_number, record in iter_json_lines(path):
        token_id = record.get("token_id")
        auth_token = get_auth_value(record)

        if not isinstance(token_id, str) or not token_id:
            raise MergeError(f"{path}:{line_number}: missing string token_id")
        if not isinstance(auth_token, str) or not auth_token:
            raise MergeError(
                f"{path}:{line_number}: missing string auth_token/token_auth"
            )

        existing = credentials.get(token_id)
        if existing is not None and existing != auth_token:
            raise MergeError(
                f"{path}:{line_number}: token_id {token_id!r} has a different "
                f"auth value than on line {first_seen[token_id]}"
            )
        credentials[token_id] = auth_token
        first_seen.setdefault(token_id, line_number)

    if not credentials:
        raise MergeError(f"{path}: no credential records found")
    return credentials


def looks_like_credentials_file(path: Path) -> bool:
    """
    Return True if the file appears to contain Canarytoken credential records.

    This is intentionally shallow so auto-detection does not read large files.
    """
    nonempty_seen = 0
    try:
        with path.open("r", encoding="utf-8") as f:
            for line in f:
                stripped = line.strip()
                if not stripped:
                    continue
                nonempty_seen += 1
                try:
                    record = json.loads(stripped)
                except json.JSONDecodeError:
                    return False
                if (
                    isinstance(record, dict)
                    and isinstance(record.get("token_id"), str)
                    and isinstance(get_auth_value(record), str)
                ):
                    return True
                if nonempty_seen >= 20:
                    return False
    except OSError:
        return False
    return False


def find_credentials_file(data_dir: Path, token_map_path: Path) -> Path:
    """Find one likely Canarytoken credential export in the data directory."""
    candidates: list[Path] = []
    token_map_resolved = token_map_path.resolve()

    for path in sorted(data_dir.iterdir()):
        if not path.is_file():
            continue
        if path.suffix.lower() not in CANDIDATE_SUFFIXES:
            continue
        if path.resolve() == token_map_resolved:
            continue
        if path.name.endswith(".bak") or path.name.endswith(".tmp"):
            continue
        if looks_like_credentials_file(path):
            candidates.append(path)

    if not candidates:
        raise MergeError(
            f"could not auto-detect a credentials file in {data_dir}; pass it "
            "explicitly with --creds-file or as the second positional argument"
        )
    if len(candidates) > 1:
        names = ", ".join(str(p) for p in candidates)
        raise MergeError(
            "multiple possible credentials files found; pass one explicitly: "
            f"{names}"
        )
    return candidates[0]


def load_token_map(path: Path) -> list[dict]:
    """Load the token_session_map.json JSON-lines file."""
    records = [record for _, record in iter_json_lines(path)]
    if not records:
        raise MergeError(f"{path}: no token map records found")
    return records


def merge_credentials(
    records: list[dict],
    credentials: dict[str, str],
) -> tuple[int, int, set[str]]:
    """
    Overwrite token_auth in matching token map records.

    Returns ``(matched_records, changed_records, matched_token_ids)``.
    """
    matched_records = 0
    changed_records = 0
    matched_token_ids: set[str] = set()

    for index, record in enumerate(records, start=1):
        token_id = record.get("token_id")
        if not isinstance(token_id, str):
            raise MergeError(f"token map record {index}: missing string token_id")
        auth_token = credentials.get(token_id)
        if auth_token is None:
            continue

        matched_records += 1
        matched_token_ids.add(token_id)
        if record.get("token_auth") != auth_token:
            changed_records += 1
        record["token_auth"] = auth_token

    return matched_records, changed_records, matched_token_ids


def next_backup_path(path: Path) -> Path:
    """Return a backup path that does not overwrite an existing backup."""
    backup = path.with_name(path.name + ".bak")
    if not backup.exists():
        return backup
    stamp = datetime.now().strftime("%Y%m%d-%H%M%S")
    return path.with_name(f"{path.name}.{stamp}.bak")


def write_json_lines_atomic(path: Path, records: list[dict]) -> None:
    """Write records as JSON-lines and atomically replace the target file."""
    fd, tmp_name = tempfile.mkstemp(
        prefix=f".{path.name}.",
        suffix=".tmp",
        dir=path.parent,
        text=True,
    )
    tmp_path = Path(tmp_name)
    try:
        with os.fdopen(fd, "w", encoding="utf-8", newline="\n") as f:
            for record in records:
                f.write(json.dumps(record, ensure_ascii=False))
                f.write("\n")
        os.replace(tmp_path, path)
    except Exception:
        try:
            tmp_path.unlink()
        except OSError:
            pass
        raise


def resolve_credentials_path(path: Path, data_dir: Path) -> Path:
    """Resolve a user-supplied credentials path, preferring existing paths."""
    if path.is_absolute() or path.exists():
        return path
    return data_dir / path


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="Overwrite token_auth values in token_session_map.json."
    )
    parser.add_argument(
        "data_dir",
        nargs="?",
        type=Path,
        default=Path("."),
        help=(
            "Cowrie honeypot folder containing token_session_map.json "
            "(default: current directory). If this is a file and no credentials "
            "file is provided, it is treated as the credentials file."
        ),
    )
    parser.add_argument(
        "credentials_file",
        nargs="?",
        type=Path,
        help=(
            "Canarytoken JSON-lines export. Relative paths are resolved first "
            "from the current directory, then from data_dir."
        ),
    )
    parser.add_argument(
        "--creds-file",
        type=Path,
        help="Explicit Canarytoken JSON-lines export path.",
    )
    parser.add_argument(
        "--token-map",
        type=Path,
        help="Path to token_session_map.json (default: <data_dir>/token_session_map.json).",
    )
    parser.add_argument(
        "--dry-run",
        action="store_true",
        help="Report what would change without writing token_session_map.json.",
    )
    parser.add_argument(
        "--no-backup",
        action="store_true",
        help="Do not create token_session_map.json.bak before writing.",
    )
    return parser.parse_args()


def main() -> int:
    args = parse_args()

    if args.creds_file and args.credentials_file:
        print(
            "error: provide only one credentials file, not both positional and "
            "--creds-file",
            file=sys.stderr,
        )
        return 2

    data_dir = args.data_dir
    credentials_path = args.creds_file or args.credentials_file
    if credentials_path is None and data_dir.is_file():
        credentials_path = data_dir
        data_dir = data_dir.parent

    token_map_path = args.token_map or (data_dir / "token_session_map.json")
    if not token_map_path.exists():
        print(f"error: token map not found: {token_map_path}", file=sys.stderr)
        return 2

    if credentials_path is None:
        try:
            credentials_path = find_credentials_file(data_dir, token_map_path)
        except MergeError as exc:
            print(f"error: {exc}", file=sys.stderr)
            return 2
    else:
        credentials_path = resolve_credentials_path(credentials_path, data_dir)

    if not credentials_path.exists():
        print(f"error: credentials file not found: {credentials_path}", file=sys.stderr)
        return 2
    if credentials_path.resolve() == token_map_path.resolve():
        print("error: credentials file cannot be token_session_map.json", file=sys.stderr)
        return 2

    try:
        credentials = load_credentials(credentials_path)
        records = load_token_map(token_map_path)
        matched_records, changed_records, matched_token_ids = merge_credentials(
            records,
            credentials,
        )
    except MergeError as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 1

    unmatched_creds = len(set(credentials) - matched_token_ids)

    print(f"credentials: {len(credentials)} loaded from {credentials_path}")
    print(f"token map:    {len(records)} records from {token_map_path}")
    print(f"matched:      {matched_records} records")
    print(f"changed:      {changed_records} token_auth values")
    if unmatched_creds:
        print(f"warning: {unmatched_creds} credentials did not match any token_id")

    if matched_records == 0:
        print("error: no token_id values matched; token map was not written", file=sys.stderr)
        return 1

    if args.dry_run:
        print("dry run: token map was not written")
        return 0

    if changed_records == 0:
        print("done: all matched token_auth values were already current")
        return 0

    if not args.no_backup:
        backup_path = next_backup_path(token_map_path)
        shutil.copy2(token_map_path, backup_path)
        print(f"backup:       {backup_path}")

    write_json_lines_atomic(token_map_path, records)
    print("done: token_session_map.json updated")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
