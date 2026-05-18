"""
AI Generated using Claude Opus 4.7
Pseudonymize Cowrie honeypot logs for sharing or analysis.

Walks a source directory recursively and writes pseudonymized copies of every
``cowrie.json*`` file and any ``token_session_map.json`` into a parallel
destination directory. Original files are never modified.

Replacements are deterministic within a run (and across runs that share a
salt), so a given IP, session ID, etc. always maps to the same pseudonym ---
preserving the ability to count, group, and join across the dataset.

Fields handled
--------------
* IPs                     ``src_ip``, ``dst_ip``, ``ip``, ``created_from_ip*``
* Session IDs             ``session``, ``session_id``, ``transport_id``
* Sensor name / UUID      ``sensor``, ``uuid``
* SSH client identifiers  ``fingerprint``, ``key``, ``hassh``,
                          ``hasshAlgorithms``
* Canarytoken secrets     ``token_id``, ``token_auth`` (token_session_map)
* Free-text fields        ``message``, ``input``, ``version``, ``url``,
                          ``filename``, ``outfile``, ``destfile``,
                          ``filepath`` --- IPs / sessions / UUIDs /
                          underscored-IP path fragments embedded inside
                          these strings are also rewritten.

Usernames, passwords, command payloads, file shasums, and SSH algorithm lists
are left untouched: they are attacker-supplied data, not operator/attacker
PII, and are typically the point of the analysis.

Usage
-----
::

    python pseudonymize_logs.py --src cowriefinal1 --dst cowriefinal1_anon
    python pseudonymize_logs.py --src cowriefinal2 --dst cowriefinal2_anon \\
        --salt-file .pseudo_salt   # share salt across runs for joinable output

The salt is generated once and persisted to ``--salt-file`` (default
``.pseudo_salt`` next to the script). Reuse the same file for every run that
needs to be cross-comparable. The reverse mapping is written to
``<dst>/_pseudonym_mapping.json`` --- keep that file private; it lets anyone
recover the original values.
"""

from __future__ import annotations

import argparse
import hmac
import json
import os
import re
import secrets
import shutil
import sys
from hashlib import sha256
from pathlib import Path


IPV4_RE = re.compile(r"\b(?:\d{1,3}\.){3}\d{1,3}\b")
IPV4_UNDERSCORE_RE = re.compile(r"\b(?:\d{1,3}_){3}\d{1,3}\b")
IPV6_RE = re.compile(
    r"\b(?:[0-9a-fA-F]{1,4}:){2,7}[0-9a-fA-F]{1,4}\b"
)
UUID_RE = re.compile(
    r"\b[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-"
    r"[0-9a-fA-F]{4}-[0-9a-fA-F]{12}\b"
)
SESSION_RE = re.compile(r"\b[0-9a-f]{12}\b")
FINGERPRINT_RE = re.compile(r"\b(?:[0-9a-f]{2}:){15}[0-9a-f]{2}\b")
HASSH_RE = re.compile(r"\b[0-9a-f]{32}\b")

IP_FIELDS = {
    "src_ip", "dst_ip", "ip",
    "created_from_ip", "created_from_ip_x_forwarded_for",
}
SESSION_FIELDS = {"session", "session_id"}
TRANSPORT_FIELDS = {"transport_id"}
TEXT_FIELDS = {
    "message", "input", "version", "url", "filename", "outfile",
    "destfile", "filepath", "ttylog", "hasshAlgorithms",
}


class Pseudonymizer:
    """Deterministic, salted pseudonymization with an in-memory inverse map."""

    def __init__(self, salt: bytes) -> None:
        self._salt = salt
        # category -> {original: pseudonym}
        self._maps: dict[str, dict[str, str]] = {}

    def _hash(self, value: str) -> str:
        return hmac.new(self._salt, value.encode("utf-8"), sha256).hexdigest()

    def _alias(self, category: str, prefix: str, value: str, *, width: int = 10) -> str:
        bucket = self._maps.setdefault(category, {})
        existing = bucket.get(value)
        if existing is not None:
            return existing
        alias = f"{prefix}_{self._hash(value)[:width]}"
        bucket[value] = alias
        return alias

    # --- public field replacers -------------------------------------------

    def ip(self, value: str) -> str:
        if ":" in value:
            return self._alias("ip6", "IP6", value)
        return self._alias("ip", "IP", value)

    def session(self, value: str) -> str:
        return self._alias("session", "SESSION", value)

    def transport_id(self, value: str) -> str:
        return self._alias("transport_id", "TRANSPORT", value)

    def sensor(self, value: str) -> str:
        return self._alias("sensor", "SENSOR", value)

    def uuid(self, value: str) -> str:
        return self._alias("uuid", "UUID", value)

    def fingerprint(self, value: str) -> str:
        return self._alias("fingerprint", "FP", value)

    def hassh(self, value: str) -> str:
        return self._alias("hassh", "HASSH", value)

    def ssh_key(self, value: str) -> str:
        return self._alias("ssh_key", "KEY", value)

    def token_id(self, value: str) -> str:
        return self._alias("token_id", "TOKEN", value)

    def token_auth(self, value: str) -> str:
        return self._alias("token_auth", "TOKENAUTH", value)

    # --- text-field substitution ------------------------------------------

    def scrub_text(self, text: str) -> str:
        """Apply every regex-based replacement to a free-text string."""
        # Order matters: UUIDs and fingerprints contain hex, so they need to
        # be matched before the generic 12-hex SESSION pattern.
        text = UUID_RE.sub(lambda m: self.uuid(m.group(0)), text)
        text = FINGERPRINT_RE.sub(lambda m: self.fingerprint(m.group(0)), text)
        text = HASSH_RE.sub(lambda m: self.hassh(m.group(0)), text)
        text = IPV4_RE.sub(lambda m: self.ip(m.group(0)), text)
        # Cowrie writes attacker IPs into filesystem paths with underscores
        # (e.g. ``filesystems/130_12_180_51/...``). Recover the IP, then
        # render the same pseudonym with underscores so paths still parse.
        text = IPV4_UNDERSCORE_RE.sub(
            lambda m: self.ip(m.group(0).replace("_", ".")).replace(".", "_"),
            text,
        )
        text = IPV6_RE.sub(lambda m: self.ip(m.group(0)), text)
        text = SESSION_RE.sub(lambda m: self.session(m.group(0)), text)
        return text

    # --- export -----------------------------------------------------------

    def inverse_mapping(self) -> dict[str, dict[str, str]]:
        """Return ``{category: {pseudonym: original}}`` for safekeeping."""
        return {
            category: {alias: original for original, alias in bucket.items()}
            for category, bucket in self._maps.items()
        }


def _scrub_value(key: str, value, ps: Pseudonymizer):
    """Pseudonymize a single value based on the JSON key it sits under."""
    if value is None:
        return None
    if key in IP_FIELDS and isinstance(value, str):
        return ps.ip(value)
    if key in SESSION_FIELDS and isinstance(value, str):
        return ps.session(value)
    if key in TRANSPORT_FIELDS and isinstance(value, str):
        return ps.transport_id(value)
    if key == "sensor" and isinstance(value, str):
        return ps.sensor(value)
    if key == "uuid" and isinstance(value, str):
        return ps.uuid(value)
    if key == "fingerprint" and isinstance(value, str):
        return ps.fingerprint(value)
    if key == "hassh" and isinstance(value, str):
        return ps.hassh(value)
    if key == "key" and isinstance(value, str):
        return ps.ssh_key(value)
    if key == "token_id" and isinstance(value, str):
        return ps.token_id(value)
    if key == "token_auth" and isinstance(value, str):
        return ps.token_auth(value)
    if key in TEXT_FIELDS and isinstance(value, str):
        return ps.scrub_text(value)
    if key in TEXT_FIELDS and isinstance(value, list):
        return [ps.scrub_text(v) if isinstance(v, str) else v for v in value]
    return value


def scrub_record(record, ps: Pseudonymizer):
    if isinstance(record, dict):
        return {k: scrub_record(_scrub_value(k, v, ps), ps) for k, v in record.items()}
    if isinstance(record, list):
        return [scrub_record(v, ps) for v in record]
    return record


def is_target_file(path: Path) -> bool:
    name = path.name
    if name == "token_session_map.json":
        return True
    # Cowrie rotates logs as cowrie.json, cowrie.json.YYYY-MM-DD, etc.
    return name == "cowrie.json" or name.startswith("cowrie.json.")


def process_file(src: Path, dst: Path, ps: Pseudonymizer) -> tuple[int, int]:
    """Process one JSON-lines file. Returns (lines_written, parse_errors)."""
    dst.parent.mkdir(parents=True, exist_ok=True)
    written = 0
    errors = 0
    with src.open("r", encoding="utf-8", errors="replace") as fin, \
         dst.open("w", encoding="utf-8", newline="\n") as fout:
        for line in fin:
            stripped = line.strip()
            if not stripped:
                continue
            try:
                record = json.loads(stripped)
            except json.JSONDecodeError:
                errors += 1
                # Drop unparseable lines rather than risk leaking raw PII.
                continue
            scrubbed = scrub_record(record, ps)
            fout.write(json.dumps(scrubbed, separators=(",", ":")))
            fout.write("\n")
            written += 1
    return written, errors


def load_or_create_salt(path: Path) -> bytes:
    if path.exists():
        salt = path.read_bytes().strip()
        if not salt:
            raise SystemExit(f"salt file {path} is empty")
        return salt
    salt = secrets.token_hex(32).encode("ascii")
    path.write_bytes(salt)
    try:
        os.chmod(path, 0o600)
    except OSError:
        pass  # Windows / non-POSIX: best effort
    return salt


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[1])
    parser.add_argument("--src", required=True, type=Path,
                        help="Source directory containing Cowrie logs.")
    parser.add_argument("--dst", required=True, type=Path,
                        help="Destination directory for pseudonymized copies.")
    parser.add_argument(
        "--salt-file",
        type=Path,
        default=Path(__file__).with_name(".pseudo_salt"),
        help="Salt file. Created on first run, reused thereafter so that "
             "pseudonyms are stable across invocations.",
    )
    parser.add_argument(
        "--mapping-out",
        type=Path,
        default=None,
        help="Where to write the reverse mapping (default: "
             "<dst>/_pseudonym_mapping.json). Treat this file as sensitive --- "
             "it can fully reverse the pseudonymization.",
    )
    parser.add_argument(
        "--no-mapping",
        action="store_true",
        help="Do not write the reverse mapping file at all (irreversible).",
    )
    args = parser.parse_args()

    if not args.src.is_dir():
        print(f"error: --src {args.src} is not a directory", file=sys.stderr)
        return 2
    if args.dst.resolve() == args.src.resolve():
        print("error: --dst must differ from --src", file=sys.stderr)
        return 2

    salt = load_or_create_salt(args.salt_file)
    ps = Pseudonymizer(salt)

    total_files = 0
    total_lines = 0
    total_errors = 0
    for path in sorted(args.src.rglob("*")):
        if not path.is_file() or not is_target_file(path):
            continue
        rel = path.relative_to(args.src)
        out_path = args.dst / rel
        lines, errors = process_file(path, out_path, ps)
        total_files += 1
        total_lines += lines
        total_errors += errors
        print(f"  {rel}: {lines} lines"
              + (f" ({errors} skipped)" if errors else ""))

    if total_files == 0:
        print("warning: no Cowrie log files found under "
              f"{args.src}", file=sys.stderr)

    if not args.no_mapping:
        mapping_path = args.mapping_out or (args.dst / "_pseudonym_mapping.json")
        mapping_path.parent.mkdir(parents=True, exist_ok=True)
        with mapping_path.open("w", encoding="utf-8") as f:
            json.dump(ps.inverse_mapping(), f, indent=2, sort_keys=True)
        try:
            os.chmod(mapping_path, 0o600)
        except OSError:
            pass
        print(f"reverse mapping: {mapping_path}")

    print(f"done: {total_files} files, {total_lines} records"
          + (f", {total_errors} unparseable lines dropped" if total_errors else ""))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
