"""
AI Generated

Canarytoken Statistics Fetcher

Pulls trigger history for each Canarytoken from the self-hosted
Canarytokens server (and canarytokens.com for AWS tokens).
Reads configuration from config.cfg and token list from
data/token_session_map.json.
"""

import argparse
import configparser
import json
import os
from collections import defaultdict
from concurrent.futures import ThreadPoolExecutor, as_completed
from datetime import datetime, timezone

import requests

BASE_DIR = os.path.dirname(__file__)
CONFIG_PATH = os.path.join(BASE_DIR, "config.cfg")
DEFAULT_DATA_DIR = os.path.join(BASE_DIR, "data")
TOKEN_MAP_PATH = os.path.join(DEFAULT_DATA_DIR, "token_session_map.json")
OUTPUT_PATH = os.path.join(DEFAULT_DATA_DIR, "token_history.json")

# The fixed path component used by the Canarytokens history API
HISTORY_PATH = "d3aece8093b71007b5ccfedad91ebb11"

# AWS tokens are hosted on the public server
PUBLIC_CANARYTOKEN_URL = "https://canarytokens.com/"


def load_config(path: str = CONFIG_PATH) -> dict:
    """Load server URL and BasicAuth credentials from config.cfg."""
    cfg = configparser.ConfigParser()
    cfg.read(path)
    section = cfg["canarytoken"]
    return {
        "api_url": section["canarytoken_api_url"].rstrip("/"),
        "username": section["cnarytoken_api_basicauth_username"],
        "password": section["canarytoken_api_basicauth_password"],
    }


def load_token_map(path: str = TOKEN_MAP_PATH) -> list[dict]:
    """Load all token entries from the mapping file."""
    tokens = []
    with open(path, encoding="utf-8") as f:
        for line in f:
            line = line.strip()
            if line:
                tokens.append(json.loads(line))
    return tokens


def fetch_token_history(
    token_id: str,
    token_auth: str,
    base_url: str,
    basic_auth: tuple[str, str] | None = None,
) -> dict:
    """
    Fetch the trigger history for a single Canarytoken.

    API endpoint:
        GET {base_url}/{HISTORY_PATH}/history?auth={token_auth}&token={token_id}

    Returns the parsed JSON response.
    """
    url = f"{base_url}/{HISTORY_PATH}/history"
    params = {"auth": token_auth, "token": token_id}
    kwargs = {"params": params, "timeout": 30}
    if basic_auth:
        kwargs["auth"] = basic_auth

    resp = requests.get(url, **kwargs)
    resp.raise_for_status()
    return resp.json()


def extract_hits(api_response: dict) -> list[dict]:
    """
    Extract the list of hits from a Canarytoken history API response.

    The response nests hits under canarydrop -> triggered_details -> hits
    and also under history -> hits.  We use triggered_details as primary.
    """
    canarydrop = api_response.get("canarydrop", {})
    triggered = canarydrop.get("triggered_details", {})
    hits = triggered.get("hits", [])
    return hits


def summarize_hits(hits: list[dict]) -> dict:
    """Produce a summary dict from a list of hit records."""
    if not hits:
        return {"total_hits": 0, "unique_ips": 0, "source_ips": [], "first_hit": None, "last_hit": None}

    ips = [h["src_ip"] for h in hits if h.get("src_ip")]
    times = [h["time_of_hit"] for h in hits if h.get("time_of_hit")]

    first = datetime.fromtimestamp(min(times), tz=timezone.utc).isoformat() if times else None
    last = datetime.fromtimestamp(max(times), tz=timezone.utc).isoformat() if times else None

    ip_counts = defaultdict(int)
    for ip in ips:
        ip_counts[ip] += 1

    return {
        "total_hits": len(hits),
        "unique_ips": len(set(ips)),
        "source_ips": [{"ip": ip, "count": c} for ip, c in sorted(ip_counts.items(), key=lambda x: -x[1])],
        "first_hit": first,
        "last_hit": last,
    }


def _fetch_one(token: dict, base_url: str, auth: tuple[str, str] | None) -> dict:
    """Fetch history for a single token and return a result dict."""
    token_id = token["token_id"]
    token_auth = token["token_auth"]
    try:
        raw = fetch_token_history(token_id, token_auth, base_url, auth)
        hits = extract_hits(raw)
        summary = summarize_hits(hits)
        return {
            "token_id": token_id,
            "token_auth": token_auth,
            "token_type": token["token_type"],
            "session_id": token["session_id"],
            "hits": hits,
            "summary": summary,
            "error": None,
        }
    except requests.RequestException as exc:
        return {
            "token_id": token_id,
            "token_auth": token_auth,
            "token_type": token["token_type"],
            "session_id": token["session_id"],
            "hits": [],
            "summary": summarize_hits([]),
            "error": str(exc),
        }


def fetch_all_token_stats(
    token_map: list[dict],
    config: dict,
    max_workers: int = 20,
) -> list[dict]:
    """
    Fetch history for every token in the map.

    Self-hosted tokens (non-AWS) are fetched in parallel with up to
    *max_workers* concurrent requests.  AWS tokens are fetched
    sequentially against the public canarytokens.com server to avoid
    overwhelming it.

    Returns a list of result dicts with token info, hits, and summary.
    """
    basic_auth = (config["username"], config["password"])

    aws_tokens = [t for t in token_map if t["token_type"] == "AWS"]
    other_tokens = [t for t in token_map if t["token_type"] != "AWS"]
    total = len(token_map)
    results = []

    # --- Self-hosted tokens: parallel (up to max_workers) ---
    if other_tokens:
        print(f"  Fetching {len(other_tokens)} self-hosted tokens "
              f"(up to {max_workers} in parallel)...")
        futures = {}
        with ThreadPoolExecutor(max_workers=max_workers) as pool:
            for token in other_tokens:
                future = pool.submit(
                    _fetch_one, token, config["api_url"], basic_auth,
                )
                futures[future] = token

            for future in as_completed(futures):
                result = future.result()
                results.append(result)
                done = len(results)
                status = (f"{result['summary']['total_hits']} hits"
                          if not result["error"] else f"ERROR: {result['error']}")
                print(f"  [{done}/{total}] {result['token_type']:12s} "
                      f"{result['token_id']}  {status}")

    # --- AWS tokens: sequential against public server ---
    if aws_tokens:
        print(f"  Fetching {len(aws_tokens)} AWS tokens sequentially "
              f"from {PUBLIC_CANARYTOKEN_URL}...")
        pub_url = PUBLIC_CANARYTOKEN_URL.rstrip("/")
        for token in aws_tokens:
            result = _fetch_one(token, pub_url, None)
            results.append(result)
            done = len(results)
            status = (f"{result['summary']['total_hits']} hits"
                      if not result["error"] else f"ERROR: {result['error']}")
            print(f"  [{done}/{total}] {result['token_type']:12s} "
                  f"{result['token_id']}  {status}")

    return results


def print_stats_report(results: list[dict]) -> None:
    """Print a summary report of all fetched token statistics."""
    triggered = [r for r in results if r["summary"]["total_hits"] > 0]
    errors = [r for r in results if r["error"]]

    print(f"\n{'=' * 70}")
    print(f"  CANARYTOKEN STATISTICS REPORT")
    print(f"{'=' * 70}")
    print(f"  Total tokens:     {len(results)}")
    print(f"  Triggered tokens: {len(triggered)}")
    print(f"  Errors:           {len(errors)}")

    # Per token type
    by_type = defaultdict(lambda: {"total": 0, "triggered": 0, "total_hits": 0})
    for r in results:
        by_type[r["token_type"]]["total"] += 1
        if r["summary"]["total_hits"] > 0:
            by_type[r["token_type"]]["triggered"] += 1
        by_type[r["token_type"]]["total_hits"] += r["summary"]["total_hits"]

    print(f"\n  By token type:")
    for ttype, stats in sorted(by_type.items()):
        print(f"    {ttype:12s}  {stats['triggered']:3d}/{stats['total']:3d} triggered  "
              f"({stats['total_hits']} total hits)")

    # Tokens with most hits
    if triggered:
        print(f"\n  Top triggered tokens:")
        for r in sorted(triggered, key=lambda x: -x["summary"]["total_hits"])[:20]:
            s = r["summary"]
            print(f"    {r['token_type']:12s} {r['token_id']}  "
                  f"{s['total_hits']:>4d} hits from {s['unique_ips']} IPs  "
                  f"(session {r['session_id']})")

    # Unique attacker IPs that triggered tokens
    all_ips = set()
    for r in triggered:
        for ip_info in r["summary"]["source_ips"]:
            all_ips.add(ip_info["ip"])
    if all_ips:
        print(f"\n  Unique IPs that triggered tokens: {len(all_ips)}")
        for ip in sorted(all_ips):
            print(f"    {ip}")

    if errors:
        print(f"\n  Tokens with errors:")
        for r in errors:
            print(f"    {r['token_type']:12s} {r['token_id']}  {r['error']}")


# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Fetch Canarytoken trigger histories.")
    parser.add_argument(
        "--data-dir",
        default=DEFAULT_DATA_DIR,
        help="Directory containing token_session_map.json; output is written to "
             "<data-dir>/token_history.json (default: %(default)s)",
    )
    args = parser.parse_args()

    token_map_path = os.path.join(args.data_dir, "token_session_map.json")
    output_path = os.path.join(args.data_dir, "token_history.json")

    print("Loading configuration...")
    config = load_config()
    print(f"  Server: {config['api_url']}")

    print(f"Loading token map from {token_map_path}...")
    token_map = load_token_map(token_map_path)
    print(f"  {len(token_map)} tokens across "
          f"{len({t['session_id'] for t in token_map})} sessions")

    print("\nFetching token histories...")
    results = fetch_all_token_stats(token_map, config)

    print_stats_report(results)

    # Save full results to JSON
    print(f"\nSaving full results to {output_path}...")
    with open(output_path, "w", encoding="utf-8") as f:
        json.dump(results, f, indent=2)
    print("Done.")
