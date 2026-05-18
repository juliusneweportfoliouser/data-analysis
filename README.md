# Code to analyze Cowrie and Canarytoken alerts

*The Python scripts have been generated using Claude Code. This README has been generated with OpenAI Codex.*

This code analyzes Cowrie logs and checks whether attackers triggered the
Canarytokens that were placed during Cowrie sessions.

*Please Note: The data analysis scripts are unable to run against pseudonymised Cowrie logs. The scripts here have only been provided for documentation.*

## Usage

1. Download the files from Cowrie:
   - `cowrie.json` files go into `<data-dir>/cowrie_logs/`
   - `token_session_map.json` goes into `<data-dir>/`.
2. Place the Canarytoken server credential export in the same `<data-dir>`.
   It must be JSON Lines, with one object per line:

   ```json
   {"token_id": "a9sw4id4lh9tajw4zh6w9oneo", "auth_token": "b00af1d8a9cbd2061c453604bcd5e53a"}
   ```

3. `python -m venv .venv`
4. On Windows: `.venv/Scripts/Activate.ps1`. On Linux: `source .venv/bin/activate`
5. `pip install -r requirements.txt`
6. Set the config variables (described below).
7. Merge the real Canarytoken auth values into `token_session_map.json`:

   ```bash
   python merge_token_creds.py <data-dir>
   ```

   Example:

   ```bash
   python merge_token_creds.py cowriefinal2
   ```

   If the credentials file cannot be auto-detected, pass it explicitly:

   ```bash
   python merge_token_creds.py cowriefinal2 canarytoken_creds.jsonl
   ```

8. Analyze the Cowrie logs:

   ```bash
   python analyze_cowrie.py --data-dir <data-dir>
   ```

9. Fetch Canarytoken trigger histories:

   ```bash
   python fetch_token_stats.py --data-dir <data-dir>
   ```

### Config file

The config file is to be placed in the project root directory, named `config.cfg`. Here is the expected content:

```bash
[canarytoken]

canarytoken_api_url = <Self-Hosted Canarytoken URL>

cnarytoken_api_basicauth_username = <BasicAuth user>
canarytoken_api_basicauth_password = <BasicAuth password>
```

## Scripts

### `merge_token_creds.py`

`token_session_map.json` contains redacted `token_auth` values. Before
running `fetch_token_stats.py`, use `merge_token_creds.py` to overwrite those
values with the real auth tokens from the Canarytoken server export.

The merge is based on `token_id`. The credential export may use either
`auth_token` or `token_auth`; both are accepted. The script updates
`token_session_map.json` in place and creates a `.bak` backup by default.

Useful commands:

```bash
python merge_token_creds.py cowriefinal2
python merge_token_creds.py cowriefinal2 canarytoken_creds.jsonl
python merge_token_creds.py cowriefinal2 --dry-run
python merge_token_creds.py --token-map cowriefinal2/token_session_map.json --creds-file cowriefinal2/canarytoken_creds.jsonl
```

Treat both the Canarytoken credential export and the updated
`token_session_map.json` as sensitive files.

### `analyze_cowrie.py`

Analyzes Cowrie JSON logs from `<data-dir>/cowrie_logs/` and prints session
activity, commands, downloads, and credentials. If
`<data-dir>/token_session_map.json` exists, token placement information is
included; otherwise that section is skipped.

### `fetch_token_stats.py`

Fetches trigger history for each token in `<data-dir>/token_session_map.json`
and writes the full result to `<data-dir>/token_history.json`. Self-hosted
tokens are fetched from the configured Canarytoken server. AWS tokens are
fetched from the public `canarytokens.com` service.

Run `merge_token_creds.py` first if `token_auth` values in
`token_session_map.json` are redacted.

### `compare_honeypots.py`

Compares multiple honeypot datasets and writes a spreadsheet report.

### `pseudonymize_logs.py`

Creates pseudonymized copies of Cowrie logs and `token_session_map.json` for
sharing or analysis. Keep the generated reverse mapping private because it can
recover the original values.

## Output

### `analyze_cowrie.py`
The commands and other data for each session are printed to the terminal. The output can be piped to a file if necessary. Here is sample output for a session:

```bash
  Session: 05ddaee1a495
    IP:       <Attacker IP>
    Time:     2026-03-09T06:40:36.520686Z
    Login:    {'username': 'root', 'password': 'password'}
    Duration: 3.1s
    Client:   SSH-2.0-Go
    HASSH:    2ec37a7cc8daf20b10e1ad6221061ca5
    Commands (4):
      > export PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin:$PATH; uname=$(uname -s -v -n -m 2>/dev/null); arch=$(uname -m 2>/dev/null); uptime=$(cat /proc/uptime 2>/dev/null | cut -d. -f1); cpus=$( (nproc 2>/dev/null || /usr/bin/nproc 2>/dev/null || grep -c "^processor" /proc/cpuinfo 2>/dev/null) | head -1); cpu_model=$( (grep -m1 -E "model name|Hardware" /proc/cpuinfo | cut -d: -f2- | sed 's/^ *//;s/ *$//' ; lscpu 2>/dev/null | awk -F: '/Model name/ {gsub(/^ +| +$/,"",$2); print $2; exit}' ; dmidecode -s processor-version 2>/dev/null | head -n1 ; uname -p 2>/dev/null) | awk 'NF{print; exit}' ); gpu_info=$( (lspci 2>/dev/null | grep -i vga; lspci 2>/dev/null | grep -i nvidia) 2>/dev/null | head -n50); cat_help=$( (cat --help 2>&1 | tr '\n' ' ') || cat --help 2>&1); ls_help=$( (ls --help 2>&1 | tr '\n' ' ') || ls --help 2>&1); last_output=$(last 2>/dev/null | head -n 10); echo "UNAME:$uname"; echo "ARCH:$arch"; echo "UPTIME:$uptime"; echo "CPUS:$cpus"; echo "CPU_MODEL:$cpu_model"; echo "GPU:$gpu_info"; echo "CAT_HELP:$cat_help"; echo "LS_HELP:$ls_help"; echo "LAST:$last_output"
      > uname -s -v -n -m 2 > /dev/null
      > uname -m 2 > /dev/null
      > cat /proc/uptime 2 > /dev/null | cut -d. -f1
```

### `fetch_token_stats.py`

The number of triggers for each Canarytoken is pulled from the Canarytoken server (the public `canarytokens.com` service for AWS tokens).
