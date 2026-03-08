# Rust SSH Log Analyzer

A high-performance Rust CLI tool that parses standard Linux `auth.log` files to **detect SSH brute-force attempts**. It identifies attacking IPs, counts failed login attempts, and lists the usernames each attacker targeted—helping security teams quickly spot and prioritize response to credential-stuffing and brute-force campaigns.

---

## Prerequisites

- **Rust** (install from [rustup.rs](https://rustup.rs)).
- **GeoIP (optional):** For country-of-origin enrichment, download the free **GeoLite2-Country** database (`.mmdb`) from [MaxMind](https://dev.maxmind.com/geoip/geolite2-free-geolocation-data). Sign up for a free license and download `GeoLite2-Country.mmdb`. Pass it with the `-g` / `--geoip` flag.

---

## Setup

For features that need an API key (e.g. AbuseIPDB), create a **`.env`** file in the project root:

```bash
ABUSEIPDB_API_KEY=your_abuseipdb_key_here
```

The tool loads `.env` automatically at startup, so you never need to pass the key on the command line or in shell history.

**Security:** Never commit `.env` to version control. Ensure **`.env`** is listed in **`.gitignore`** (it is in this repo). Keep keys out of shell history and logs.

---

## Features

- **Memory-efficient parsing** — Uses `std::io::BufReader` to read the log file **line-by-line**. The file is never loaded entirely into memory, so the tool scales to very large log files (e.g., hundreds of MB or more) without excessive RAM usage.
- **Precise extraction** — Uses the **regex** crate to match only lines indicating failed SSH logins and to capture both the **username** and **IP address**. Supports both forms:
  - `Failed password for <user> from <ip> ...`
  - `Failed password for invalid user <user> from <ip> ...`
- **Aggregated reporting** — Builds a per-IP summary (total attempts + unique usernames) and prints a sorted “Top Attackers” report to the terminal.
- **Configurable threshold** — Use `-t` / `--threshold` to show only attackers with at least N failed attempts, reducing noise from one-off probes (default: 1 = show all).
- **CSV export** — Use `-o` / `--output` to export the filtered Top Attackers list to a CSV file for actionable firewall blocklists or further analysis (same threshold applies; headers: IP, Country, Abuse Score, Attempts, Usernames).
- **Offline GeoIP data enrichment** — Use `-g` / `--geoip` with a MaxMind DB path (e.g. **GeoLite2-Country.mmdb**) to resolve the **country ISO code** (e.g. US, CN) for each attacking IP. Works fully offline; invalid or unknown IPs show as "Unknown". The terminal report shows the code next to the IP (e.g. `IP: 1.2.3.4 [CN]`), and the CSV gains a **Country** column.
- **Automated Threat Intelligence** — Integrates with the **AbuseIPDB API** via the `-a` / `--abuseipdb` flag (or seamlessly via `.env`). The tool fetches the real-time "Abuse Confidence Score" (0–100%) for each attacking IP, empowering analysts to immediately identify and block high-confidence threats.

---

## Usage

The tool reads **ABUSEIPDB_API_KEY** from a `.env` file (or the environment) when needed, so you can run it without putting secrets in the command line or shell history.

Analyze an `auth.log` file by passing its path with `--file` (or `-f`):

```bash
cargo run -- --file auth.log
```

**Full example** — filter, GeoIP enrichment, and CSV export. The API key is loaded securely from `.env` in the background:

```bash
cargo run -- -f auth.log -t 2 -g GeoLite2-Country.mmdb -o blocklist.csv
```

**Filter out low-level noise** with the optional `-t` / `--threshold` flag: only attackers with **at least** that many failed attempts are shown. The default is `1` (show all).

```bash
# Show only attackers with 5 or more failed attempts
cargo run -- -f auth.log -t 5
```

**Export to CSV** with `-o` / `--output` to write the filtered list to a file (e.g. for firewall blocklists):

```bash
# Filter to 3+ attempts and export to blocklist.csv
cargo run -- -f auth.log -t 3 -o blocklist.csv
```

**Add country-of-origin** with `-g` / `--geoip` (path to GeoLite2-Country.mmdb). Combine with threshold and CSV export:

```bash
# Filter, enrich with GeoIP, and export (IP, Country, Attempts, Usernames)
cargo run -- -f auth.log -t 2 -g GeoLite2-Country.mmdb -o blocklist.csv
```

**Enrich with Threat Intelligence** (AbuseIPDB score). Securely load your API key via the `.env` file to prevent credential leakage in shell history. Combine with GeoIP and CSV export for a complete threat report:

```bash
cargo run -- -f auth.log -t 2 -g GeoLite2-Country.mmdb -o blocklist.csv
```

Or run the release binary directly (e.g., after `cargo build --release`):

```bash
./target/release/log_analyzer --file /var/log/auth.log
./target/release/log_analyzer --file /var/log/auth.log --threshold 10
./target/release/log_analyzer -f /var/log/auth.log -t 3 -o blocklist.csv
./target/release/log_analyzer -f /var/log/auth.log -t 2 -g GeoLite2-Country.mmdb -o blocklist.csv
```

On Windows:

```powershell
.\target\release\log_analyzer.exe --file auth.log
.\target\release\log_analyzer.exe -f auth.log -t 5
.\target\release\log_analyzer.exe -f auth.log -t 3 -o blocklist.csv
.\target\release\log_analyzer.exe -f auth.log -t 2 -g GeoLite2-Country.mmdb -o blocklist.csv
```

---

## Example Output

Running the analyzer on a sample `auth.log` produces a report like:

```
═══════════════════════════════════════════════════════════════
              SSH BRUTE-FORCE LOG ANALYSIS REPORT
═══════════════════════════════════════════════════════════════

  Total failed login attempts analyzed: 8
  Showing attackers with >= 1 failed attempts

  Top Attackers (by failed attempt count)
  ---------------------------------------
    IP: 114.114.114.114  |  Attempts: 4  |  Usernames: [root]
    IP: 203.0.113.45  |  Attempts: 2  |  Usernames: [ftp, root]
    IP: 198.51.100.22  |  Attempts: 2  |  Usernames: [admin]

═══════════════════════════════════════════════════════════════
```

With GeoIP (`-g GeoLite2-Country.mmdb`) and AbuseIPDB (API key in `.env` or `-a`), the report includes country codes and abuse confidence scores with clear pipe separators:

```
  Top Attackers (by failed attempt count)
  ---------------------------------------
    IP: 114.114.114.114 [CN]   | Abuse Score: 100% |  Attempts: 4  |  Usernames: [root]
    IP: 203.0.113.45 [US]      | Abuse Score: 25%  |  Attempts: 2  |  Usernames: [ftp, root]
    IP: 198.51.100.22 [US]     | Abuse Score: 0%   |  Attempts: 2  |  Usernames: [admin]
```

Exported CSV with `-o blocklist.csv` (and optional `-g` and AbuseIPDB) has headers **IP, Country, Abuse Score, Attempts, Usernames**:

```csv
IP,Country,Abuse Score,Attempts,Usernames
114.114.114.114,CN,100%,4,root
203.0.113.45,US,25%,2,ftp;root
198.51.100.22,US,0%,2,admin
```

With a threshold (e.g. `-t 5`) only attackers meeting the minimum attempt count are listed; the header shows the applied threshold, and if none qualify you’ll see: **No attackers met the threshold of X attempts.**

The report shows:

1. **Total failed login attempts** — Number of matching “Failed password …” lines.
2. **Top Attackers** — IPs sorted by failed attempt count (descending).
3. **Per-attacker details** — IP, attempt count, and the list of unique usernames they tried.

---

## License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.
