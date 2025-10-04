# Lumen

**Offensive Security Tool for Reconnaissance and Information Gathering**

![os](https://img.shields.io/badge/OS-Linux,%20macOS-yellow.svg)
![pythonver](https://img.shields.io/badge/python-3.10%2B-blue.svg)
![version](https://img.shields.io/badge/version-0.8.5-lightgrey.svg)

## Highlights
- Full-scope recon in one run: DNS, WHOIS, TLS fingerprinting, WAF detection, web metadata, and storage hunting
- Concurrent Nmap discovery plus the `vulners.nse` script and Nikto web scanning – all enabled by default
- Dir and file brute-forcing with a configurable fuzzer and smart response filtering
- Rich subdomain enumeration via SAN parsing, Google dorking, DNSDumpster, and brute-force wordlists
- Flexible routing (Tor/proxy support) and structured per-target output for easy triage
- Built with asyncio and thread pools to keep scans fast without sacrificing coverage

## Quick Start

### Option 1 – Docker
```bash
# Build the image
docker build -t lumen-scan .

# Run a scan (outputs land in ./Lumen_scan_results on the host)
docker run --rm \
  -v "$(pwd)/Lumen_scan_results:/home/lumen/app/Lumen_scan_results" \
  lumen-scan example.com
```
The container ships with Nmap, Nikto, and other native dependencies pre-installed. Mount an output directory to persist results between runs.

### Option 2 – Native Python
```bash
git clone https://github.com/evyatarmeged/Lumen.git
cd Lumen

python3 -m venv .venv
source .venv/bin/activate

pip install --upgrade pip
pip install -r requirements.txt
pip install -e .

lumen example.com
```
Prerequisites: Python 3.10+, Nmap, Nikto, and OpenSSL available in your `PATH`. On macOS install `coreutils` (`brew install coreutils`) to provide `gtimeout`.

### Option 3 – Use the bundled launcher without installing
If you do not want to install the package into your environment, the repository ships with a thin wrapper that executes the CLI in-place:

```bash
git clone https://github.com/evyatarmeged/Lumen.git
cd Lumen

python3 -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt

# Optional: add the repo to your PATH or symlink the launcher
chmod +x lumen
ln -s "$(pwd)/lumen" ~/.local/bin/lumen  # assuming ~/.local/bin is on PATH

lumen --help
```
This keeps the code editable while giving you the same `lumen` command line interface on any machine you clone the project to.

## Recon Dashboard

Every `lumen` run now launches the Streamlit dashboard automatically (defaults to `http://localhost:8501`) and opens it in your default browser. Use `--no-dashboard` if you’re running headless or prefer not to start the UI.

You can still launch it manually when needed:

```bash
streamlit run dashboard/app.py         # direct runner
lumen-dashboard                        # console script after pip install
```

The sidebar lets you point the dashboard at any scan output directory. Every new Lumen run updates `dashboard/state.json`, so the UI always defaults to your latest `--outdir`. Each target view includes quick metrics, CVE tables, raw logs, and an embedded Nikto report when available.

## Usage
```text
Usage: lumen [OPTIONS] TARGET

Options:
  -d, --dns-records TEXT                 Comma separated DNS records to query.
                                         Defaults to: A,MX,NS,CNAME,SOA,TXT
  --tor-routing                          Route HTTP traffic through Tor (port
                                         9050)
  --proxy-list TEXT                      Load-balanced proxy list for HTTP(S)
                                         requests
  --proxy TEXT                           Single proxy to route HTTP(S) traffic
  -c, --cookies TEXT                     Comma separated cookies (key:value)
  -w, --wordlist TEXT                    Wordlist for URL fuzzing
  -T, --threads INTEGER                  Worker threads for fuzzing/subdomain
                                         enumeration (default: 25)
  --ignored-response-codes TEXT          HTTP codes to ignore during fuzzing
                                         (default: 302,400,401,402,403,404,503,504)
  --subdomain-list TEXT                  Wordlist for subdomain brute-forcing
  -sc, --scripts                         Add Nmap -sC
  -sv, --services                        Add Nmap -sV
  -f, --full-scan                        Combine -sC and -sV
  -p, --port TEXT                        Custom port range for Nmap
  --vulners-nmap-scan / --skip-vulners-nmap-scan
                                         Run the Nmap vulners script (default:
                                         enabled)
  --vulners-path TEXT                    Custom path to vulners.nse
  --skip-nmap-scan                       Skip the default Nmap discovery scan
  --nikto-scan / --skip-nikto-scan       Run Nikto against the primary web
                                         service (default: enabled)
  --dashboard / --no-dashboard           Auto-launch the dashboard (default:
                                         enabled)
  --dashboard-port INTEGER               Dashboard listener port (default:
                                         8501)
  -fr, --follow-redirects                Follow redirects during fuzzing
  --tls-port INTEGER                     Port for TLS checks (default: 443)
  --skip-health-check                    Do not verify host availability before
                                         scanning
  --no-url-fuzzing                       Skip URL fuzzing
  --no-sub-enum                          Skip subdomain brute-force
  --subdomain-cve-scan                   Parse url_fuzz.txt and probe each host
                                         with Nmap + vulners
  -q, --quiet                            Suppress stdout logging
  -v, --verbose                          Increase verbosity (-vv for debug)
  -o, --outdir TEXT                      Output directory (default:
                                         Lumen_scan_results)
  --help                                 Show this message and exit
```
All core scanners (Nmap, Nmap + vulners, Nikto, TLS/WAF profiling, URL fuzzing, and subdomain recon) are active by default. Opt out with the `--skip-*`/`--no-*` flags if you need a lighter run.

## Output Layout
Each scan is stored under `<outdir>/<target>/<YYYYMMDD-HHMMSS>/`, so older runs stay side-by-side with the latest. Inside a run directory you’ll find:
- `nmap_scan.txt`, `nmap_vulners_scan.txt`, and `nikto_report.html`
- `web_scan.txt`, `waf.txt`, `tls_report.txt`, `whois.txt`, and other module logs
- `url_fuzz.txt`, `subdomains.txt`, and optional `cve_subdomains.txt`
- `scan_metadata.json` capturing the enabled modules and dashboard URL for that execution
- `summary.json` providing a structured view consumed by the dashboard
- A root-level `manifest.json` that aggregates every run across all domains, keeping combined CVE/open-port/URL-hit totals up to date

These files are plain text/HTML and can be shared with downstream tooling or attached to reports.

## Support & Contributions
Issues and pull requests are welcome. Please open an issue describing the bug or feature idea before submitting large changes.
