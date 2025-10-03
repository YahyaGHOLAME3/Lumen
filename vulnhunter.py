#!/usr/bin/env python3
"""
VulnHunter - Advanced Domain & Subdomain Vulnerability Scanner
"""
"""
This script performs domain/subdomain enumeration, HTTP probing, and comprehensive
vulnerability scanning using tools like subfinder, Nmap (with vulners.nse),
Nikto, Nuclei, and more.

Features:
- Domain and subdomain enumeration
- WAF detection
- TLS/SSL analysis
- HTTP security headers check
- OWASP Top 10 vulnerability scanning
- CVE detection via vulners.nse
- Performance optimizations

= = = = = = = = = =
USE AT YOUR OWN RISK!
= = = = = = = = = =
"""
import argparse
import logging
import os
import shutil
import asyncio
import aiohttp
import concurrent.futures
import subprocess
import re
import sys
import json
import time
from datetime import datetime
from urllib.parse import urlparse
from typing import List, Dict, Tuple, Set, Optional, Any, Union
from tqdm import tqdm

# Default timeout values
DEFAULT_REQUEST_TIMEOUT = 10
DEFAULT_SCAN_TIMEOUT = 600

# Additional keywords for scanning
file_exposure_keywords = [
    '.env', '.htpasswd', '.htaccess', 'config', 'settings', 'phpinfo', 'backup', 'db_backup',
    'logs', 'debug', 'error_log', 'credentials', 'database', 'test', 'sandbox', 'swagger',
    '.git', '.svn', '.DS_Store', 'web.config', 'wp-config', 'config.php', 'admin'
]

sql_keywords = [
    'sql', 'query', 'select', 'insert', 'update', 'delete', 'exec', 'db', 'table',
    'schema', 'sqlmap', 'id', 'querystring', 'mysql', 'postgres', 'oracle', 'mysqli'
]

path_traversal_keywords = [
    '../', '../../', 'root', 'etc', 'passwd', 'shadow', 'system32', 'cmd', 'bash',
    'kernel', 'windows', 'system', 'proc', 'bin', 'boot', 'dev', 'var', 'tmp'
]

api_cloud_keywords = [
    'api_key', 'secret_key', 'cloudfront', 'aws_access_key', 'aws_secret_key',
    's3_bucket', 'gcloud', 'azure_key', 'bucket', 'cloud', 'token', 'firebase',
    'gcp', 'secret', 'api-', 'oauth', 'auth', 'jwt', 'sso'
]

session_cookie_keywords = [
    'session', 'cookie', 'session_id', 'csrf', 'xsrf', 'sid', 'token', 'jwt',
    'JSESSIONID', 'PHPSESSID', 'auth', 'bearer', 'oauth'
]

xss_keywords = [
    'script', 'alert', 'onload', 'onerror', 'eval', 'javascript', 'xss',
    'cross-site', 'html', 'src=', 'href=', 'onclick', 'onmouseover'
]

# Combine all sensitive keywords
sensitive_keywords = (
    file_exposure_keywords + sql_keywords +
    path_traversal_keywords + api_cloud_keywords +
    session_cookie_keywords + xss_keywords
)

# Banner display (improved version)
def print_banner():
    banner_color = '\033[94m'  # Blue
    reset_color = '\033[0m'    # Reset

    print('=' * 84)
    print(f"{banner_color}")
    print(r'''
 _    _       _       _   _             _
| |  | |     | |     | | | |           | |
| |  | |_   _| |_ __ | |_| |_   _ _ __ | |_ ___ _ __
| |/\| | | | | | '_ \| __| | | | | '_ \| __/ _ \ '__|
\  /\  / |_| | | | | | |_| | |_| | | | | ||  __/ |
 \/  \/ \__,_|_|_| |_|\__|_|\__,_|_| |_|\__\___|_|
''')
    print(f"{reset_color}")
    print('             -- Advanced Domain & Subdomain Vulnerability Scanner -- ')
    print('=' * 84)

# Setup logging based on verbosity
def setup_logging(verbosity):
    level = logging.WARNING
    if verbosity == 1:
        level = logging.INFO
    elif verbosity >= 2:
        level = logging.DEBUG

    log_format = '%(asctime)s [%(levelname)s] %(message)s'
    if verbosity >= 2:
        log_format = '%(asctime)s [%(levelname)s] [%(filename)s:%(lineno)d] %(message)s'

    logging.basicConfig(
        level=level,
        format=log_format,
        datefmt='%H:%M:%S'
    )

    # Create a file handler for logging
    file_handler = logging.FileHandler('vulnhunter.log')
    file_handler.setFormatter(logging.Formatter(log_format))
    logging.getLogger('').addHandler(file_handler)

# CLI arguments (enhanced with more options)
def parse_args():
    parser = argparse.ArgumentParser(
        description='VulnHunter - Advanced Domain & Subdomain Vulnerability Scanner',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog='''
Examples:
  # Basic scan with default options
  python vulnhunter.py -d example.com

  # Full scan with all options
  python vulnhunter.py -d example.com --nmap --nikto --nuclei --waf --tls --headers --owasp -v

  # Targeted scan with specific ports
  python vulnhunter.py -d example.com --ports 80,443,8080 --nmap

  # Quick scan for subdomains only
  python vulnhunter.py -d example.com --subdomain-only

  # Rate-limited scan for careful enumeration
  python vulnhunter.py -d example.com --rate-limit 10 -v
'''
    )

    # Required arguments
    parser.add_argument('-d', '--domain', required=True, help='Target domain to scan')

    # Output options
    parser.add_argument('-o', '--output', default='output', help='Output directory (default: output)')
    parser.add_argument('--json', action='store_true', help='Output results in JSON format')
    parser.add_argument('--clean', action='store_true', help='Clean output directories before scanning')

    # Scan options
    parser.add_argument('--subdomain-only', action='store_true', help='Only enumerate subdomains without vulnerability scanning')
    parser.add_argument('--include-root', action='store_true', help='Always include the root domain in scans (default: true)', default=True)
    parser.add_argument('--ports', default='80,443', help='Comma-separated list of ports to scan (default: 80,443)')
    parser.add_argument('--threads', type=int, default=10, help='Number of concurrent threads for scanning (default: 10)')
    parser.add_argument('--timeout', type=int, default=DEFAULT_SCAN_TIMEOUT, help='Timeout in seconds for scanning operations (default: 600)')
    parser.add_argument('--rate-limit', type=int, help='Rate limit for requests per second')

    # Scan modules
    parser.add_argument('--nmap', action='store_true', help='Enable Nmap scanning with vulners NSE script for CVE detection')
    parser.add_argument('--nikto', action='store_true', help='Enable Nikto scanning for web vulnerabilities')
    parser.add_argument('--nuclei', action='store_true', help='Enable Nuclei scanning for known vulnerabilities')
    parser.add_argument('--waf', action='store_true', help='Detect Web Application Firewalls')
    parser.add_argument('--tls', action='store_true', help='Perform TLS/SSL security checks')
    parser.add_argument('--headers', action='store_true', help='Check HTTP security headers')
    parser.add_argument('--owasp', action='store_true', help='Perform OWASP Top 10 vulnerability checks')
    parser.add_argument('--all', action='store_true', help='Enable all scanning modules')

    # Verbosity
    parser.add_argument('-v', '--verbose', action='count', default=0, help='Increase verbosity (can be used multiple times)')

    args = parser.parse_args()

    # If --all is specified, enable all scan modules
    if args.all:
        args.nmap = args.nikto = args.nuclei = args.waf = args.tls = args.headers = args.owasp = True

    return args

# Clean output directories
def clean_dirs(base):
    dirs = ['subdomains', 'nmap_scans', 'nikto_scans', 'nuclei_reports',
            'waf_detection', 'tls_reports', 'http_headers', 'owasp_checks']
    for d in dirs:
        path = os.path.join(base, d)
        if os.path.exists(path):
            shutil.rmtree(path)
            logging.info(f'Removed {path}')

    # Recreate directories
    for d in dirs:
        path = os.path.join(base, d)
        os.makedirs(path, exist_ok=True)

# Check if a tool is installed
def check_tool_installed(tool_name):
    try:
        subprocess.run(['which', tool_name], check=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        return True
    except subprocess.SubprocessError:
        return False

# Verify required tools are installed
def verify_tools(args):
    required_tools = ['subfinder']

    if args.nmap:
        required_tools.append('nmap')
    if args.nikto:
        required_tools.append('nikto')
    if args.nuclei:
        required_tools.append('nuclei')
    if args.waf:
        required_tools.append('wafw00f')
    if args.headers:
        required_tools.append('curl')
    if args.tls:
        required_tools.append('openssl')

    missing_tools = []
    for tool in required_tools:
        if not check_tool_installed(tool):
            missing_tools.append(tool)

    if missing_tools:
        logging.error(f"Missing required tools: {', '.join(missing_tools)}")
        logging.error("Please install them before running this script.")
        return False

    return True

# Enumerate subdomains via subfinder with improved error handling
def enum_subdomains(domain, rate_limit=None):
    logging.info(f'Enumerating subdomains for {domain}')
    subdomains = set()

    # Always add the root domain
    subdomains.add(domain)

    try:
        cmd = ['subfinder', '-all', '-d', domain, '-silent']

        # Add rate limiting if specified
        if rate_limit:
            cmd.extend(['-rate-limit', str(rate_limit)])

        output = subprocess.check_output(cmd, stderr=subprocess.PIPE, timeout=300)

        for line in output.splitlines():
            subdomain = line.decode().strip()
            if subdomain:  # Only add non-empty lines
                subdomains.add(subdomain)

        logging.info(f'Found {len(subdomains)} subdomains (including root domain)')
    except subprocess.CalledProcessError as e:
        logging.error(f'Error running subfinder: {e}')
        logging.debug(f'stderr: {e.stderr.decode() if e.stderr else "None"}')
    except subprocess.TimeoutExpired:
        logging.error('Subfinder timed out')
    except Exception as e:
        logging.error(f'Unexpected error during subdomain enumeration: {e}')

    return list(subdomains)

# Async HTTP probe with better error handling
async def probe_domain(session, domain, pbar=None, timeout=DEFAULT_REQUEST_TIMEOUT):
    """Probe a domain to check if it's alive via HTTP/HTTPS"""
    results = []

    # Try HTTPS first, then fallback to HTTP if it fails
    for scheme in ['https', 'http']:
        try:
            url = f"{scheme}://{domain}"
            async with session.get(url, timeout=timeout,
                                   allow_redirects=True,
                                   ssl=False) as resp:  # Ignore SSL errors
                status = resp.status
                headers = dict(resp.headers)
                title = ''

                # Try to extract page title if it's HTML
                content_type = headers.get('Content-Type', '')
                if 'text/html' in content_type:
                    text = await resp.text(errors='ignore')
                    title_match = re.search(r'<title[^>]*>(.*?)</title>', text, re.IGNORECASE | re.DOTALL)
                    if title_match:
                        title = title_match.group(1).strip()

                results.append({
                    'domain': domain,
                    'url': url,
                    'status': status,
                    'headers': headers,
                    'title': title,
                    'alive': status < 400  # Consider it alive if status is < 400
                })

                # If HTTPS worked, no need to try HTTP
                if scheme == 'https' and status < 400:
                    break
        except Exception as e:
            logging.debug(f"Error probing {scheme}://{domain}: {e}")

    if pbar:
        pbar.update(1)

    # Return the best result (HTTPS preferred over HTTP)
    for result in results:
        if result['alive']:
            return result

    # If no successful results, return the first one or None
    return results[0] if results else None

async def probe_domains(domains, max_concurrent=10, timeout=DEFAULT_REQUEST_TIMEOUT):
    """Probe multiple domains concurrently to check if they're alive"""
    results = []

    # Custom connector with keepalive and increased connection limits
    connector = aiohttp.TCPConnector(
        ssl=False,  # We'll handle SSL errors manually
        limit_per_host=10,  # Allow more connections per host
        ttl_dns_cache=300,  # Cache DNS results
    )

    async with aiohttp.ClientSession(connector=connector) as session:
        # Create a progress bar
        with tqdm(total=len(domains), desc="Probing domains") as pbar:
            tasks = []
            semaphore = asyncio.Semaphore(max_concurrent)

            # Create a task for each domain with semaphore to limit concurrency
            async def probe_with_limit(domain):
                async with semaphore:
                    return await probe_domain(session, domain, pbar, timeout)

            # Create all tasks
            for domain in domains:
                task = asyncio.create_task(probe_with_limit(domain))
                tasks.append(task)

            # Wait for all tasks to complete
            completed_results = await asyncio.gather(*tasks, return_exceptions=True)

            # Process results, filtering out exceptions
            for result in completed_results:
                if isinstance(result, Exception):
                    logging.debug(f"Error during probing: {result}")
                elif result:  # Only add non-None results
                    results.append(result)

    # Return list of alive domains with their details
    return [r for r in results if r and r.get('alive')]

# Check for sensitive keywords
def check_sensitive(domains):
    found = []
    for domain in domains:
        domain_str = domain['domain'].lower()
        for keyword in sensitive_keywords:
            if keyword.lower() in domain_str:
                if domain not in found:
                    found.append(domain)
                    logging.info(f"Sensitive keyword found in domain: {domain['domain']} - Keyword: {keyword}")
                break
    return found

# Parse open ports from Nmap output
def parse_nmap_open_ports(nmap_file):
    ports = []
    try:
        with open(nmap_file) as f:
            for line in f:
                # Match lines with port/protocol and state
                if '/tcp' in line and 'open' in line:
                    parts = line.split()
                    if len(parts) >= 3:
                        port_proto = parts[0]
                        service = parts[2]
                        port = port_proto.split('/')[0]
                        ports.append((port, service))
    except FileNotFoundError:
        logging.error(f'Nmap output file not found: {nmap_file}')
    except Exception as e:
        logging.error(f'Error parsing Nmap output: {e}')

    return ports

# Parse CVEs from Nmap vulners output
def parse_nmap_cves(nmap_file):
    cves = []
    try:
        with open(nmap_file) as f:
            content = f.read()

            # Extract all CVEs using regex
            cve_pattern = r'CVE-\d{4}-\d{4,7}'
            found_cves = re.findall(cve_pattern, content)

            # Extract severity if available
            for cve in found_cves:
                severity = None
                severity_match = re.search(rf'{cve}.*?(\d+\.\d+)', content)
                if severity_match:
                    severity = float(severity_match.group(1))

                cves.append({
                    'id': cve,
                    'severity': severity
                })

    except FileNotFoundError:
        logging.error(f'Nmap output file not found: {nmap_file}')
    except Exception as e:
        logging.error(f'Error parsing Nmap CVEs: {e}')

    return cves

# Detect WAF using wafw00f
def detect_waf(host, output_dir):
    waf_file = os.path.join(output_dir, f'{host}_waf.txt')
    cmd = ['wafw00f', host, '-o', waf_file]

    logging.info(f'Detecting WAF for {host}')
    try:
        subprocess.run(cmd, timeout=60, capture_output=True, text=True)

        # Parse the WAF detection results
        waf_type = 'None'
        if os.path.exists(waf_file):
            with open(waf_file, 'r') as f:
                content = f.read()
                waf_match = re.search(r'The site (.*?) is behind a (.*?) WAF', content)
                if waf_match:
                    waf_type = waf_match.group(2)

        return waf_type
    except subprocess.TimeoutExpired:
        logging.error(f'WAF detection timed out for {host}')
        return "Unknown (timeout)"
    except Exception as e:
        logging.error(f'Error during WAF detection: {e}')
        return "Error"

# Check TLS/SSL security using OpenSSL
def check_tls_security(host, port, output_dir):
    tls_file = os.path.join(output_dir, f'{host}_{port}_tls.txt')

    # Use OpenSSL to check SSL/TLS
    cmd = [
        'openssl', 's_client',
        '-connect', f'{host}:{port}',
        '-servername', host,
        '-showcerts',
        '-tlsextdebug',
    ]

    logging.info(f'Checking TLS/SSL security for {host}:{port}')
    try:
        # Send a newline on stdin so OpenSSL terminates cleanly without waiting for input
        result = subprocess.run(
            cmd,
            timeout=60,
            capture_output=True,
            text=True,
            input='\n',
        )

        if result.returncode != 0:
            stderr_msg = result.stderr.strip() or 'Unknown OpenSSL error.'
            logging.error(f'TLS security check failed for {host}:{port}: {stderr_msg}')
            return {'error': stderr_msg}

        with open(tls_file, 'w') as f:
            f.write(result.stdout)

        # Parse the TLS information
        tls_info = {
            'protocol': None,
            'cipher': None,
            'cert_expiry': None,
            'cert_subject': None,
            'cert_issuer': None,
            'self_signed': False
        }

        # Extract protocol version
        protocol_match = re.search(r'Protocol  : (.*)', result.stdout)
        if protocol_match:
            tls_info['protocol'] = protocol_match.group(1)

        # Extract cipher
        cipher_match = re.search(r'Cipher    : (.*)', result.stdout)
        if cipher_match:
            tls_info['cipher'] = cipher_match.group(1)

        # Extract certificate information
        cert_match = re.search(r'subject=(.*?)\n.*?issuer=(.*?)\n.*?notAfter=(.*?)\n',
                             result.stdout, re.DOTALL)
        if cert_match:
            tls_info['cert_subject'] = cert_match.group(1).strip()
            tls_info['cert_issuer'] = cert_match.group(2).strip()
            tls_info['cert_expiry'] = cert_match.group(3).strip()

            # Check if self-signed (subject = issuer)
            if tls_info['cert_subject'] == tls_info['cert_issuer']:
                tls_info['self_signed'] = True

        return tls_info
    except subprocess.TimeoutExpired:
        logging.error(f'TLS security check timed out for {host}:{port}')
        return {"error": "timeout"}
    except Exception as e:
        logging.error(f'Error during TLS security check: {e}')
        return {"error": str(e)}

# Check HTTP security headers
def check_http_headers(url, output_dir):
    domain = urlparse(url).netloc
    headers_file = os.path.join(output_dir, f'{domain}_headers.json')

    try:
        cmd = [
            'curl', '-s', '-I',
            '-A', 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36',
            '--connect-timeout', '10',
            url
        ]

        logging.info(f'Checking HTTP security headers for {url}')
        result = subprocess.run(cmd, timeout=30, capture_output=True, text=True)

        # Parse headers
        headers = {}
        for line in result.stdout.splitlines():
            if ': ' in line:
                key, value = line.split(': ', 1)
                headers[key.strip()] = value.strip()

        # Check for security headers
        security_headers = {
            'Strict-Transport-Security': headers.get('Strict-Transport-Security', 'Missing'),
            'Content-Security-Policy': headers.get('Content-Security-Policy', 'Missing'),
            'X-Content-Type-Options': headers.get('X-Content-Type-Options', 'Missing'),
            'X-Frame-Options': headers.get('X-Frame-Options', 'Missing'),
            'X-XSS-Protection': headers.get('X-XSS-Protection', 'Missing'),
            'Referrer-Policy': headers.get('Referrer-Policy', 'Missing'),
            'Permissions-Policy': headers.get('Permissions-Policy', headers.get('Feature-Policy', 'Missing')),
            'Server': headers.get('Server', 'Not disclosed')
        }

        # Save headers to file
        with open(headers_file, 'w') as f:
            json.dump({"all_headers": headers, "security_headers": security_headers}, f, indent=2)

        return security_headers
    except subprocess.TimeoutExpired:
        logging.error(f'HTTP headers check timed out for {url}')
        return {"error": "timeout"}
    except Exception as e:
        logging.error(f'Error during HTTP headers check: {e}')
        return {"error": str(e)}

# Run Nmap scan with enhanced options including vulners.nse
def run_nmap_scan(host, output_dir, ports='80,443'):
    nmap_file = os.path.join(output_dir, f'{host}_nmap.txt')
    nmap_xml = os.path.join(output_dir, f'{host}_nmap.xml')

    # Prepare ports argument
    ports_arg = ports if ports else '80,443'

    # Determine whether we can perform a SYN scan (requires root)
    can_use_syn_scan = False
    try:
        can_use_syn_scan = hasattr(os, 'geteuid') and os.geteuid() == 0
    except AttributeError:
        # os.geteuid is not available on Windows; fall back to connect scan
        can_use_syn_scan = False

    if can_use_syn_scan:
        logging.debug('Using Nmap SYN scan (-sS). Root privileges detected.')
    else:
        logging.debug('Root privileges not detected; falling back to Nmap TCP connect scan (-sT).')

    cmd = [
        'nmap',
        '-Pn',                      # Skip host discovery
        '-sS' if can_use_syn_scan else '-sT',  # SYN scan needs root; fallback to connect scan
        '-sV',                      # Service/version detection
        '-p', ports_arg,            # Specified ports
        '--script=banner,vulners,http-security-headers,ssl-enum-ciphers,http-waf-detect',
        '-oN', nmap_file,           # Normal output
        '-oX', nmap_xml,            # XML output
        '--open',                   # Only show open ports
        '--max-retries', '2',       # Limit retries for speed
        '--host-timeout', '300s',   # 5-minute timeout per host
    ]

    if can_use_syn_scan:
        # These flags only work when we have sufficient privileges
        cmd.extend(['--min-rate', '1000', '--defeat-rst-ratelimit'])

    cmd.append(host)

    logging.info(f'Running Nmap scan on {host} (ports: {ports_arg})')
    try:
        result = subprocess.run(
            cmd,
            timeout=600,
            capture_output=True,
            text=True,
        )

        if result.returncode != 0:
            stderr_msg = result.stderr.strip() or 'Unknown Nmap error.'
            logging.error(f'Nmap scan failed for {host}: {stderr_msg}')
            return {'error': stderr_msg}

        logging.info(f'Nmap scan completed for {host}')

        # Ensure output files exist (some Nmap builds may not create them on failure)
        if not os.path.exists(nmap_file):
            with open(nmap_file, 'w') as f:
                f.write(result.stdout)
            logging.debug('Nmap normal output file was missing; populated from stdout.')
        if not os.path.exists(nmap_xml):
            logging.debug('Nmap XML output file was not created; skipping XML-specific parsing.')

        # Parse results
        open_ports = parse_nmap_open_ports(nmap_file)
        cves = parse_nmap_cves(nmap_file)

        if open_ports:
            logging.info(
                'Open ports on %s: %s',
                host,
                ', '.join([f"{port}/{service}" for port, service in open_ports])
            )

        if cves:
            logging.info(f'Found {len(cves)} potential CVEs for {host}')

        return {
            'open_ports': open_ports,
            'cves': cves,
            'nmap_file': nmap_file,
            'nmap_xml': nmap_xml
        }
    except subprocess.TimeoutExpired:
        logging.error(f'Nmap scan timed out for {host}')
        return {'error': 'timeout'}
    except Exception as e:
        logging.error(f'Error during Nmap scan: {e}')
        return {'error': str(e)}

# Run Nikto scan with enhanced options
def run_nikto_scan(host, port, output_dir, scheme='http'):
    nikto_file = os.path.join(output_dir, f'{host}_{port}_nikto.html')
    target = f'{scheme}://{host}:{port}'

    # Build the Nikto command with enhanced options
    cmd = [
        'nikto',
        '-h', target,
        '-p', str(port),
        '-Tuning', '123bde',          # More comprehensive tuning
        '-Display', 'V',              # Verbose output
        '-Format', 'html',            # HTML report
        '-o', nikto_file,             # Output path
        '-useragent', 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36',
        '-timeout', '10',             # Per-request timeout
        '-maxtime', '1800',           # Overall scan timeout: 30m
        '-Cgidirs', '/cgi-bin,/scripts,/admin,/wp-admin,/dashboard',
        '-evasion', '1',              # Simple IDS evasion
        '-ask', 'no'                  # Don't ask questions
    ]

    # Add SSL option if HTTPS
    if scheme == 'https':
        cmd.append('-ssl')

    logging.info(f'Running Nikto scan on {target}')
    try:
        result = subprocess.run(cmd, timeout=1800, capture_output=True, text=True)
        if result.returncode == 0:
            logging.info(f'Nikto scan completed for {target}')
            return {'output_file': nikto_file}
        else:
            logging.error(f'Nikto scan failed for {target}: {result.stderr}')
            return {'error': result.stderr}
    except subprocess.TimeoutExpired:
        logging.error(f'Nikto scan timed out for {target}')
        return {'error': 'timeout'}
    except Exception as e:
        logging.error(f'Error during Nikto scan: {e}')
        return {'error': str(e)}

# Run Nuclei scan with enhanced templates
def run_nuclei_scan(host, port, output_dir, scheme='http'):
    nuclei_file = os.path.join(output_dir, f'{host}_{port}_nuclei.json')
    target = f'{scheme}://{host}:{port}'

    # Build the Nuclei command with comprehensive templates
    cmd = [
        'nuclei',
        '-u', target,
        '-o', nuclei_file,
        '-j',                      # JSON output
        '-c', '50',                # Concurrency level
        '-timeout', '5',           # Template timeout
        '-retries', '2',           # Retry attempts
        '-rate-limit', '150',      # Rate limit
        '-severity', 'critical,high,medium,low',
        '-t', 'cves/',             # CVE templates
        '-t', 'vulnerabilities/',  # Vulnerability templates
        '-t', 'technologies/',     # Technology detection
        '-t', 'misconfiguration/', # Misconfigurations
        '-t', 'exposures/',        # Information exposures
        '-t', 'http/headers',      # HTTP headers
    ]

    logging.info(f'Running Nuclei scan on {target}')
    try:
        result = subprocess.run(cmd, timeout=600, capture_output=True, text=True)
        if result.returncode == 0:
            logging.info(f'Nuclei scan completed for {target}')

            # Parse results
            vulnerabilities = []
            if os.path.exists(nuclei_file):
                try:
                    with open(nuclei_file, 'r') as f:
                        for line in f:
                            try:
                                vuln = json.loads(line)
                                vulnerabilities.append(vuln)
                            except json.JSONDecodeError:
                                pass
                except Exception as e:
                    logging.error(f'Error parsing Nuclei results: {e}')

            return {
                'output_file': nuclei_file,
                'vulnerabilities': vulnerabilities
            }
        else:
            logging.error(f'Nuclei scan failed for {target}: {result.stderr}')
            return {'error': result.stderr}
    except subprocess.TimeoutExpired:
        logging.error(f'Nuclei scan timed out for {target}')
        return {'error': 'timeout'}
    except Exception as e:
        logging.error(f'Error during Nuclei scan: {e}')
        return {'error': str(e)}

# Check for OWASP Top 10 vulnerabilities
def check_owasp_top10(url, output_dir):
    domain = urlparse(url).netloc
    owasp_file = os.path.join(output_dir, f'{domain}_owasp.txt')

    # We'll use nuclei with OWASP-specific templates
    cmd = [
        'nuclei',
        '-u', url,
        '-o', owasp_file,
        '-t', 'vulnerabilities/owasp-top-10',
        '-t', 'vulnerabilities/generic/sqli',
        '-t', 'vulnerabilities/generic/xss',
        '-t', 'vulnerabilities/generic/ssrf',
        '-t', 'vulnerabilities/generic/open-redirect',
        '-t', 'vulnerabilities/generic/crlf-injection',
        '-t', 'vulnerabilities/generic/csrf',
        '-t', 'vulnerabilities/wordpress/wp-unique-vulns',
        '-severity', 'critical,high,medium',
        '-timeout', '10',
    ]

    logging.info(f'Checking OWASP Top 10 vulnerabilities for {url}')
    try:
        subprocess.run(cmd, timeout=300, capture_output=True, text=True)

        # Parse results
        owasp_results = []
        if os.path.exists(owasp_file):
            with open(owasp_file, 'r') as f:
                content = f.read()
                if content:
                    owasp_results.append(content)

        return {
            'output_file': owasp_file,
            'vulnerabilities_found': len(owasp_results) > 0,
            'results': owasp_results
        }
    except subprocess.TimeoutExpired:
        logging.error(f'OWASP check timed out for {url}')
        return {'error': 'timeout'}
    except Exception as e:
        logging.error(f'Error during OWASP check: {e}')
        return {'error': str(e)}

# Comprehensive vulnerability scanning
def scan_vulnerabilities(target, base_dir, args):
    """
    Perform comprehensive vulnerability scanning on a target

    Args:
        target: Dictionary with domain information from probe_domains
        base_dir: Base output directory
        args: Command line arguments
    """
    domain = target['domain']
    url = target['url']
    logging.info(f'Beginning vulnerability scan for {domain} ({url})')

    results = {
        'domain': domain,
        'url': url,
        'status_code': target['status'],
        'title': target.get('title', ''),
        'scans': {}
    }

    # Extract ports from URL or use default
    parsed_url = urlparse(url)
    port = parsed_url.port
    if not port:
        port = 443 if parsed_url.scheme == 'https' else 80

    # Parse additional ports to scan
    ports_to_scan = args.ports.split(',')
    if str(port) not in ports_to_scan:
        ports_to_scan.append(str(port))

    # 1) Nmap scan with vulners.nse for CVE detection
    if args.nmap:
        nmap_dir = os.path.join(base_dir, 'nmap_scans')
        os.makedirs(nmap_dir, exist_ok=True)

        nmap_result = run_nmap_scan(domain, nmap_dir, ','.join(ports_to_scan))
        results['scans']['nmap'] = nmap_result

    # 2) Detect WAF
    if args.waf:
        waf_dir = os.path.join(base_dir, 'waf_detection')
        os.makedirs(waf_dir, exist_ok=True)

        waf_result = detect_waf(domain, waf_dir)
        results['scans']['waf'] = waf_result

    # 3) Check TLS/SSL security
    if args.tls and parsed_url.scheme == 'https':
        tls_dir = os.path.join(base_dir, 'tls_reports')
        os.makedirs(tls_dir, exist_ok=True)

        tls_result = check_tls_security(domain, port, tls_dir)
        results['scans']['tls'] = tls_result

    # 4) Check HTTP security headers
    if args.headers:
        headers_dir = os.path.join(base_dir, 'http_headers')
        os.makedirs(headers_dir, exist_ok=True)

        headers_result = check_http_headers(url, headers_dir)
        results['scans']['headers'] = headers_result

    # 5) Run Nikto scan
    if args.nikto:
        nikto_dir = os.path.join(base_dir, 'nikto_scans')
        os.makedirs(nikto_dir, exist_ok=True)

        nikto_result = run_nikto_scan(domain, port, nikto_dir, parsed_url.scheme)
        results['scans']['nikto'] = nikto_result

    # 6) Run Nuclei scan
    if args.nuclei:
        nuclei_dir = os.path.join(base_dir, 'nuclei_reports')
        os.makedirs(nuclei_dir, exist_ok=True)

        nuclei_result = run_nuclei_scan(domain, port, nuclei_dir, parsed_url.scheme)
        results['scans']['nuclei'] = nuclei_result

    # 7) Check OWASP Top 10
    if args.owasp:
        owasp_dir = os.path.join(base_dir, 'owasp_checks')
        os.makedirs(owasp_dir, exist_ok=True)

        owasp_result = check_owasp_top10(url, owasp_dir)
        results['scans']['owasp'] = owasp_result

    logging.info(f'Completed vulnerability scan for {domain}')
    return results

# Generate a summary report
def generate_summary(results, output_dir):
    summary_file = os.path.join(output_dir, 'scan_summary.txt')
    json_file = os.path.join(output_dir, 'scan_results.json')

    # Save full results as JSON
    with open(json_file, 'w') as f:
        json.dump(results, f, indent=2)

    # Generate text summary
    with open(summary_file, 'w') as f:
        f.write("=" * 80 + "\n")
        f.write("                 VulnHunter Scan Summary\n")
        f.write("=" * 80 + "\n\n")

        f.write(f"Scan Date: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n")
        f.write(f"Target Domain: {results['target_domain']}\n")
        f.write(f"Subdomains Found: {len(results['all_subdomains'])}\n")
        f.write(f"Alive Hosts: {len(results['alive_hosts'])}\n")
        f.write(f"Sensitive Subdomains: {len(results['sensitive_subdomains'])}\n\n")

        # Scan statistics
        f.write("Scan Statistics:\n")
        f.write("-" * 40 + "\n")

        # Count vulnerabilities by severity
        vuln_count = {'critical': 0, 'high': 0, 'medium': 0, 'low': 0, 'info': 0, 'unknown': 0}
        cve_count = 0

        for host in results.get('vulnerability_results', []):
            # Count CVEs from Nmap+vulners
            if 'scans' in host and 'nmap' in host['scans']:
                cves = host['scans']['nmap'].get('cves', [])
                cve_count += len(cves)

            # Count Nuclei findings
            if 'scans' in host and 'nuclei' in host['scans']:
                nuclei_vulns = host['scans']['nuclei'].get('vulnerabilities', [])
                for vuln in nuclei_vulns:
                    severity = vuln.get('severity', 'unknown').lower()
                    if severity in vuln_count:
                        vuln_count[severity] += 1
                    else:
                        vuln_count['unknown'] += 1

        f.write(f"Total CVEs Found: {cve_count}\n")
        f.write("Vulnerabilities by Severity:\n")
        for sev, count in vuln_count.items():
            if count > 0:
                f.write(f"  - {sev.capitalize()}: {count}\n")
        f.write("\n")

        # List hosts with issues
        f.write("Hosts with Potential Issues:\n")
        f.write("-" * 40 + "\n")

        for host in results.get('vulnerability_results', []):
            domain = host['domain']
            has_issues = False

            # Check for CVEs
            if 'scans' in host and 'nmap' in host['scans'] and host['scans']['nmap'].get('cves'):
                has_issues = True

            # Check for Nuclei findings
            if 'scans' in host and 'nuclei' in host['scans'] and host['scans']['nuclei'].get('vulnerabilities'):
                has_issues = True

            # Check for OWASP findings
            if 'scans' in host and 'owasp' in host['scans'] and host['scans']['owasp'].get('vulnerabilities_found'):
                has_issues = True

            if has_issues:
                f.write(f"  - {domain}\n")

        f.write("\n")
        f.write("=" * 80 + "\n")
        f.write("Full results available in: " + json_file + "\n")
        f.write("=" * 80 + "\n")

    return summary_file, json_file

# Main workflow
async def main():
    args = parse_args()
    print_banner()
    setup_logging(args.verbose)

    # Verify required tools
    if not verify_tools(args):
        sys.exit(1)

    # Set up directories
    base_dir = args.output
    os.makedirs(base_dir, exist_ok=True)

    if args.clean:
        clean_dirs(base_dir)

    # Prepare subdomain directory
    subdir = os.path.join(base_dir, 'subdomains')
    os.makedirs(subdir, exist_ok=True)

    # Record start time
    start_time = time.time()

    # Step 1: Enumerate subdomains (now always including root domain)
    subdomains = enum_subdomains(args.domain, args.rate_limit)

    # Always ensure root domain is included
    if args.domain not in subdomains:
        subdomains.append(args.domain)

    with open(os.path.join(subdir, 'all.txt'), 'w') as f:
        f.write("\n".join(subdomains))

    # Step 2: Probe for alive domains
    logging.info('Probing for alive domains')
    alive_domains = await probe_domains(
        subdomains,
        max_concurrent=args.threads,
        timeout=DEFAULT_REQUEST_TIMEOUT
    )

    # Save alive domains
    with open(os.path.join(subdir, 'alive.txt'), 'w') as f:
        f.write("\n".join([d['domain'] for d in alive_domains]))

    # Step 3: Check for sensitive subdomains
    logging.info('Checking for sensitive subdomains')
    sensitive_domains = check_sensitive(alive_domains)

    with open(os.path.join(subdir, 'sensitive.txt'), 'w') as f:
        f.write("\n".join([d['domain'] for d in sensitive_domains]))

    # Early exit if subdomain-only mode
    if args.subdomain_only:
        elapsed = time.time() - start_time
        logging.info(f'Subdomain enumeration completed in {elapsed:.2f} seconds')
        logging.info(f'Found {len(subdomains)} subdomains, {len(alive_domains)} alive, {len(sensitive_domains)} sensitive')
        return

    # Step 4: Vulnerability scanning
    logging.info('Starting vulnerability scans')

    # If no alive domains were found but include_root is true, add the root domain for scanning
    if not alive_domains and args.include_root:
        logging.warning('No alive subdomains found. Adding root domain for scanning.')
        alive_domains.append({
            'domain': args.domain,
            'url': f'http://{args.domain}',
            'status': 0,
            'alive': True
        })

    # Start vulnerability scans with thread pool
    vulnerability_results = []
    with concurrent.futures.ThreadPoolExecutor(max_workers=args.threads) as executor:
        future_to_domain = {
            executor.submit(scan_vulnerabilities, domain, base_dir, args): domain
            for domain in alive_domains
        }

        # Process results as they complete
        for future in tqdm(
            concurrent.futures.as_completed(future_to_domain),
            total=len(future_to_domain),
            desc="Scanning targets"
        ):
            domain = future_to_domain[future]
            try:
                result = future.result()
                vulnerability_results.append(result)
            except Exception as e:
                logging.error(f"Error scanning {domain['domain']}: {e}")

    # Step 5: Generate summary report
    logging.info('Generating summary report')
    summary_results = {
        'target_domain': args.domain,
        'all_subdomains': subdomains,
        'alive_hosts': [d['domain'] for d in alive_domains],
        'sensitive_subdomains': [d['domain'] for d in sensitive_domains],
        'vulnerability_results': vulnerability_results
    }

    summary_file, json_file = generate_summary(summary_results, base_dir)

    # Calculate and display elapsed time
    elapsed = time.time() - start_time
    logging.info(f'Scan completed in {elapsed:.2f} seconds')
    print(f"\nScan summary saved to: {summary_file}")
    print(f"Full results saved to: {json_file}")

if __name__ == '__main__':
    try:
        if sys.version_info >= (3, 7):
            asyncio.run(main())
        else:
            # For Python 3.6 and below
            loop = asyncio.get_event_loop()
            loop.run_until_complete(main())
    except KeyboardInterrupt:
        logging.warning('Execution interrupted by user')
        sys.exit(1)
    except Exception as e:
        logging.error(f'Unhandled exception: {e}')
        sys.exit(1)
