#!/usr/bin/env python3
"""
SubHTTPx - Subdomain Enumeration and Vulnerability Scanner
"""
"""
This script performs subdomain enumeration, HTTP probing, and vulnerability scanning,
 = = = = = = = = = =
 USE AT YOU OWN RISK!
 = = = = = = = = = =

It uses tools like subfinder, Nmap, Nikto, and Nuclei to gather information about a target domain.
It can also check for sensitive subdomains based on predefined keywords.
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

# Additional keywords for scanning
file_exposure_keywords = [
    '.env', '.htpasswd', '.htaccess', 'config', 'settings', 'phpinfo', 'backup', 'db_backup',
    'logs', 'debug', 'error_log', 'credentials', 'database', 'test', 'sandbox'
]

sql_keywords = [
    'sql', 'query', 'select', 'insert', 'update', 'delete', 'exec', 'db', 'table',
    'schema', 'sqlmap', 'id', 'querystring'
]

path_traversal_keywords = [
    '../', '../../', 'root', 'etc', 'passwd', 'shadow', 'system32', 'cmd', 'bash',
    'kernel', 'windows', 'system', 'proc', 'bin'
]

api_cloud_keywords = [
    'api_key', 'secret_key', 'cloudfront', 'aws_access_key', 'aws_secret_key',
    's3_bucket', 'gcloud', 'azure_key', 'bucket', 'cloud', 'token'
]

session_cookie_keywords = [
    'session', 'cookie', 'session_id', 'csrf', 'xsrf', 'sid', 'token', 'jwt',
    'JSESSIONID', 'PHPSESSID'
]

xss_keywords = [
    'script', 'alert', 'onload', 'onerror', 'eval', 'javascript', 'xss',
    'cross-site', 'html', 'src=', 'href='
]

# Combine all sensitive keywords
sensitive_keywords = (
            file_exposure_keywords + sql_keywords +
            path_traversal_keywords + api_cloud_keywords +
            session_cookie_keywords + xss_keywords)

# Banner display (do not change)
def print_banner():
        print('=' * 84)
        print(r'''
 _____                                                                        _____
( ___ )                                                                      ( ___ )
 |   |~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~|   |
 |   |                                                                        |   |
 |   |   _    _         _         _     _                                     |   |
 |   |  | |  | |       | |       | |   | |               _                    |   |
 |   |  | |  | | _   _ | | ____  | |__ | | _   _  ____  | |_    ____   ____   |   |
 |   |   \ \/ / | | | || ||  _ \ |  __)| || | | ||  _ \ |  _)  / _  ) / ___)  |   |
 |   |    \  /  | |_| || || | | || |   | || |_| || | | || |__ ( (/ / | |      |   |
 |   |     \/    \____||_||_| |_||_|   |_| \____||_| |_| \___) \____)|_|      |   |
 |   |                                                                        |   |
 |___|~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~|___|
(_____)                                                                      (_____)
        ''')
        print('             -- Subdomain Enumeration and Vulnerability Scanner -- ')
        print('=' * 84)


# Setup logging based on verbosity
def setup_logging(verbosity):
    level = logging.WARNING
    if verbosity == 1:
        level = logging.INFO
    elif verbosity >= 2:
        level = logging.DEBUG
    logging.basicConfig(
        level=level,
        format='%(asctime)s [%(levelname)s] %(message)s',
        datefmt='%H:%M:%S'
    )

# CLI arguments
def parse_args():
    parser = argparse.ArgumentParser(
        description='SubHTTPx - Subdomain & Vulnerability Scanner'
    )
    parser.add_argument('-d', '--domain', required=True, help='Target domain')
    parser.add_argument('-o', '--output', default='output', help='Output directory')
    parser.add_argument('--nmap', action='store_true', help='Enable Nmap scanning')
    parser.add_argument('--nikto', action='store_true', help='Enable Nikto scanning')
    parser.add_argument('--nuclei', action='store_true', help='Enable Nuclei scanning')
    parser.add_argument('--clean', action='store_true', help='Clean output dirs first')
    parser.add_argument('-v', '--verbose', action='count', default=0, help='Increase verbosity')
    return parser.parse_args()

# Clean output directories
def clean_dirs(base):
    dirs = ['subdomains', 'nmap_scans', 'nikto_scans', 'nuclei_reports']
    for d in dirs:
        path = os.path.join(base, d)
        if os.path.exists(path):
            shutil.rmtree(path)
            logging.info(f'Removed {path}')

# Enumerate subdomains via subfinder
def enum_subdomains(domain):
    logging.info(f'Enumerating subdomains for {domain}')
    try:
        output = subprocess.check_output(
            ['subfinder', '-all', '-d', domain, '-silent'],
            stderr=subprocess.DEVNULL
        )
        return [line.decode().strip() for line in output.splitlines() if line.strip()]
    except subprocess.CalledProcessError:
        logging.error('Error running subfinder')
        return []

# Async HTTP probe
async def probe_domain(session, url):
    try:
        async with session.get(f'http://{url}', timeout=5) as resp:
            if resp.status < 400:
                logging.debug(f'{url} is alive (HTTP {resp.status})')
                return url
    except Exception:
        return None

async def probe_domains(domains):
    async with aiohttp.ClientSession() as session:
        tasks = [probe_domain(session, d) for d in domains]
        results = await asyncio.gather(*tasks)
    return [r for r in results if r]

# Check for sensitive keywords
def check_sensitive(domains):
    found = []
    for d in domains:
        lower = d.lower()
        if any(kw.lower() in lower for kw in sensitive_keywords):
            found.append(d)
    return found

# Parse open ports from Nmap output
def parse_nmap_open_ports(nmap_file):
    ports = []
    try:
        with open(nmap_file) as f:
            for line in f:
                if '/tcp' in line and 'open' in line:
                    parts = line.split()
                    if len(parts) >= 3:
                        port_proto = parts[0]
                        service = parts[2]
                        port = port_proto.split('/')[0]
                        ports.append((port, service))
    except FileNotFoundError:
        logging.error(f'Nmap output file not found: {nmap_file}')
    return ports

# Scan vulnerabilities: Nmap→Nikto→Nuclei
def scan_vulnerabilities(host, base, use_nmap, use_nikto, use_nuclei):
    logging.debug(f'Beginning vulnerability scan for {host}')
    open_ports = []

    # 1) Nmap scan, parse open ports
    if use_nmap:
        nmap_dir = os.path.join(base, 'nmap_scans'); os.makedirs(nmap_dir, exist_ok=True)
        nmap_file = os.path.join(nmap_dir, f'{host}_nmap.txt')
        cmd = ['nmap', '-sS','-sV', '-O', '-A', '--script=vuln', '-oN', nmap_file, host]
        logging.info(f'Running Nmap on {host}')
        try:
            subprocess.run(cmd, timeout=300, capture_output=True, text=True)
            open_ports = parse_nmap_open_ports(nmap_file)
            logging.info(f'Found open ports for {host}: {open_ports}')
        except subprocess.TimeoutExpired:
            logging.error(f'Nmap timed out on {host}')

    # 2) Nikto scan on HTTP(S) ports
    if use_nikto:
        nikto_dir = os.path.join(base, 'nikto_scans')
        os.makedirs(nikto_dir, exist_ok=True)

        if not open_ports:
            logging.warning(f'No open ports to scan with Nikto for {host}')

        for port, service in open_ports:
            if 'http' not in service.lower():
                continue

            # choose scheme based on port/service
            scheme = 'https' if port == 443 or 'ssl' in service.lower() else 'http'
            target = f'{scheme}://{host}:{port}'
            out_file = os.path.join(nikto_dir, f'{host}_{port}_nikto.html')

            # build the full command
            cmd = [
                'nikto',
                '-h', target,
                '-p', str(port),
                '-Tuning', '123b',                         # interesting files, misconfigs, info disclosure + backup/software
                '-Display', 'V',                           # verbose: all info/warnings/errors
                '-Format', 'html',                         # HTML report
                '-o', out_file,                            # output path
                '-useragent', 'Mozilla/5.0 (compatible; Nikto/2.5.0)',
                '-timeout', '10',                          # per-request timeout
                '-maxtime', '1800',                        # overall scan timeout: 30m
                '-Cgidirs', '/cgi-bin,/scripts',           # explicit CGI dirs
                '-Evasion', '4',                           # simple IDS evasion
            ]
            if scheme == 'https':
                cmd.append('-ssl')

            logging.info(f'Running Nikto on {target}')
            try:
                res = subprocess.run(cmd, timeout=1800, capture_output=True, text=True)
                if res.returncode == 0:
                    logging.info(f'Nikto results saved to {out_file}')
                else:
                    logging.error(f'Nikto error for {target}: {res.stderr.strip()}')
            except subprocess.TimeoutExpired:
                logging.error(f'Nikto timed out on {target}')


    # 3) Nuclei scan on HTTP(S) ports
    if use_nuclei:
        nuclei_dir = os.path.join(base, 'nuclei_reports'); os.makedirs(nuclei_dir, exist_ok=True)
        if not open_ports:
            logging.warning(f'No open ports to scan with Nuclei for {host}')
        for port, service in open_ports:
            if 'http' not in service.lower():
                continue
            scheme = 'https' if port == '443' or 'https' in service.lower() else 'http'
            target = f'{scheme}://{host}:{port}'
            out_file = os.path.join(nuclei_dir, f'{host}_{port}_nuclei.txt')
            cmd = ['nuclei', '-u', target, '-o', out_file]
            logging.info(f'Running Nuclei on {target}')
            try:
                res = subprocess.run(cmd, timeout=300, capture_output=True, text=True)
                if res.returncode == 0:
                    logging.info(f'Nuclei results saved to {out_file}')
                else:
                    logging.error(f'Nuclei error for {target}: {res.stderr.strip()}')
            except subprocess.TimeoutExpired:
                logging.error(f'Nuclei timed out on {target}')

# Main workflow
def main():
    args = parse_args()
    print_banner()
    setup_logging(args.verbose)

    base = args.output; os.makedirs(base, exist_ok=True)
    if args.clean:
        clean_dirs(base)

    subs = enum_subdomains(args.domain)
    subdir = os.path.join(base, 'subdomains'); os.makedirs(subdir, exist_ok=True)
    with open(os.path.join(subdir, 'all.txt'), 'w') as f:
        f.write("\n".join(subs))

    logging.info('Probing for alive subdomains')
    alive = asyncio.run(probe_domains(subs))
    with open(os.path.join(subdir, 'alive.txt'), 'w') as f:
        f.write("\n".join(alive))

    logging.info('Checking for sensitive subdomains')
    sens = check_sensitive(alive)
    with open(os.path.join(subdir, 'sensitive.txt'), 'w') as f:
        f.write("\n".join(sens))

    logging.info('Starting vulnerability scans')
    if not alive:
        logging.warning('No alive hosts found, skipping vulnerability scans')
    else:
        with concurrent.futures.ThreadPoolExecutor(max_workers=os.cpu_count() or 4) as pool:
            pool.map(
                lambda h: scan_vulnerabilities(h, base, args.nmap, args.nikto, args.nuclei),
                alive
            )

if __name__ == '__main__':
    try:
        main()
    except KeyboardInterrupt:
        logging.warning('Execution interrupted by user')
        sys.exit(1)
