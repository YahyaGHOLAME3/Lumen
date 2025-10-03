import time
import asyncio
import threading
import click
import os
import sys

# Add the project root to Python path so lumen_src can be found
sys.path.insert(0, os.path.abspath(os.path.dirname(os.path.dirname(__file__))))

from lumen_src.utils.coloring import COLOR, COLORED_COMBOS
from lumen_src.utils.exceptions import LumenException, HostHandlerException
from lumen_src.utils.request_handler import RequestHandler
from lumen_src.utils.logger import SystemOutLogger
from lumen_src.utils.help_utils import HelpUtilities
from lumen_src.lib.fuzzer import URLFuzzer
#from lumen_src.utils.nikto import Nikto
from lumen_src.lib.host import Host
from lumen_src.lib.scanner import Scanner, NmapScan, NmapVulnersScan, VulnersScanner
from lumen_src.lib.sub_domain import SubDomainEnumerator
from lumen_src.lib.dns_handler import DNSHandler
from lumen_src.lib.waf import WAF
from lumen_src.lib.tls import TLSHandler
from lumen_src.lib.web_app import WebApplicationScanner


# Set path for relative access to builtin files.

MY_PATH = os.path.abspath(os.path.dirname(__file__))

DEFAULT_DNS_RECORDS = ("A", "MX", "NS", "CNAME", "SOA", "TXT")
VALID_DNS_RECORDS = {
    "A", "AAAA", "AFSDB", "APL", "CAA", "CDNSKEY", "CDS", "CERT", "CNAME",
    "DHCID", "DLV", "DNAME", "DNSKEY", "DS", "EUI48", "EUI64", "HINFO",
    "HIP", "IPSECKEY", "KEY", "KX", "LOC", "MX", "NAPTR", "NS", "NSEC",
    "NSEC3", "NSEC3PARAM", "PTR", "RRSIG", "RP", "SIG", "SOA", "SPF", "SRV",
    "SSHFP", "SVCB", "TA", "TKEY", "TLSA", "TSIG", "TXT", "URI"
}
CLI_PREPROCESS_WARNINGS: list[str] = []


def _preprocess_cli_args():
    """Normalize argv to handle missing option values gracefully."""
    global CLI_PREPROCESS_WARNINGS

    raw_args = sys.argv[1:]
    patched: list[str] = []
    warnings: list[str] = []
    i = 0

    while i < len(raw_args):
        arg = raw_args[i]

        # Helper to fetch the next argument if present
        next_arg = raw_args[i + 1] if i + 1 < len(raw_args) else None

        if arg in ("-d", "--dns-records"):
            # Support --dns-records=value syntax out of the box
            if "=" in arg and arg.startswith("--"):
                patched.append(arg)
            else:
                if not next_arg or next_arg.startswith("-"):
                    patched.extend([arg, ",".join(DEFAULT_DNS_RECORDS)])
                    warnings.append(
                        "Option '-d/--dns-records' used without a value; falling back to default records."
                    )
                else:
                    patched.extend([arg, next_arg])
                    i += 1
            i += 1
            continue

        if arg in ("-c", "--cookies"):
            # Support --cookies=value
            if "=" in arg and arg.startswith("--"):
                value = arg.split("=", 1)[1]
                if value:
                    patched.append(arg)
                else:
                    warnings.append(
                        "Option '--cookies' provided without a value; ignoring cookies option."
                    )
            else:
                if not next_arg or next_arg.startswith("-"):
                    warnings.append(
                        "Option '-c/--cookies' requires key:value pairs; ignoring cookies option."
                    )
                else:
                    patched.extend([arg, next_arg])
                    i += 1
            i += 1
            continue

        patched.append(arg)
        i += 1

    sys.argv = [sys.argv[0]] + patched
    CLI_PREPROCESS_WARNINGS = warnings


def intro(logger):
    logger.info("""{}
+-----------------------------------------------------------------------+
|                                                                       |
|                    ___           ___           ___           ___      |
|                   /__/\         /__/\         /  /\         /__/\     |
|                   \  \:\       |  |::\       /  /:/_        \  \:\    |
|  ___     ___       \  \:\      |  |:|:\     /  /:/ /\        \  \:\   |
| /__/\   /  /\  ___  \  \:\   __|__|:|\:\   /  /:/ /:/_   _____\__\:\  |
| \  \:\ /  /:/ /__/\  \__\:\ /__/::::| \:\ /__/:/ /:/ /\ /__/::::::::\ |
|  \  \:\  /:/  \  \:\ /  /:/ \  \:\~~\__\/ \  \:\/:/ /:/ \  \:\~~\~~\/ |
|   \  \:\/:/    \  \:\  /:/   \  \:\        \  \::/ /:/   \  \:\  ~~~  |
|    \  \::/      \  \:\/:/     \  \:\        \  \:\/:/     \  \:\      |
|     \__\/        \  \::/       \  \:\        \  \::/       \  \:\     |
|                   \__\/         \__\/         \__\/         \__\/     |
|                                                                       |
+-----------------------------------------------------------------------+
{}

-------------------------------------------------------------------
    """.format(COLOR.GRAY, COLOR.RESET))


@click.command()
@click.version_option("0.8.5")
@click.argument("target")
@click.option("-d", "--dns-records", default="A,MX,NS,CNAME,SOA,TXT",
              help="Comma separated DNS records to query. Defaults to: A,MX,NS,CNAME,SOA,TXT")
@click.option("--tor-routing", is_flag=True, help="Route HTTP traffic through Tor (uses port 9050)."
                                                  " Slows total runtime significantly")
@click.option("--proxy-list", help="Path to proxy list file that would be used for routing HTTP traffic."
                                   " A proxy from the list will be chosen at random for each request."
                                   " Slows total runtime")
@click.option("-c", "--cookies", help="Comma separated cookies to add to the requests. "
                                        "Should be in the form of key:value\n"
                                        "Example: PHPSESSID:12345,isMobile:false")
@click.option("--proxy", help="Proxy address to route HTTP traffic through. Slows total runtime")
@click.option("-w", "--wordlist", default=os.path.join(MY_PATH, "wordlists/fuzzlist"),
                help="Path to wordlist that would be used for URL fuzzing")
@click.option("-T", "--threads", default=25,
              help="Number of threads to use for URL Fuzzing/Subdomain enumeration. Default: 25")
@click.option("--ignored-response-codes", default="302,400,401,402,403,404,503,504",
                help="Comma separated list of HTTP status code to ignore for fuzzing."
                    " Defaults to: 302,400,401,402,403,404,503,504")
@click.option("--subdomain-list", default=os.path.join(MY_PATH, "wordlists/subdomains"),
              help="Path to subdomain list file that would be used for enumeration")
@click.option("-sc", "--scripts", is_flag=True, help="Run Nmap scan with -sC flag")
@click.option("-sv", "--services", is_flag=True, help="Run Nmap scan with -sV flag")
@click.option("-f", "--full-scan", is_flag=True, help="Run Nmap scan with both -sV and -sC")
@click.option("-p", "--port", help="Use this port range for Nmap scan instead of the default")
@click.option("--vulners-nmap-scan", is_flag=True, help="Perform an NmapVulners scan. "
                                                        "Runs instead of the regular Nmap scan and is longer.")
@click.option("--vulners-path", default=os.path.join(MY_PATH, "utils/misc/vulners.nse"),
              help="Path to the custom nmap_vulners.nse script."
                   "If not used, Lumen uses the built-in script it ships with.")
@click.option("-fr", "--follow-redirects", is_flag=True, default=False,
              help="Follow redirects when fuzzing. Default: False (will not follow redirects)")
@click.option("--tls-port", default=443, help="Use this port for TLS queries. Default: 443")
@click.option("--skip-health-check", is_flag=True, help="Do not test for target host availability")
@click.option("--no-url-fuzzing", is_flag=True, help="Do not fuzz URLs")
@click.option("--no-sub-enum", is_flag=True, help="Do not bruteforce subdomains")
@click.option("--skip-nmap-scan", is_flag=True, help="Do not perform an Nmap scan")
# @click.option("-d", "--delay", default="0.25-1",
#               help="Min and Max number of seconds of delay to be waited between requests\n"
#                    "Defaults to Min: 0.25, Max: 1. Specified in the format of Min-Max")
@click.option("-q", "--quiet", is_flag=True, help="Do not output to stdout")
@click.option("-v", "--verbose", count=True, help="Increase output verbosity (use -vv for debug)")
@click.option("-o", "--outdir", default="Lumen_scan_results",
              help="Directory destination for scan output")
@click.option("--subdomain-cve-scan", is_flag=True, help="Parse url_fuzz.txt and scan every hostname for CVEs, writing cve_subdomains.txt")

def main(target,
         tor_routing,
         proxy_list,
         proxy,
         cookies,
         dns_records,
         wordlist,
         threads,
         ignored_response_codes,
         subdomain_list,
         full_scan,
         scripts,
         services,
         port,
         vulners_nmap_scan,
         vulners_path,
         tls_port,
         skip_health_check,
         follow_redirects,
         no_url_fuzzing,
         no_sub_enum,
         skip_nmap_scan,
         # delay,
         outdir,
         quiet,
         verbose,
         subdomain_cve_scan):
    try:
        # ------ Arg validation ------
        # Set logging level and Logger instance
        log_level = HelpUtilities.determine_verbosity(quiet, verbose)
        logger = SystemOutLogger(log_level)
        intro(logger)

        logger.debug(
            "CLI options -> quiet=%s, verbose=%s, follow_redirects=%s, skip_nmap_scan=%s",
            quiet,
            verbose,
            follow_redirects,
            skip_nmap_scan
        )

        for warning in CLI_PREPROCESS_WARNINGS:
            logger.warning(warning)

        target = target.lower()
        try:
            HelpUtilities.validate_executables()
        except LumenException as e:
            logger.critical(str(e))
            exit(9)
        logger.debug("Validated required external executables")
        HelpUtilities.validate_wordlist_args(proxy_list, wordlist, subdomain_list)
        HelpUtilities.validate_proxy_args(tor_routing, proxy, proxy_list)
        HelpUtilities.create_output_directory(outdir)
        logger.debug("Output directory prepared at %s", outdir)

        if tor_routing:
            logger.info("{} Testing that Tor service is up...".format(COLORED_COMBOS.NOTIFY))
        elif proxy_list:
            if proxy_list and not os.path.isfile(proxy_list):
                raise FileNotFoundError("Not a valid file path, {}".format(proxy_list))
            else:
                logger.info("{} Routing traffic using proxies from list {}\n".format(
                    COLORED_COMBOS.NOTIFY, proxy_list))
        elif proxy:
            logger.info("{} Routing traffic through proxy {}\n".format(COLORED_COMBOS.NOTIFY, proxy))

        # TODO: Sanitize delay argument

        parsed_dns_records = [record.strip().upper() for record in dns_records.split(",") if record.strip()]
        invalid_dns_records = [record for record in parsed_dns_records if record not in VALID_DNS_RECORDS]
        dns_records = tuple(record for record in parsed_dns_records if record in VALID_DNS_RECORDS)

        if invalid_dns_records:
            logger.warning(
                "Ignoring invalid DNS record types: {}".format(", ".join(invalid_dns_records))
            )

        if not dns_records:
            dns_records = DEFAULT_DNS_RECORDS
            logger.info(
                "{} No valid DNS record types provided; using defaults {}".format(
                    COLORED_COMBOS.NOTIFY, ",".join(DEFAULT_DNS_RECORDS)
                )
            )
        logger.debug("Resolved DNS record list: %s", ",".join(dns_records))
        ignored_response_codes = tuple(int(code) for code in ignored_response_codes.split(","))
        logger.debug("Ignored response codes: %s", ignored_response_codes)

        if port:
            HelpUtilities.validate_port_range(port)

        # ------ /Arg validation ------

        if cookies:
            if ":" not in cookies:
                if cookies in {"-fr", "--follow-redirects"}:
                    follow_redirects = True
                    logger.debug("Promoted stray follow-redirects flag into option handling")
                logger.warning(
                    "Cookies must be supplied as comma separated key:value pairs. Ignoring provided cookies option."
                )
                cookies = None
            else:
                try:
                    cookies = HelpUtilities.parse_cookie_arg(cookies)
                except LumenException as e:
                    logger.warning("{}{}{}".format(COLOR.YELLOW, str(e), COLOR.RESET))
                    cookies = None
        logger.debug("Cookies configured: %s", bool(cookies))

        # Set Request Handler instance
        request_handler = RequestHandler(
            proxy_list=proxy_list,
            tor_routing=tor_routing,
            single_proxy=proxy,
            cookies=cookies
        )
        logger.debug(
            "Request handler initialised (tor_routing=%s, proxy_list=%s, single_proxy=%s)",
            tor_routing,
            bool(proxy_list),
            bool(proxy)
        )

        if tor_routing:
            try:
                HelpUtilities.confirm_traffic_routs_through_tor()
                logger.info("{} Validated Tor service is up. Routing traffic anonymously\n".format(
                    COLORED_COMBOS.NOTIFY))
            except LumenException as err:
                print("{}{}{}".format(COLOR.RED, str(err), COLOR.RESET))
                exit(3)

        main_loop = asyncio.get_event_loop()

        logger.info("{}### Lumen Scan Started ###{}\n".format(COLOR.GRAY, COLOR.RESET))
        logger.info("{} Trying to gather information about host: {}".format(COLORED_COMBOS.INFO, target))

        # TODO: Populate array when multiple targets are supported
        # hosts = []
        try:
            host = Host(target=target, dns_records=dns_records)
            host.parse()
            logger.debug(
                "Host parsing complete: target=%s, protocol=%s, port=%s", host.target, host.protocol, host.port
            )
        except HostHandlerException as e:
            logger.critical("{}{}{}".format(COLOR.RED, str(e), COLOR.RESET))
            exit(11)

        if not skip_health_check:
            try:
                HelpUtilities.validate_target_is_up(host)
            except LumenException as err:
                logger.critical("{}{}{}".format(COLOR.RED, str(err), COLOR.RESET))
                exit(42)

        if not skip_nmap_scan:
            if vulners_nmap_scan:
                logger.info("\n{} Setting NmapVulners scan to run in the background".format(COLORED_COMBOS.INFO))
                nmap_vulners_scan = NmapVulnersScan(host=host, port_range=port, vulners_path=vulners_path)
                nmap_thread = threading.Thread(target=VulnersScanner.run, args=(nmap_vulners_scan,))
                # Run NmapVulners scan in the background
                nmap_thread.start()
                logger.debug("Started NmapVulners thread (port_range=%s, vulners_path=%s)", port, vulners_path)
            else:
                logger.info("\n{} Setting Nmap scan to run in the background".format(COLORED_COMBOS.INFO))
                nmap_scan = NmapScan(
                    host=host,
                    port_range=port,
                    full_scan=full_scan,
                    scripts=scripts,
                    services=services)

                nmap_thread = threading.Thread(target=Scanner.run, args=(nmap_scan,))
                # Run Nmap scan in the background. Can take some time
                nmap_thread.start()
                logger.debug(
                    "Started Nmap thread (port_range=%s, full_scan=%s, scripts=%s, services=%s)",
                    port,
                    full_scan,
                    scripts,
                    services
                )
        if not skip_nmap_scan:
            if nmap_thread.is_alive():
                logger.info("{} All scans done. Waiting for Nmap scan to wrap up…".format(
                    COLORED_COMBOS.INFO))
                nmap_thread.join()  # Improved: Use join() instead of sleep loop for efficiency
                logger.debug("Background Nmap thread joined (initial wait)")

        # Run first set of checks - TLS, Web/WAF Data, DNS data
        waf = WAF(host)
        tls_info_scanner = TLSHandler(host, tls_port)
        web_app_scanner = WebApplicationScanner(host)
        tasks = (
            asyncio.ensure_future(tls_info_scanner.run()),
            asyncio.ensure_future(waf.detect()),
            asyncio.ensure_future(DNSHandler.grab_whois(host)),
            asyncio.ensure_future(web_app_scanner.run_scan()),
            asyncio.ensure_future(DNSHandler.generate_dns_dumpster_mapping(host, logger))
        )

        main_loop.run_until_complete(asyncio.wait(tasks))
        logger.debug("Core reconnaissance tasks completed")

        # Second set of checks - URL fuzzing, Subdomain enumeration
        if not no_url_fuzzing:
            fuzzer = URLFuzzer(
                host,
                wordlist_path=wordlist,
                num_threads=threads,
                ignored_codes=ignored_response_codes,
                follow_redirects=follow_redirects,
                quiet=quiet,
                console_level=log_level,
            )
            main_loop.run_until_complete(
                fuzzer.fuzz(
                    sub_domain=False,
                    log_file_path="{}/url_fuzz.txt".format(host.target)
                )
            )
            logger.debug("URL fuzzing completed")

        if not host.is_ip:
            sans = tls_info_scanner.sni_data.get("SANs")
            subdomain_enumerator = SubDomainEnumerator(
                host,
                domain_list=subdomain_list,
                sans=sans,
                ignored_response_codes=ignored_response_codes,
                num_threads=threads,
                follow_redirects=follow_redirects,
                no_sub_enum=no_sub_enum
            )
            main_loop.run_until_complete(subdomain_enumerator.run())
            logger.debug("Subdomain enumeration completed")

        if not skip_nmap_scan:
            if nmap_thread.is_alive():
                logger.info("{} All scans done. Waiting for Nmap scan to wrap up. "
                            "Time left may vary depending on scan type and port range".format(COLORED_COMBOS.INFO))
                nmap_thread.join()  # Improved: Use join() instead of sleep loop for efficiency
                logger.debug("Background Nmap thread joined (final wait)")

        logger.info("\n{}### Lumen scan finished ###{}\n".format(COLOR.GRAY, COLOR.RESET))
        os.system("stty sane")

        SubdomainCVEScanner = None  # Placeholder in case the condition is False
        if subdomain_cve_scan:
            from lumen_src.lib.subdomain_cve_scanner import SubdomainCVEScanner

        if SubdomainCVEScanner is not None:
            SubdomainCVEScanner(target_root=target).scan()
        else:
            # Optional: Log or handle the case where scanning is skipped
            logger.info("Subdomain CVE scan skipped based on conditions.")  # Improved: Use logger instead of print for consistency


    except KeyboardInterrupt:
        print("{}Keyboard Interrupt detected. Exiting{}".format(COLOR.RED, COLOR.RESET))
        # Fix F'd up terminal after CTRL+C
        os.system("stty sane")
        exit(42)

if __name__ == "__main__":
    _preprocess_cli_args()
    main()
