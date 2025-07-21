"""
Loop through url_fuzz.txt, pull out every unique sub-domain, and dump
all CVEs (CVSS ≥5) into a single file:  <target>/cve_subdomains.txt
"""

import re
import subprocess
from pathlib import Path
from concurrent.futures import ThreadPoolExecutor, as_completed

from lumen_src.utils.logger import Logger
from lumen_src.utils.coloring import COLOR, COLORED_COMBOS
from lumen_src.utils.help_utils import HelpUtilities
from lumen_src.utils.exceptions import FuzzerException   # reuse existing error class

URL_RE = re.compile(r"https?://([^/\s]+)", re.I)   # grabs the hostname part

class SubdomainCVEScanner:
    def __init__(
        self,
        target_root: str,
        fuzz_log: str | None = None,
        threads: int = 8,
        ports: str = "80,443",
        min_cvss: float = 5.0,
    ):
        """
        :param target_root: directory where url_fuzz.txt lives (and where the output will be written)
        :param fuzz_log:    explicit path to url_fuzz.txt (defaults to <target_root>/url_fuzz.txt)
        """
        self.target_root = Path(target_root).expanduser()
        self.fuzz_log = Path(fuzz_log) if fuzz_log else self.target_root / "url_fuzz.txt"
        self.threads = threads
        self.ports = ports
        self.min_cvss = min_cvss

        if not self.fuzz_log.exists():
            raise FuzzerException(f"Cannot open {self.fuzz_log}; aborting CVE scan.")

        self.out_logger = self._make_logger()

    # ────────────────────────── helpers ──────────────────────────

    def _make_logger(self) -> Logger:
        """
        All sub-domain results go to <target_root>/cve_subdomains.txt
        """
        out_path = self.target_root / "cve_subdomains.txt"
        return Logger(HelpUtilities.get_output_path(out_path))

    @staticmethod
    def _extract_hosts(text: str) -> set[str]:
        """
        Return a set of hostnames found in the text (case-insensitive).
        """
        return {m.group(1).lower() for m in URL_RE.finditer(text)}

    def _run_nmap(self, host: str) -> tuple[str, str]:
        """
        Fire one Nmap scan with vulners.nse.
        Returns (host, raw_xml_output) so ThreadPool workers can gather everything.
        """
        cmd = [
            "nmap",
            "-sV",
            "-p", self.ports,
            "--script", "vulners",
            "--script-args", f"mincvss={self.min_cvss}",
            "-oX", "-",        # send XML to stdout
            host,
        ]
        res = subprocess.run(cmd, capture_output=True, text=True, check=False)
        return host, res.stdout

    @staticmethod
    def _pick_cves(nmap_xml: str) -> list[str]:
        """
        Tiny XML-less extractor – fast enough for purpose.
        """
        return sorted(set(re.findall(r"CVE-\d{4}-\d{3,7}", nmap_xml)))

    # ────────────────────────── public API ──────────────────────────

    def scan(self):
        # 1️⃣ gather all hostnames from url_fuzz.txt
        all_hosts: set[str] = set()
        with self.fuzz_log.open() as fh:
            for line in fh:
                all_hosts.update(self._extract_hosts(line))

        self.out_logger.info(f"{COLORED_COMBOS.INFO} Found {len(all_hosts)} unique hostnames to scan\n")

        # 2️⃣ threaded Nmap + vulners on each hostname
        with ThreadPoolExecutor(max_workers=self.threads) as pool:
            futures = {pool.submit(self._run_nmap, h): h for h in all_hosts}
            for future in as_completed(futures):
                host, xml = future.result()
                cves = self._pick_cves(xml)

                if not cves:
                    self.out_logger.info(f"\t{COLOR.GREEN}[{host}] No CVEs ≥{self.min_cvss}{COLOR.RESET}")
                else:
                    self.out_logger.info(f"\t{COLOR.RED}[{host}] {len(cves)} CVEs found:{COLOR.RESET}")
                    for c in cves:
                        self.out_logger.info(f"\t    {c}")
                self.out_logger.info("")  # blank line between hosts
