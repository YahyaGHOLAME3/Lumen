import re
import subprocess
import urllib.request
from pathlib import Path
from subprocess import PIPE, Popen
from typing import List, Tuple, Optional

from lumen_src.utils.help_utils import HelpUtilities
from lumen_src.utils.logger import Logger
from lumen_src.utils.coloring import COLOR, COLORED_COMBOS

# ---------------------------------------------------------------------------
#  Constants
# ---------------------------------------------------------------------------
RAW_VULNERS_URL = (
    "https://raw.githubusercontent.com/vulnersCom/nmap-vulners/master/vulners.nse"
)


class NmapScan:
    """Generic Nmap scanner wrapper."""

    def __init__(
        self,
        host,
        port_range: Optional[str] = None,
        *,
        full_scan: bool | None = None,
        scripts: bool | None = None,
        services: bool | None = None,
    ) -> None:
        self.target: str = host.target
        self.full_scan = full_scan
        self.scripts = scripts
        self.services = services
        self.port_range = port_range

        # One log‑file per scan type / target ▸  <target>/nmap_scan.txt
        self.path = HelpUtilities.get_output_path(f"{self.target}/nmap_scan.txt")
        self.logger = Logger(self.path)

    # ------------------------------------------------------------------
    #  Template method – subclasses extend/override build_script()
    # ------------------------------------------------------------------
    def build_script(self) -> List[str]:
        """Return the argv list that will be passed to *subprocess*."""
        script: List[str] = ["nmap", "-Pn", self.target]

        # Port range
        if self.port_range:
            HelpUtilities.validate_port_range(self.port_range)
            script.extend(["-p", self.port_range])
            self.logger.info(
                f"{COLORED_COMBOS.NOTIFY} Added port range {self.port_range} to Nmap script"
            )

        # Script / service detection flags
        if self.full_scan:
            script.extend(["-sV", "-sC"])
            self.logger.info(
                f"{COLORED_COMBOS.NOTIFY} Added scripts and services to Nmap script"
            )
        else:
            if self.scripts:
                script.append("-sC")
                self.logger.info(
                    f"{COLORED_COMBOS.NOTIFY} Added safe‑scripts scan to Nmap script"
                )
            if self.services:
                script.append("-sV")
                self.logger.info(
                    f"{COLORED_COMBOS.NOTIFY} Added service scan to Nmap script"
                )
        return script


class NmapVulnersScan(NmapScan):
    """Run *vulners.nse* against the target.

    Path resolution order (first hit wins):
    1. Explicit --vulners-path argument
    2. Project‑local copy  ▸  lumen_src/utils/misc/vulners.nse
    3. System Nmap DATADIR/scripts/vulners.nse
    4. **Auto‑download** from GitHub to project‑local copy
    """

    def __init__(
        self,
        host,
        port_range: Optional[str] = None,
        *,
        vulners_path: str | Path | None = None,
    ) -> None:
        super().__init__(host=host, port_range=port_range)

        # Resolve path to vulners.nse (may auto‑download)
        self.vulners_path: str = self._resolve_vulners_path(vulners_path)

        # Dedicated log file
        self.path = HelpUtilities.get_output_path(
            f"{self.target}/nmap_vulners_scan.txt"
        )
        self.logger = Logger(self.path)

    # ------------------------------------------------------------------
    #  Path resolution helpers
    # ------------------------------------------------------------------
    def _resolve_vulners_path(self, custom_path: str | Path | None) -> str:
        # 1️⃣  Caller‑supplied path
        if custom_path:
            p = Path(custom_path).expanduser().resolve()
            if p.is_file():
                return str(p)

        # 2️⃣  Project‑local copy
        local_copy = (
            Path(__file__).resolve().parent.parent / "utils" / "misc" / "vulners.nse"
        )
        if local_copy.is_file():
            return str(local_copy)

        # 3️⃣  System copy inside Nmap DATADIR
        try:
            version_out = subprocess.check_output(["nmap", "--version"], text=True)
            datadir_line = next(l for l in version_out.splitlines() if "DATADIR" in l)
            datadir = datadir_line.split("DATADIR:")[-1].strip()
            system_copy = Path(datadir) / "scripts" / "vulners.nse"
            if system_copy.is_file():
                return str(system_copy)
        except Exception:
            pass  # Fall through to auto‑download

        # 4️⃣  Auto‑download to project utils/misc
        try:
            self.logger.info(
                f"{COLORED_COMBOS.NOTIFY} vulners.nse not found – downloading fresh copy …"
            )
            local_copy.parent.mkdir(parents=True, exist_ok=True)
            urllib.request.urlretrieve(RAW_VULNERS_URL, local_copy)
            self.logger.info(
                f"{COLORED_COMBOS.GOOD} Downloaded vulners.nse to {local_copy}"
            )
            return str(local_copy)
        except Exception as e:
            raise FileNotFoundError(
                "Failed to locate or download vulners.nse. Pass --vulners-path or install the script manually."
            ) from e

    # ------------------------------------------------------------------
    #  Build command
    # ------------------------------------------------------------------
    def build_script(self) -> List[str]:
        script: List[str] = [
            "nmap",
            "-Pn",
            "-sV",
            "-sC",
            "--script",
            self.vulners_path,
            self.target,
        ]

        if self.port_range:
            HelpUtilities.validate_port_range(self.port_range)
            script.extend(["-p", self.port_range])
            self.logger.info(
                f"{COLORED_COMBOS.NOTIFY} Added port range {self.port_range} to Nmap script"
            )
        return script


class Scanner:
    """Execute any *NmapScan* subclass and log/parse its output."""

    @classmethod
    def run(cls, scan: NmapScan) -> None:
        script = scan.build_script()

        scan.logger.info(f"{COLORED_COMBOS.INFO} Nmap script to run: {' '.join(script)}")
        scan.logger.info(f"{COLORED_COMBOS.GOOD} Nmap scan started\n")

        process = Popen(script, stdout=PIPE, stderr=PIPE)
        result, err = process.communicate()
        result, err = result.decode().strip(), err.decode().strip()

        if err:
            scan.logger.error(err)
        if result:
            parsed = cls._parse_scan_output(result)
            if parsed:
                scan.logger.info(parsed)

        cls._write_raw(scan, result, err)

    # ------------------------------------------------------------------
    #  Output helpers
    # ------------------------------------------------------------------
    @staticmethod
    def _write_raw(scan: NmapScan, result: str, err: str) -> None:
        """Persist raw stdout/stderr to the scan log file."""
        Path(scan.path).write_text("")  # truncate
        if result:
            scan.logger.debug(result + "\n")
        if err:
            scan.logger.debug(err + "\n")

    @staticmethod
    def _parse_scan_output(result: str) -> str:
        parsed_output = ""
        for line in result.split("\n"):
            if "PORT" in line and "STATE" in line:
                parsed_output += f"{COLORED_COMBOS.GOOD} Nmap discovered the following ports:\n"
                continue
            if ("/tcp" in line or "/udp" in line) and "open" in line:
                cols = line.split()
                parsed_output += f"\t{COLOR.GREEN}{cols[0]}{COLOR.RESET} {' '.join(cols[1:])}\n"
        return parsed_output


class VulnersScanner(Scanner):
    """Parse *vulners.nse* results and highlight CVEs."""

    @classmethod
    def _parse_scan_output(cls, result: str) -> str:
        ports_with_cves, ports_clean = cls._split_ports(result)

        # Colour‑highlight ports and CVE strings
        highlight_port = lambda s: re.sub(r"(\d+\/(?:tcp|udp))", COLOR.GREEN + r"\1" + COLOR.RESET, s)
        highlight_cve = lambda s: re.sub(r"(\sCVE\S*)", COLOR.RED + r"\1" + COLOR.RESET, s)

        ports_with_cves = highlight_port(ports_with_cves)
        ports_with_cves = highlight_cve(ports_with_cves)
        ports_clean = highlight_port(ports_clean)

        parsed_output = ""
        if ports_clean:
            parsed_output += (
                f"{COLORED_COMBOS.GOOD} NmapVulners discovered the following open ports:\n{ports_clean}"
            )
        if ports_with_cves:
            parsed_output += (
                f"{COLORED_COMBOS.GOOD} NmapVulners discovered vulnerable software on these ports:\n{ports_with_cves}"
            )
        return parsed_output

    # ------------------------------------------------------------------
    #  Private helpers
    # ------------------------------------------------------------------
    @staticmethod
    def _split_ports(res: str) -> Tuple[str, str]:
        """Separate port blocks that contain CVE information from those that do not.

        The function looks for sections like:
            80/tcp open  http
            | vulners: ...
            |   CVE-xxxx-xxxx ...
            |_  CVE-yyyy-yyyy ...

        Everything between the port line and the final `|_` terminator is kept
        together so the caller can colourise and print it intact.
        """
        block_re = r"(?:^\d+/(?:tcp|udp).*open.*$\n(?:^\|.*$\n)+)"
        blocks = re.findall(block_re, res, re.MULTILINE)

        with_cve = ""
        without_cve = ""
        for b in blocks:
            if "CVE" in b or "vulners" in b:
                with_cve += b
            else:
                without_cve += b
        return with_cve, without_cve
