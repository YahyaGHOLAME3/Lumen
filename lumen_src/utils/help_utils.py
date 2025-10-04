import os
import json
import distutils.spawn
from datetime import datetime
from pathlib import Path
from platform import system
from collections import Counter
from subprocess import PIPE, check_call, CalledProcessError
from requests.exceptions import ConnectionError
from lumen_src.utils.exceptions import LumenException, ScannerException, RequestHandlerException
from lumen_src.utils.request_handler import RequestHandler


class HelpUtilities:

    PATH: Path | None = None
    _DASHBOARD_STATE_FILE = Path(__file__).resolve().parents[3] / "dashboard" / "state.json"
    _RUN_DIRECTORIES: dict[str, Path] = {}

    @classmethod
    def validate_target_is_up(cls, host):
        cmd = "ping -c 1 {}".format(host.target)
        try:
            check_call(cmd.split(), stdout=PIPE, stderr=PIPE)
            return
        except CalledProcessError:
            # Maybe ICMP is blocked. Try web server
            try:
                if host.port == 443 or host.port == 80:
                    url = "{}://{}".format(host.protocol, host.target)
                else:
                    url = "{}://{}:{}".format(host.protocol, host.target, host.port)
                rh = RequestHandler()
                rh.send("GET", url=url, timeout=15)
                return
            except (ConnectionError, RequestHandlerException):
                raise LumenException("Target {} seems to be down (no response to ping or from a web server"
                                       " at port {}).\nRun with --skip-health-check to ignore hosts"
                                       " considered as down.".format(host, host.port))

    @classmethod
    def parse_cookie_arg(cls, cookie_arg):
        try:
            cookies = {}
            for c in cookie_arg.split(','):
                c = c.split(":")
                cookies[c[0]] = c[1]
            return cookies
        except (IndexError, TypeError):
            raise LumenException("Cookie parsing error occurred, probably due to invalid cookie format.\n"
                                   "Cookie format should be comma separated key:value pairs. Use --help "
                                   "for more info.")

    @classmethod
    def validate_wordlist_args(cls, proxy_list, wordlist, subdomain_list):
        if proxy_list and not os.path.isfile(proxy_list):
            raise FileNotFoundError("Not a valid file path, {}".format(proxy_list))

        if wordlist and not os.path.isfile(wordlist):
            raise FileNotFoundError("Not a valid file path, {}".format(wordlist))

        if subdomain_list and not os.path.isfile(subdomain_list):
            raise FileNotFoundError("Not a valid file path, {}".format(subdomain_list))

    @classmethod
    def validate_port_range(cls, port_range):
        """Validate port range for Nmap scan"""
        ports = port_range.split("-")
        if all(ports) and int(ports[-1]) <= 65535 and not len(ports) != 2:
            return True
        raise ScannerException("Invalid port range {}".format(port_range))

    @classmethod
    def validate_proxy_args(cls, *args):
        """No more than 1 of the following can be specified: tor_routing, proxy, proxy_list"""
        supplied_proxies = Counter((not arg for arg in (*args,))).get(False)
        if not supplied_proxies:
            return
        elif supplied_proxies > 1:
            raise LumenException("Must specify only one of the following:\n"
                                   "--tor-routing, --proxy-list, --proxy")

    @classmethod
    def determine_verbosity(cls, quiet, verbosity=0):
        if quiet:
            return "CRITICAL"

        if verbosity is None:
            verbosity = 0

        if verbosity >= 1:
            return "DEBUG"

        return "INFO"

    @classmethod
    def find_nmap_executable(cls):
        return distutils.spawn.find_executable("nmap")

    @classmethod
    def find_openssl_executable(cls):
        return distutils.spawn.find_executable("openssl")

    @classmethod
    def find_mac_gtimeout_executable(cls):
        """To add macOS support, the coreutils package needs to be installed using homebrew"""
        return distutils.spawn.find_executable("gtimeout")

    @classmethod
    def validate_executables(cls):
        if not (cls.find_nmap_executable() and cls.find_openssl_executable()):
            raise LumenException("Could not find Nmap or OpenSSL "
                                   "installed. Please install them and run Lumen again.")
        if system() == "Darwin":
            if not cls.find_mac_gtimeout_executable():
                raise LumenException("To support Lumen with macOS 'gtimeout' must be installed.\n"
                                       "gtimeout can be installed by running 'brew install coreutils'")
        return

    @classmethod
    def create_output_directory(cls, outdir):
        """Tries to create base output directory"""
        base_path = Path(outdir).expanduser()
        base_path.mkdir(parents=True, exist_ok=True)
        cls.PATH = base_path
        cls._RUN_DIRECTORIES = {}
        cls._update_dashboard_state(base_path)

    @classmethod
    def get_output_path(cls, module_path):
        base = cls.PATH or Path.cwd()
        path_obj = Path(module_path)

        if path_obj.is_absolute():
            out_path = path_obj.expanduser()
        else:
            parts = path_obj.parts
            if parts:
                if len(parts) == 1:
                    out_path = (base / path_obj).expanduser()
                else:
                    target = parts[0]
                    run_dir = cls._get_run_directory(target, base)
                    remaining = Path(*parts[1:])
                    out_path = (run_dir / remaining).expanduser()
            else:
                out_path = (base / path_obj).expanduser()

        out_path.parent.mkdir(parents=True, exist_ok=True)
        return str(out_path)

    @classmethod
    def _get_run_directory(cls, target: str, base: Path) -> Path:
        if target not in cls._RUN_DIRECTORIES:
            timestamp = datetime.utcnow().strftime("%Y%m%d-%H%M%S")
            target_dir = base / target
            run_dir = target_dir / timestamp
            suffix = 1
            while run_dir.exists():
                suffix += 1
                run_dir = target_dir / f"{timestamp}-{suffix}"
            run_dir.mkdir(parents=True, exist_ok=True)
            cls._RUN_DIRECTORIES[target] = run_dir
        return cls._RUN_DIRECTORIES[target]

    @classmethod
    def get_scan_directory(cls, target: str) -> str:
        base = cls.PATH or Path.cwd()
        run_dir = cls._get_run_directory(target, base)
        return str(run_dir)

    @classmethod
    def _update_dashboard_state(cls, base_path: Path) -> None:
        state_file = cls._DASHBOARD_STATE_FILE
        try:
            state_file.parent.mkdir(parents=True, exist_ok=True)
            state: dict[str, str]
            if state_file.exists():
                try:
                    state = json.loads(state_file.read_text(encoding="utf-8"))
                except json.JSONDecodeError:
                    state = {}
            else:
                state = {}
            state["output_root"] = str(base_path)
            state_file.write_text(json.dumps(state, indent=2), encoding="utf-8")
        except OSError:
            # Dashboard directory may not be present; ignore silently.
            pass

    @classmethod
    def confirm_traffic_routs_through_tor(cls):
        rh = RequestHandler()
        try:
            page = rh.send("GET", url="https://check.torproject.org")
            if "Congratulations. This browser is configured to use Tor." in page.text:
                return
            elif "Sorry. You are not using Tor" in page.text:
                raise LumenException("Traffic does not seem to be routed through Tor.\nExiting")
        except RequestHandlerException:
            raise LumenException("Tor service seems to be down - not able to connect to 127.0.0.1:9050.\nExiting")

    @classmethod
    def query_dns_dumpster(cls, host):
        # Start DNS Dumpster session for the token
        request_handler = RequestHandler()
        dnsdumpster_session = request_handler.get_new_session()
        url = "https://dnsdumpster.com"
        if host.naked:
            target = host.naked
        else:
            target = host.target
        payload = {
            "targetip": target,
            "csrfmiddlewaretoken": None
        }
        try:
            dnsdumpster_session.get(url, timeout=10)
            jar = dnsdumpster_session.cookies
            for c in jar:
                if not c.__dict__.get("name") == "csrftoken":
                    continue
                payload["csrfmiddlewaretoken"] = c.__dict__.get("value")
                break
            dnsdumpster_session.post(url, data=payload, headers={"Referer": "https://dnsdumpster.com/"})

            return dnsdumpster_session.get("https://dnsdumpster.com/static/map/{}.png".format(target))
        except ConnectionError:
            raise LumenException

    @classmethod
    def extract_hosts_from_cidr(cls):
        pass

    @classmethod
    def extract_hosts_from_range(cls):
        pass
