"""
url_fuzzer.py
~~~~~~~~~~~~~

High‑speed URL / sub‑domain brute‑forcer with:

•  Rich‑formatted console table (only “interesting” hits)
•  CSV audit log (all requests)
•  Quiet / verbose switch
•  Optional SQLite persistence
•  Graceful handling of wildcard responses & connection drops
"""

from __future__ import annotations

import csv
import logging
import sqlite3
import time
import uuid
from concurrent.futures import ThreadPoolExecutor, as_completed
from pathlib import Path
from typing import Iterable, List, Optional, Sequence, Tuple

from rich.console import Console
from rich.logging import RichHandler
from rich.table import Table
from requests.exceptions import ConnectionError as RequestsConnectionError

# ──────────────────────────────────────────────────────────────────────────────
# Internal project helpers – adjust imports if your package layout differs
# ──────────────────────────────────────────────────────────────────────────────
from lumen_src.utils.coloring import COLOR, COLORED_COMBOS
from lumen_src.utils.exceptions import FuzzerException, RequestHandlerException
from lumen_src.utils.help_utils import HelpUtilities
from lumen_src.utils.logger import Logger
from lumen_src.utils.request_handler import RequestHandler

__all__ = ["URLFuzzer"]


# ------------------------------------------------------------------------------
# Utility logging helpers
# ------------------------------------------------------------------------------

def _setup_console_logger(level: str | int = "INFO") -> logging.Logger:
    """Return a Rich‑based console logger with colour support."""
    logging.basicConfig(
        level=level,
        format="%(message)s",
        handlers=[RichHandler(markup=True)],
    )
    return logging.getLogger("url-fuzzer")


# ------------------------------------------------------------------------------
# Main class
# ------------------------------------------------------------------------------

class URLFuzzer:
    """Multithreaded URL / sub‑domain fuzzer with tidy, dual‑channel output."""

    # Response codes we usually care to *see* in console
    INTERESTING_CODES: set[int] = {200, 301, 302, 307, 308, 401, 403, 500}

    def __init__(
        self,
        host,
        *,
        wordlist_path: str | Path,
        num_threads: int = 50,
        ignored_codes: Sequence[int] = (404,),
        follow_redirects: bool = False,
        quiet: bool = True,
        console_level: str | int = "INFO",
        csv_path: str | Path | None = None,
        sqlite_path: str | Path | None = None,
    ):
        # Host attributes expected: target, protocol, port
        self.target = host.target
        self.proto = host.protocol
        self.port = host.port

        self.wordlist_path = Path(wordlist_path)
        self.num_threads = num_threads
        self.follow_redirects = follow_redirects
        self.ignored_codes = set(ignored_codes)
        self.quiet = quiet

        self.request_handler = RequestHandler()
        self.console = _setup_console_logger(console_level)
        self.csv_path = Path(csv_path) if csv_path else Path(f"{self.target}/url_fuzz_{int(time.time())}.csv")
        self.sqlite_path = Path(sqlite_path) if sqlite_path else None

        self.wordset = self._load_wordlist()

        # Runtime accumulators
        self._hits: List[Tuple[int, str, Optional[str]]] = []

    # ────────────────────────────────────────────────────────────────────────
    # Public API
    # ────────────────────────────────────────────────────────────────────────

    async def fuzz(
        self,
        *,
        sub_domain: bool = False,
        log_file_path: Optional[str | Path] = None,
    ) -> None:
        """Run the fuzzing session (awaitable for compatibility with your event loop)."""
        log = self._init_text_logger(log_file_path)

        try:
            self._guard_against_wildcards(sub_domain)
            self._emit_header(sub_domain)

            with ThreadPoolExecutor(self.num_threads) as pool:
                futures = {
                    pool.submit(self._fetch, word, sub_domain): word
                    for word in self.wordset
                }
                for future in as_completed(futures):
                    if exc := future.exception():
                        if isinstance(exc, RequestsConnectionError):
                            continue  # transient drop, ignore
                        raise exc  # unexpected → propagate

            self._render_console_table()
        except FuzzerException as e:
            log.info(f"{COLORED_COMBOS.BAD} {e}")
        except RequestsConnectionError as e:
            if "Remote end closed connection without response" in str(e):
                log.info(f"{COLORED_COMBOS.BAD} {e}. Target is actively closing connections.")

    # ────────────────────────────────────────────────────────────────────────
    # Internal helpers
    # ────────────────────────────────────────────────────────────────────────

    def _load_wordlist(self) -> set[str]:
        try:
            with open(self.wordlist_path, "r", encoding="utf-8") as fp:
                return {line.strip() for line in fp if line.strip()}
        except FileNotFoundError as e:
            raise FuzzerException(f"Cannot open wordlist: {self.wordlist_path}") from e

    # ------------------------------------------------------------------

    def _init_text_logger(self, manual_path: str | Path | None) -> Logger:
        """Create a plain file logger for machine‑readable output."""
        out_path = manual_path or self.csv_path
        out_path = HelpUtilities.get_output_path(str(out_path))
        # Ensure directory exists
        Path(out_path).expanduser().parent.mkdir(parents=True, exist_ok=True)
        # Write CSV header if file is new
        if not Path(out_path).exists():
            with open(out_path, "w", newline="") as f:
                csv.writer(f).writerow(["code", "url", "redirect"])
        return Logger(out_path)

    # ------------------------------------------------------------------

    def _emit_header(self, sub_domain: bool) -> None:
        mode = "sub‑domains" if sub_domain else "URLs"
        self.console.info(f"[bold cyan]{COLORED_COMBOS.INFO} Fuzzing {mode}[/]")
        self.console.info(f"{COLORED_COMBOS.INFO} Wordlist → {self.wordlist_path}")

    # ------------------------------------------------------------------

    def _build_url(self, uri: str, sub_domain: bool) -> str:
        if sub_domain:
            host_part = f"{uri}.{self.target}"
            base = f"{self.proto}://{host_part}"
        else:
            base = f"{self.proto}://{self.target}"
            if self.port not in (80, 443):
                base = f"{base}:{self.port}"
        if sub_domain:
            if self.port not in (80, 443):
                return f"{self.proto}://{uri}.{self.target}:{self.port}"
            return f"{self.proto}://{uri}.{self.target}"
        return f"{base}/{uri}"

    # ------------------------------------------------------------------

    def _fetch(self, uri: str, sub_domain: bool) -> None:
        url = self._build_url(uri, sub_domain)
        try:
            res = self.request_handler.send("HEAD", url=url, allow_redirects=self.follow_redirects)
            self._process_response(res.status_code, url, res.headers.get("Location"))
        except (AttributeError, RequestHandlerException, RequestsConnectionError):
            pass  # silently drop malformed / refused connections

    # ------------------------------------------------------------------

    def _process_response(self, status: int, url: str, redirect: Optional[str]) -> None:
        # Log everything to CSV
        with open(self.csv_path, "a", newline="") as f:
            csv.writer(f).writerow([status, url, redirect or ""])

        if self.sqlite_path:
            self._persist_sqlite(status, url, redirect)

        # Store only interesting hits for console
        if (not self.quiet) or (status not in self.ignored_codes and status in self.INTERESTING_CODES):
            self._hits.append((status, url, redirect))

    # ------------------------------------------------------------------

    def _persist_sqlite(self, status: int, url: str, redirect: Optional[str]) -> None:
        db_path = HelpUtilities.get_output_path(str(self.sqlite_path))
        with sqlite3.connect(db_path) as db:
            db.execute(
                "CREATE TABLE IF NOT EXISTS hits(target, code, url, redirect, ts)",
            )
            db.execute(
                "INSERT INTO hits VALUES(?,?,?,?,datetime('now'))",
                (self.target, status, url, redirect or "",),
            )

    # ────────────────────────────────────────────────────────────────────────
    # Wildcard detection
    # ────────────────────────────────────────────────────────────────────────

    def _guard_against_wildcards(self, sub_domain: bool) -> None:
        codes = self._fake_requests(sub_domain)
        if 200 in codes:
            if sub_domain:
                raise FuzzerException("Wildcard sub‑domain detected – skipping brute‑force.")
            raise FuzzerException("Server returns 200 for every resource – skipping brute‑force.")

    def _fake_requests(self, sub_domain: bool) -> List[int]:
        session = self.request_handler.get_new_session()
        codes: List[int] = []
        for _ in range(2):
            fake = str(uuid.uuid4())
            url = self._build_url(fake, sub_domain)
            try:
                res = self.request_handler.send("GET", url=url, allow_redirects=True)
                codes.append(res.status_code)
                codes.append(
                    session.get(url, allow_redirects=self.follow_redirects).status_code
                )
            except RequestHandlerException:
                if sub_domain:  # NXDOMAIN – no wildcard
                    return [0]
                raise FuzzerException(f"Target {self.target} seems down.")

        return codes

    # ────────────────────────────────────────────────────────────────────────
    # Final pretty output
    # ────────────────────────────────────────────────────────────────────────

    def _render_console_table(self) -> None:
        if not self._hits:
            self.console.info("[grey62]No interesting responses found.[/]")
            return

        tbl = Table(show_header=True, header_style="bold magenta")
        tbl.add_column("Code", width=6)
        tbl.add_column("URL", overflow="fold")
        tbl.add_column("→ Redirect", overflow="fold")

        palette = {2: "green", 3: "blue", 4: "red", 5: "magenta"}
        for code, url, loc in sorted(self._hits, key=lambda t: (t[0], t[1])):
            colour = palette.get(code // 100, "white")
            tbl.add_row(f"[{colour}]{code}[/]", url, loc or "-")

        Console().print(tbl)


# ------------------------------------------------------------------------------
# Example (remove if you integrate in a larger CLI)
# ------------------------------------------------------------------------------

if __name__ == "__main__":
    import asyncio
    from types import SimpleNamespace

    # Minimal dummy host object
    dummy_host = SimpleNamespace(target="example.com", protocol="https", port=443)

    fuzzer = URLFuzzer(
        host=dummy_host,
        wordlist_path="common.txt",
        num_threads=100,
        quiet=False,
        follow_redirects=True,
    )

    asyncio.run(fuzzer.fuzz(sub_domain=False))
