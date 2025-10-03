import re
import subprocess
import sys
import time
from dataclasses import dataclass
from pathlib import Path
from typing import List, Optional

from lumen_src.utils.help_utils import HelpUtilities
from lumen_src.utils.logger import Logger, SystemOutLogger


@dataclass
class NiktoScanResult:
    command: List[str]
    exit_code: int
    stdout: List[str]
    stderr: List[str]
    output_file: Optional[str]
    duration_seconds: float

    @property
    def ok(self) -> bool:
        return self.exit_code == 0

    def merged_output(self) -> List[str]:
        return [*self.stdout, *self.stderr]


class Nikto:
    @staticmethod
    def run_nikto(
        target: str,
        output_file: str | None = None,
        *,
        log_file: str | None = None,
        timeout: int = 900,
    ) -> NiktoScanResult:
        logger = SystemOutLogger()
        safe_target = re.sub(r"[^A-Za-z0-9._-]+", "_", target)

        if log_file is None and HelpUtilities.PATH is not None:
            log_file = HelpUtilities.get_output_path(f"{safe_target}/nikto.txt")

        output_path = Path(output_file).expanduser() if output_file else None
        if output_path:
            output_path.parent.mkdir(parents=True, exist_ok=True)

        cmd = ["nikto", "-h", target, "-ask", "no", "-Display", "V"]
        if output_path:
            cmd += ["-o", str(output_path), "-Format", "html"]

        start = time.time()
        try:
            proc = subprocess.run(
                cmd,
                capture_output=True,
                text=True,
                check=False,
                timeout=timeout,
            )
        except FileNotFoundError as exc:
            message = "Nikto executable not found. Please install Nikto before running this scan."
            logger.error(message)
            raise RuntimeError(message) from exc
        except subprocess.TimeoutExpired as exc:
            stdout_lines = exc.stdout.splitlines() if exc.stdout else []
            stderr_lines = exc.stderr.splitlines() if exc.stderr else []
            result = NiktoScanResult(
                command=cmd,
                exit_code=-1,
                stdout=stdout_lines,
                stderr=stderr_lines,
                output_file=str(output_path) if output_path else None,
                duration_seconds=float(timeout),
            )
            logger.error(f"Nikto scan for {target} timed out after {timeout} seconds")
            Nikto._write_log(log_file, result)
            return result

        duration = time.time() - start
        stdout_lines = proc.stdout.splitlines()
        stderr_lines = proc.stderr.splitlines()

        result = NiktoScanResult(
            command=cmd,
            exit_code=proc.returncode,
            stdout=stdout_lines,
            stderr=stderr_lines,
            output_file=str(output_path) if output_path else None,
            duration_seconds=duration,
        )

        Nikto._write_log(log_file, result)

        summary = f"Nikto scan for {target} completed in {duration:.1f}s (exit {proc.returncode})."
        if proc.returncode == 0:
            logger.info(summary)
        else:
            logger.warning(summary)

        if result.stdout:
            for line in result.stdout:
                logger.debug(line)
        elif output_path:
            logger.info(f"Nikto wrote the detailed report to {output_path}")

        if result.stderr:
            for line in result.stderr:
                logger.warning(line)

        return result

    @staticmethod
    def _write_log(log_file: str | None, result: NiktoScanResult) -> None:
        if not log_file:
            return

        file_logger = Logger(log_file)
        file_logger.info(f"Command: {' '.join(result.command)}")
        file_logger.info(f"Exit code: {result.exit_code}")
        file_logger.info(f"Duration: {result.duration_seconds:.1f}s")

        if result.stdout:
            file_logger.info("--- stdout ---")
            for line in result.stdout:
                file_logger.info(line)

        if result.stderr:
            file_logger.info("--- stderr ---")
            for line in result.stderr:
                file_logger.info(line)

        if result.output_file:
            file_logger.info(f"Nikto generated report: {result.output_file}")


# Backwards compatibility for existing imports expecting lowercase name
nikto = Nikto
