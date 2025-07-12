
import subprocess
from .logger import log

def run_cmd(cmd, timeout=120):
    """Run a shell command (list) and stream output."""
    log.debug(f"Executing: {' '.join(cmd)}")
    try:
        result = subprocess.run(
            cmd,
            capture_output=True,
            text=True,
            timeout=timeout,
        )
        if result.stdout:
            print(result.stdout.strip())
        if result.stderr:
            log.warning(result.stderr.strip())
        return result.returncode
    except subprocess.TimeoutExpired:
        log.error(f"Command timeout after {timeout}s: {' '.join(cmd)}")
        return -1
