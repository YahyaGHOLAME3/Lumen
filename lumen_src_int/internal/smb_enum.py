
from ..utils.command_runner import run_cmd
from ..utils.logger import log

def run(target):
    """Enumerate SMB shares using smbclient (no creds)"""
    log.info(f"[SMB] Enumerating shares on {target}")
    run_cmd(["smbclient", "-L", f"//{target}", "-N"])
