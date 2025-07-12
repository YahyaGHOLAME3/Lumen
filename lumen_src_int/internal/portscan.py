
from ..utils.command_runner import run_cmd
from ..utils.logger import log

def run(target):
    log.info(f"[NMAP] Comprehensive scan on {target}")
    run_cmd(["nmap", "-sC", "-sV", "-Pn", "-oN", f"nmap_{target}.txt", target])
