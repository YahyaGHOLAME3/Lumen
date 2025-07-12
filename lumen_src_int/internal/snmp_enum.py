from ..utils.command_runner import run_cmd
from ..utils.logger import log

def run(target, community='public'):
    """Walk SNMP with common community string"""
    log.info(f"[SNMP] Walking {target} ({community})")
    run_cmd(["snmpwalk", "-v2c", "-c", community, target, "1.3.6.1.2.1.1"])
