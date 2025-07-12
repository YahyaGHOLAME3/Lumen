
from ..utils.command_runner import run_cmd
from ..utils.logger import log

def run(target, base='dc=example,dc=local'):
    """Basic anonymous LDAP search"""
    log.info(f"[LDAP] Searching LDAP on {target}")
    run_cmd(["ldapsearch", "-x", "-H", f"ldap://{target}", "-b", base])
