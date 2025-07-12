
  from ..internal import smb_enum, ldap_enum, snmp_enum, portscan
  from ..utils.logger import log

  def _help():
      print("""\nInternal Commands:
portscan <IP>
smb_enum <IP>
ldap_enum <IP> [<BASE_DN>]
snmp_enum <IP> [community]
help
back\n""")

  def run():
      print("\n[+] Internal Pentest Selected")
      _help()
      while True:
          try:
              cmd = input("internal> ").strip()
          except (EOFError, KeyboardInterrupt):
              print()
              break
          if not cmd:
              continue
          if cmd == "help":
              _help()
              continue
          if cmd == "back":
              break
          parts = cmd.split()
          action = parts[0]
          args = parts[1:]
          if action == "portscan" and len(args) == 1:
              portscan.run(args[0])
          elif action == "smb_enum" and len(args) == 1:
              smb_enum.run(args[0])
          elif action == "ldap_enum":
              if len(args) >= 1:
                  base = args[1] if len(args) > 1 else 'dc=example,dc=local'
                  ldap_enum.run(args[0], base)
          elif action == "snmp_enum":
              if len(args) >= 1:
                  community = args[1] if len(args) > 1 else 'public'
                  snmp_enum.run(args[0], community)
          else:
              log.error("Unknown command or wrong args. Type 'help'.")
