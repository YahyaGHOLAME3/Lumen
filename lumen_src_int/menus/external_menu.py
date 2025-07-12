
  from ..external import port_scan, http_enum, nuclei_scan
  from ..utils.logger import log

  def _help():
      print("""\nExternal Commands:
portscan <IP/CIDR>
http_enum <urls_file>
nuclei_scan <urls_file>
help
back\n""")

  def run():
      print("\n[+] External Pentest Selected")
      _help()
      while True:
          try:
              cmd = input("external> ").strip()
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
              port_scan.run(args[0])
          elif action == "http_enum" and len(args) == 1:
              http_enum.run(args[0])
          elif action == "nuclei_scan" and len(args) == 1:
              nuclei_scan.run(args[0])
          else:
              log.error("Unknown command or wrong args. Type 'help'.")
