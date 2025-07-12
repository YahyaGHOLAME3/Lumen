# Notes
- For now no docker file
- Last release will be pushed to PyPi
- Last release will be also pushed to docker and be used as a container

### Innternal Logic
lumen_src/
│
├── lib/                         # Core logic modules
│   ├── dns_handler.py
│   ├── fuzzer.py
│   ├── host.py
│   ├── owasp.py
│   ├── scanner.py
│   ├── storage_explorer.py
│   ├── sub_domain.py
│   ├── test_nikto.py
│   ├── tls.py
│   ├── waf.py
│   ├── web_app.py
│   ├── internal/
│   │   ├── __init__.py
│   │   ├── smb_enum.py              # SMB shares, users, null sessions
│   │   ├── ldap_enum.py             # LDAP queries, domain info
│   │   ├── rdp_checker.py           # RDP brute/enum
│   │   ├── snmp_enum.py             # Public strings, device info
│   │   ├── ad_bloodhound.py         # BloodHound SharpHound orchestration
│   │   ├── credential_dumper.py     # mimikatz, secretsdump.py interface
│   │   ├── privilege_checker.py     # PEAS wrapper or escal checker
│
├── utils/                       # Utilities and common helpers
│   ├── coloring.py
│   ├── exceptions.py
│   ├── help_utils.py
│   ├── logger.py
│   ├── request_handler.py
│   ├── singleton.py
│   ├── web_server_validator.py
│   ├── command_builder.py         # New: Build & sanitize CLI calls
│   ├── result_parser.py           # New: Parse nmap, nuclei, ffuf etc.
│
├── wordlists/
│   ├── fuzzlist
│   ├── storage_sensitive
│   ├── subdomains
│   ├── smb_userlist.txt           # For null session brute
│   ├── smb_passlist.txt
│   ├── ldap_users.txt
│   ├── web_paths.txt
│
├── tests/                       # Unit tests
│   ├── test_fuzzer.py
│   ├── test_host.py
│   ├── test_subdomain.py
│   ├── test_waf.py
│   ├── test_web_app.py
│   ├── test_internal/
│       ├── test_smb_enum.py
│       ├── test_ldap_enum.py
│       ├── test_snmp_enum.py
│
├── lumen_main.py                # CLI entry point
├── .gitignore
├── Dockerfile
├── .travis.yml
