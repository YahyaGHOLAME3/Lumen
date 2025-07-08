import subprocess, sys

class nikto:
    def run_nikto(target: str, output_file: str = None):
        cmd = ["nikto", "-h", target]
        if output_file:
            cmd += ["-o", output_file, "-Format", "txt"]
        try:
            proc = subprocess.run(cmd, capture_output=True, text=True, check=True)
        except subprocess.CalledProcessError as e:
            print(f"[!] Nikto scan failed: {e}", file=sys.stderr)
            return
        print(proc.stdout)
        return proc.stdout.splitlines()
