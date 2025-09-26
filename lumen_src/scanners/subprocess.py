"""
Safe subprocess wrapper for executing external commands.
"""
import asyncio
import logging
import re
import shlex
from typing import List, Tuple, Optional, Union, Dict, Any

logger = logging.getLogger("lumen.scanners.subprocess")

class SafeSubprocessRunner:
    """
    Safe wrapper for running external commands with proper sanitization and timeouts.
    """

    def __init__(self):
        """Initialize the subprocess runner."""
        pass

    async def run_command(
        self, cmd: List[str], timeout: int = 60, check: bool = False
    ) -> int:
        """
        Run a command and return exit code.

        Args:
            cmd: Command to run as list of arguments
            timeout: Timeout in seconds
            check: Whether to raise an exception on non-zero exit code

        Returns:
            Command exit code

        Raises:
            ValueError: If command is not allowed
            asyncio.TimeoutError: If command times out
            RuntimeError: If check is True and command returns non-zero
        """
        if not self._validate_command(cmd):
            raise ValueError(f"Command not allowed: {shlex.join(cmd)}")

        logger.debug(f"Running command: {shlex.join(cmd)}")

        try:
            process = await asyncio.create_subprocess_exec(
                *cmd,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE
            )

            try:
                await asyncio.wait_for(process.communicate(), timeout)
            except asyncio.TimeoutError:
                logger.warning(f"Command timed out: {shlex.join(cmd)}")
                process.kill()
                raise

            if check and process.returncode != 0:
                raise RuntimeError(f"Command failed with exit code {process.returncode}: {shlex.join(cmd)}")

            return process.returncode

        except (ValueError, OSError) as e:
            logger.error(f"Error running command: {str(e)}")
            raise

    async def run_command_with_output(
        self, cmd: List[str], timeout: int = 60, check: bool = False
    ) -> Tuple[int, str, str]:
        """
        Run a command and return exit code, stdout and stderr.

        Args:
            cmd: Command to run as list of arguments
            timeout: Timeout in seconds
            check: Whether to raise an exception on non-zero exit code

        Returns:
            Tuple of (exit_code, stdout, stderr)

        Raises:
            ValueError: If command is not allowed
            asyncio.TimeoutError: If command times out
            RuntimeError: If check is True and command returns non-zero
        """
        if not self._validate_command(cmd):
            raise ValueError(f"Command not allowed: {shlex.join(cmd)}")

        logger.debug(f"Running command with output: {shlex.join(cmd)}")

        try:
            process = await asyncio.create_subprocess_exec(
                *cmd,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE
            )

            try:
                stdout, stderr = await asyncio.wait_for(process.communicate(), timeout)
            except asyncio.TimeoutError:
                logger.warning(f"Command timed out: {shlex.join(cmd)}")
                process.kill()
                raise

            stdout_str = stdout.decode('utf-8', errors='replace')
            stderr_str = stderr.decode('utf-8', errors='replace')

            if check and process.returncode != 0:
                raise RuntimeError(
                    f"Command failed with exit code {process.returncode}: {shlex.join(cmd)}\n"
                    f"stdout: {stdout_str}\n"
                    f"stderr: {stderr_str}"
                )

            return process.returncode, stdout_str, stderr_str

        except (ValueError, OSError) as e:
            logger.error(f"Error running command: {str(e)}")
            raise

    def _validate_command(self, cmd: List[str]) -> bool:
        """
        Validate that a command is allowed to run.

        Args:
            cmd: Command to validate

        Returns:
            True if allowed, False otherwise
        """
        if not cmd:
            return False

        # List of allowed commands (security control)
        allowed_commands = {
            "nmap": self._validate_nmap_args,
            "openssl": self._validate_openssl_args,
            "dig": self._validate_dig_args,
            "host": self._validate_host_args,
            "whois": self._validate_whois_args,
            "curl": self._validate_curl_args,
            "timeout": lambda args: True  # Simple wrapper
        }

        # Get base command (handle full paths)
        base_cmd = cmd[0].split("/")[-1]

        # Check if command is allowed
        if base_cmd not in allowed_commands:
            logger.warning(f"Command not in allowed list: {base_cmd}")
            return False

        # If command has a specific validator, use it
        return allowed_commands[base_cmd](cmd[1:])

    def _validate_nmap_args(self, args: List[str]) -> bool:
        """
        Validate nmap arguments for safety.

        Args:
            args: nmap arguments

        Returns:
            True if allowed, False otherwise
        """
        # Disallow these potentially dangerous flags
        dangerous_flags = ["-oN", "-oX", "-oG", "-oS", "-oA", "--script-args", "--script-args-file"]

        for arg in args:
            # Check for dangerous direct arguments
            if arg in dangerous_flags:
                return False

            # Check for dangerous scripts
            if arg.startswith("--script=") or arg == "-sC":
                scripts = arg.split("=")[1] if "=" in arg else "default"
                # Only allow safe built-in scripts
                if scripts not in ["default", "discovery", "version", "safe"]:
                    # Check if using intrusive scripts
                    if any(x in scripts for x in ["exploit", "intrusive", "vuln", "brute"]):
                        return False

        return True

    def _validate_openssl_args(self, args: List[str]) -> bool:
        """Validate openssl arguments for safety."""
        # Only allow specific openssl commands
        allowed_subcmds = ["s_client", "x509", "ciphers", "version"]

        if args and args[0] not in allowed_subcmds:
            return False

        return True

    def _validate_dig_args(self, args: List[str]) -> bool:
        """Validate dig arguments for safety."""
        # Dig is generally safe, but check for specific dangerous options
        dangerous_args = ["-f", "-b"]

        return not any(arg in dangerous_args for arg in args)

    def _validate_host_args(self, args: List[str]) -> bool:
        """Validate host command arguments for safety."""
        # Host command is generally safe
        return True

    def _validate_whois_args(self, args: List[str]) -> bool:
        """Validate whois arguments for safety."""
        # Whois is generally safe
        return True

    def _validate_curl_args(self, args: List[str]) -> bool:
        """Validate curl arguments for safety."""
        # Only allow safe curl operations (GET/HEAD with limited options)
        dangerous_args = ["-X", "--request", "-T", "--upload-file", "-o", "--output", "-d", "--data"]

        for i, arg in enumerate(args):
            if arg in dangerous_args:
                return False

            # Don't allow writing to arbitrary files
            if arg in ["-o", "--output"] and i + 1 < len(args):
                return False

        return True
