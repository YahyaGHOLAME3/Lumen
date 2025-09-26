"""
TLS scanner plugin for safe TLS configuration checks.
"""
import logging
import asyncio
import ssl
from typing import List, Dict, Any, Optional, Tuple

from . import ScannerPlugin
from ..results import ScanResult
from ..subprocess import SafeSubprocessRunner

logger = logging.getLogger("lumen.scanners.tls")

class TLSHandshakePlugin(ScannerPlugin):
    """
    Plugin for checking TLS configuration via handshake (cipher support, versions).
    """

    @property
    def is_active(self) -> bool:
        """This is an active but non-intrusive scanner."""
        return True

    async def scan(self, target: str, config: Any) -> List[ScanResult]:
        """
        Check TLS configuration for a target.

        Args:
            target: Domain name or IP to scan
            config: Scan configuration

        Returns:
            List of scan results for TLS findings
        """
        results = []
        port = config.extra_args.get('tls_port', 443)

        # Try native SSL/TLS check first
        native_results = await self._check_tls_native(target, port)
        results.extend(native_results)

        # If OpenSSL is available, use it for more detailed checks
        if await self._is_openssl_available():
            openssl_results = await self._check_tls_openssl(target, port)
            results.extend(openssl_results)

        return results

    async def _check_tls_native(self, target: str, port: int) -> List[ScanResult]:
        """
        Check TLS using native Python SSL.

        Args:
            target: Target hostname
            port: Target port

        Returns:
            List of scan results
        """
        results = []

        try:
            # Create SSL context for TLS check
            context = ssl.create_default_context()

            # Try to establish SSL connection
            reader, writer = await asyncio.open_connection(
                target, port, ssl=context, server_hostname=target
            )

            # Get SSL information
            ssl_obj = writer.get_extra_info('ssl_object')
            version = ssl_obj.version()
            cipher = ssl_obj.cipher()
            cert = ssl_obj.getpeercert()

            # Close the connection
            writer.close()
            await writer.wait_closed()

            # Add version finding
            results.append(ScanResult(
                target=target,
                check_name="tls_version",
                severity="info",
                finding=f"TLS Version: {version}",
                evidence=f"Connected using {version}",
                scanner=self.name,
                metadata={"tls_version": version}
            ))

            # Add cipher finding
            if cipher:
                cipher_name = cipher[0]
                results.append(ScanResult(
                    target=target,
                    check_name="tls_cipher",
                    severity="info",
                    finding=f"TLS Cipher: {cipher_name}",
                    evidence=f"Connected using cipher {cipher_name}",
                    scanner=self.name,
                    metadata={"cipher": cipher_name}
                ))

            # Check certificate
            if cert:
                # Check expiration
                import datetime
                not_after = datetime.datetime.strptime(cert['notAfter'], "%b %d %H:%M:%S %Y %Z")
                days_remaining = (not_after - datetime.datetime.now()).days

                if days_remaining < 30:
                    severity = "high" if days_remaining < 7 else "medium"
                    results.append(ScanResult(
                        target=target,
                        check_name="tls_cert_expiration",
                        severity=severity,
                        finding=f"Certificate expires in {days_remaining} days",
                        evidence=f"Expiration date: {cert['notAfter']}",
                        scanner=self.name,
                        metadata={"days_remaining": days_remaining}
                    ))

                # Check subject alternative names
                if 'subjectAltName' in cert:
                    sans = [san[1] for san in cert['subjectAltName'] if san[0] == 'DNS']
                    results.append(ScanResult(
                        target=target,
                        check_name="tls_cert_sans",
                        severity="info",
                        finding=f"Certificate covers {len(sans)} domains",
                        evidence=f"SANs: {', '.join(sans[:5])}{'...' if len(sans) > 5 else ''}",
                        scanner=self.name,
                        metadata={"subject_alt_names": sans}
                    ))

        except ssl.SSLError as e:
            results.append(ScanResult(
                target=target,
                check_name="tls_error",
                severity="medium",
                finding=f"SSL/TLS error: {str(e)}",
                evidence=str(e),
                scanner=self.name,
                metadata={"error": str(e)}
            ))
        except Exception as e:
            logger.debug(f"Error checking TLS for {target}:{port}: {str(e)}")

        return results

    async def _is_openssl_available(self) -> bool:
        """Check if OpenSSL is available on the system."""
        try:
            runner = SafeSubprocessRunner()
            returncode = await runner.run_command(["openssl", "version"])
            return returncode == 0
        except Exception:
            return False

    async def _check_tls_openssl(self, target: str, port: int) -> List[ScanResult]:
        """
        Check TLS using OpenSSL for more detailed information.

        Args:
            target: Target hostname
            port: Target port

        Returns:
            List of scan results
        """
        results = []

        try:
            runner = SafeSubprocessRunner()

            # Get certificate information
            cmd = [
                "openssl", "s_client", "-connect", f"{target}:{port}",
                "-servername", target, "-showcerts"
            ]
            _, stdout, _ = await runner.run_command_with_output(cmd, timeout=10)

            if not stdout:
                return results

            # Check for weak protocols
            weak_protocols = []
            for protocol in ["sslv2", "sslv3", "tls1"]:
                cmd = [
                    "openssl", "s_client", "-connect", f"{target}:{port}",
                    f"-{protocol}", "-servername", target
                ]
                returncode, _, _ = await runner.run_command_with_output(cmd, timeout=5)
                if returncode == 0:
                    weak_protocols.append(protocol.upper())

            if weak_protocols:
                results.append(ScanResult(
                    target=target,
                    check_name="tls_weak_protocols",
                    severity="high",
                    finding=f"Weak SSL/TLS protocols supported: {', '.join(weak_protocols)}",
                    evidence=f"Server accepts connections using: {', '.join(weak_protocols)}",
                    scanner=self.name,
                    metadata={"weak_protocols": weak_protocols}
                ))

        except Exception as e:
            logger.debug(f"Error during OpenSSL scan of {target}:{port}: {str(e)}")

        return results
