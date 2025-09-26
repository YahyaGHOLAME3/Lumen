"""
HTTP scanner plugin for safe web application scanning.
"""
import logging
import asyncio
from typing import List, Dict, Any, Optional, Tuple
import urllib.parse
import re

import aiohttp
from aiohttp.client_exceptions import ClientError

from . import ScannerPlugin
from ..results import ScanResult
from ..utils import check_robots_txt

logger = logging.getLogger("lumen.scanners.http")

class HTTPHeaderScannerPlugin(ScannerPlugin):
    """
    Plugin for scanning HTTP headers for security issues.
    Uses safe HEAD/GET requests with short timeouts.
    """

    @property
    def is_active(self) -> bool:
        """This is an active but non-intrusive scanner."""
        return True

    async def scan(self, target: str, config: Any) -> List[ScanResult]:
        """
        Scan HTTP headers for a target.

        Args:
            target: Domain name or IP to scan
            config: Scan configuration

        Returns:
            List of scan results
        """
        results = []

        # Try both HTTP and HTTPS
        schemes = ["https", "http"]
        headers = {"User-Agent": "Lumen-Scanner/1.0"}

        for scheme in schemes:
            url = f"{scheme}://{target}"

            try:
                # First check if scanning is allowed by robots.txt
                if config.respect_robots_txt:
                    robots_allowed = await check_robots_txt(url, "Lumen-Scanner")
                    if not robots_allowed:
                        logger.info(f"Skipping {url} as scanning is not allowed by robots.txt")
                        results.append(ScanResult(
                            target=target,
                            check_name="robots_txt_check",
                            severity="info",
                            finding="Scanning not allowed by robots.txt",
                            evidence=f"robots.txt at {url}/robots.txt disallows scanning",
                            scanner=self.name
                        ))
                        continue

                # Use a session with a short timeout
                timeout = aiohttp.ClientTimeout(total=10)
                async with aiohttp.ClientSession(timeout=timeout) as session:
                    # First try a HEAD request (safest)
                    async with session.head(url, headers=headers) as response:
                        server_header = response.headers.get("Server")
                        security_headers = await self._check_security_headers(response.headers)

                        # Add server information
                        if server_header:
                            results.append(ScanResult(
                                target=target,
                                check_name="http_server_header",
                                severity="info",
                                finding=f"Server: {server_header}",
                                evidence=f"Header: Server: {server_header}",
                                scanner=self.name,
                                metadata={"url": url, "header": "Server", "value": server_header}
                            ))

                        # Add security header findings
                        for header_result in security_headers:
                            results.append(header_result._replace(target=target))

                    # Perform a safe GET with limited response size
                    async with session.get(url, headers=headers) as response:
                        # Only read first 8KB to avoid large responses
                        body = await response.read()

                        # Check for common issues in response
                        for finding in await self._analyze_response(url, response, body[:8192]):
                            results.append(finding._replace(target=target))

            except ClientError as e:
                logger.debug(f"HTTP error for {url}: {str(e)}")
            except asyncio.TimeoutError:
                logger.debug(f"Timeout connecting to {url}")
            except Exception as e:
                logger.error(f"Error scanning {url}: {str(e)}")

        return results

    async def _check_security_headers(self, headers: Dict) -> List[ScanResult]:
        """
        Check for security-related HTTP headers.

        Args:
            headers: HTTP response headers

        Returns:
            List of scan results for header findings
        """
        results = []

        # Important security headers that should be present
        security_headers = {
            "Strict-Transport-Security": "strict_transport_security",
            "Content-Security-Policy": "content_security_policy",
            "X-Content-Type-Options": "x_content_type_options",
            "X-Frame-Options": "x_frame_options",
            "X-XSS-Protection": "x_xss_protection",
            "Referrer-Policy": "referrer_policy"
        }

        for header, check_name in security_headers.items():
            if header not in headers:
                results.append(ScanResult(
                    target="",  # Will be filled in by caller
                    check_name=f"missing_{check_name}",
                    severity="medium" if header == "Strict-Transport-Security" else "low",
                    finding=f"Missing {header} header",
                    evidence=f"The {header} security header is not set",
                    scanner=self.name,
                    metadata={"missing_header": header}
                ))

        return results

    async def _analyze_response(
        self, url: str, response: aiohttp.ClientResponse, body: bytes
    ) -> List[ScanResult]:
        """
        Analyze HTTP response for common issues.

        Args:
            url: URL that was requested
            response: HTTP response object
            body: Response body (partial)

        Returns:
            List of scan results
        """
        results = []

        # Check for information disclosure in headers
        sensitive_headers = ["X-Powered-By", "X-AspNet-Version", "X-AspNetMvc-Version"]
        for header in sensitive_headers:
            if header in response.headers:
                results.append(ScanResult(
                    target="",  # Will be filled in by caller
                    check_name="information_disclosure",
                    severity="low",
                    finding=f"Information disclosure in {header} header",
                    evidence=f"{header}: {response.headers[header]}",
                    scanner=self.name,
                    metadata={"url": url, "header": header, "value": response.headers[header]}
                ))

        # Basic version detection patterns (safe, non-exploitative)
        try:
            body_text = body.decode('utf-8', errors='ignore')

            # Generic version pattern (non-exploitative)
            version_pattern = r'[vV]ersion[\s:=]+(\d+\.\d+\.\d+)'
            versions = re.findall(version_pattern, body_text)
            if versions:
                results.append(ScanResult(
                    target="",  # Will be filled in by caller
                    check_name="version_disclosure",
                    severity="low",
                    finding=f"Version information disclosed: {versions[0]}",
                    evidence=f"Found version string in response body",
                    scanner=self.name,
                    metadata={"url": url, "version": versions[0]}
                ))
        except Exception as e:
            logger.debug(f"Error analyzing response body: {str(e)}")

        return results
