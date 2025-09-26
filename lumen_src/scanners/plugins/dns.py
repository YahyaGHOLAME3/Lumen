"""
DNS scanner plugin for passive DNS enumeration.
"""
import logging
import asyncio
from typing import List, Dict, Any, Optional

import dns.resolver
from dns.resolver import Resolver
from dns.exception import DNSException

from . import ScannerPlugin
from ..results import ScanResult

logger = logging.getLogger("lumen.scanners.dns")

class DNSEnumerationPlugin(ScannerPlugin):
    """
    Plugin for passive DNS record enumeration (A, AAAA, MX, TXT, CNAME, etc.)
    """

    @property
    def is_active(self) -> bool:
        """DNS queries are considered passive."""
        return False

    async def scan(self, target: str, config: Any) -> List[ScanResult]:
        """
        Enumerate DNS records for a target domain.

        Args:
            target: Domain name to scan
            config: Scan configuration

        Returns:
            List of scan results for DNS records
        """
        record_types = ["A", "AAAA", "MX", "TXT", "CNAME", "SOA", "NS"]
        results = []

        # Check if target is a valid domain (not an IP)
        if target.replace(".", "").isdigit() or ":" in target:
            logger.debug(f"Skipping DNS enumeration for IP address: {target}")
            return results

        resolver = dns.resolver.Resolver()

        # Run DNS queries in executor to avoid blocking
        loop = asyncio.get_event_loop()
        for record_type in record_types:
            try:
                records = await loop.run_in_executor(
                    None, self._query_dns, resolver, target, record_type
                )

                if records:
                    for record in records:
                        results.append(ScanResult(
                            target=target,
                            check_name=f"dns_record_{record_type.lower()}",
                            severity="info",
                            finding=f"DNS {record_type} record: {record}",
                            evidence=str(record),
                            scanner=self.name,
                            metadata={
                                "record_type": record_type,
                                "record": str(record),
                            }
                        ))
            except Exception as e:
                logger.debug(f"Error querying {record_type} records for {target}: {str(e)}")

        return results

    def _query_dns(self, resolver: Resolver, domain: str, record_type: str) -> List[str]:
        """
        Query DNS records using the provided resolver.

        Args:
            resolver: DNS resolver
            domain: Domain to query
            record_type: Type of record to query

        Returns:
            List of record strings
        """
        try:
            answers = resolver.resolve(domain, record_type)
            return [str(rdata) for rdata in answers]
        except dns.resolver.NoAnswer:
            return []
        except DNSException:
            return []
