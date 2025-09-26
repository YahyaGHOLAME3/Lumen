"""
Scanner plugin interface and base implementations.
"""
import abc
from typing import List, Dict, Any, Optional
from dataclasses import dataclass

from ..results import ScanResult


class ScannerPlugin(abc.ABC):
    """Base interface for scanner plugins."""

    def __init__(self):
        """Initialize the scanner plugin."""
        pass

    @property
    def name(self) -> str:
        """Get the name of the scanner plugin."""
        return self.__class__.__name__

    @property
    def is_active(self) -> bool:
        """
        Whether this plugin performs active scanning.
        Passive scanners don't send traffic to the target.
        """
        return True

    @property
    def is_intrusive(self) -> bool:
        """
        Whether this plugin performs intrusive scanning.
        Intrusive scanners may affect target performance or trigger alerts.
        """
        return False

    @abc.abstractmethod
    async def scan(self, target: str, config: Any) -> List[ScanResult]:
        """
        Run the scanner against a target.

        Args:
            target: The target to scan (domain name or IP)
            config: Scan configuration

        Returns:
            List of scan results
        """
        pass
