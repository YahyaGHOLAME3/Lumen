"""
Core scanner orchestration module - manages scanner execution, rate limiting and results.
"""
import os
import time
import asyncio
import logging
import random
from typing import List, Dict, Any, Optional, Set, Callable, Awaitable, Union
from concurrent.futures import ThreadPoolExecutor
from dataclasses import dataclass, field

from .auth import AuthorizationVerifier
from .results import ScanResult, ResultStorage
from .plugins import ScannerPlugin

logger = logging.getLogger("lumen.scanners")

@dataclass
class ScanConfig:
    """Configuration for a scan job."""
    targets: List[str]
    mode: str = "safe-active"  # passive, safe-active, intrusive
    concurrency: int = 5
    rate_limit: float = 1.0  # requests per second per target
    timeout: int = 30  # seconds
    output_dir: Optional[str] = None
    format: str = "text"  # text, json, ndjson
    auth_file: Optional[str] = None
    plugins: List[str] = field(default_factory=list)
    dry_run: bool = False
    respect_robots_txt: bool = True
    extra_args: Dict[str, Any] = field(default_factory=dict)

class ScanOrchestrator:
    """
    Orchestrates the execution of multiple scanners with rate limiting and concurrency control.
    """

    def __init__(self, config: ScanConfig):
        """
        Initialize the scan orchestrator.

        Args:
            config: Scan configuration
        """
        self.config = config
        self.auth = AuthorizationVerifier(config.auth_file)
        self.results = ResultStorage(config.output_dir)
        self.plugins: List[ScannerPlugin] = []
        self._target_timestamps: Dict[str, float] = {}
        self._scan_start_time = time.time()

    async def run(self) -> List[ScanResult]:
        """
        Run the scan with the provided configuration.

        Returns:
            List of scan results

        Raises:
            AuthorizationError: If targets are not authorized
        """
        # Verify authorization for all targets
        self.auth.verify_targets(self.config.targets)

        # Check for intrusive mode authorization
        if self.config.mode == "intrusive" and not self.auth.is_intrusive_authorized():
            raise ValueError("Intrusive scanning mode requested but not authorized")

        # Dry run check - just log what would happen but don't execute
        if self.config.dry_run:
            logger.info(f"DRY RUN: Would scan {len(self.config.targets)} targets "
                       f"in {self.config.mode} mode with {len(self.plugins)} plugins")
            for target in self.config.targets:
                for plugin in self.plugins:
                    logger.info(f"DRY RUN: Would run {plugin.name} against {target}")
            return []

        # Log start of scan
        logger.info(f"Starting scan of {len(self.config.targets)} targets "
                   f"in {self.config.mode} mode with {len(self.plugins)} plugins")

        # Create task queue for all target+plugin combinations
        tasks = []
        for target in self.config.targets:
            for plugin in self.plugins:
                if self._plugin_matches_mode(plugin):
                    tasks.append(self._run_plugin_with_rate_limit(plugin, target))

        # Execute tasks with concurrency limit
        results = []
        if tasks:
            results = await asyncio.gather(*tasks)

        # Flatten results list (since each task returns a list)
        all_results = [r for sublist in results if sublist for r in sublist]

        # Store results if output_dir is specified
        if self.config.output_dir and all_results:
            self.results.store_results(all_results)

        logger.info(f"Scan completed in {time.time() - self._scan_start_time:.2f}s with "
                   f"{len(all_results)} findings")

        return all_results

    def _plugin_matches_mode(self, plugin: ScannerPlugin) -> bool:
        """Check if plugin should run in current mode."""
        if self.config.mode == "passive" and plugin.is_active:
            return False
        if self.config.mode != "intrusive" and plugin.is_intrusive:
            return False
        return True

    async def _run_plugin_with_rate_limit(
        self, plugin: ScannerPlugin, target: str
    ) -> List[ScanResult]:
        """
        Run a plugin against a target with rate limiting.

        Args:
            plugin: Scanner plugin to run
            target: Target to scan

        Returns:
            List of scan results
        """
        # Apply rate limiting
        await self._wait_for_rate_limit(target)

        try:
            # Run the plugin
            logger.debug(f"Running {plugin.name} against {target}")
            results = await plugin.scan(target, self.config)
            return results
        except Exception as e:
            logger.error(f"Error running {plugin.name} against {target}: {str(e)}")
            return []

    async def _wait_for_rate_limit(self, target: str) -> None:
        """
        Wait to respect rate limits for the target.

        Args:
            target: The target being scanned
        """
        now = time.time()

        # Get the last request time for this target
        last_request = self._target_timestamps.get(target, 0)

        # Calculate time to wait (with small random jitter for backoff)
        wait_time = max(0, (1.0 / self.config.rate_limit) - (now - last_request))
        wait_time += random.uniform(0, 0.1)  # Add small jitter (0-100ms)

        if wait_time > 0:
            await asyncio.sleep(wait_time)

        # Update the timestamp after waiting
        self._target_timestamps[target] = time.time()

    def register_plugin(self, plugin: ScannerPlugin) -> None:
        """Register a scanner plugin."""
        self.plugins.append(plugin)
