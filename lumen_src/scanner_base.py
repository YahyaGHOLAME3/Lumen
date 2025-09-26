# """
# Base class for all scanner plugins in the framework.
# """
# import abc
# import asyncio
# import time
# import random
# from typing import List, Dict, Any, Optional, Set

# from .scan_result import ScanResult
# from .auth_verifier import TargetScope
# from ..utils.logger import Logger


# class ScannerBase(abc.ABC):
#     """Base scanner class that all scanner plugins must extend."""

#     # Default rate limits
#     DEFAULT_CONCURRENCY = 5
#     DEFAULT_RATE_LIMIT = 1  # requests per second per target
#     DEFAULT_MAX_RETRIES = 3

#     def __init__(self,
#                  concurrency: int = DEFAULT_CONCURRENCY,
#                  rate_limit: float = DEFAULT_RATE_LIMIT,
#                  logger: Optional[Logger] = None):
#         """
#         Initialize the base scanner.

#         Args:
#             concurrency: Maximum number of concurrent tasks
#             rate_limit: Maximum requests per second per target
#             logger: Logger instance for output
#         """
#         self.concurrency = concurrency
#         self.rate_limit = rate_limit
#         self.logger = logger or Logger("scanner.log")
#         self._last_request_time: Dict[str, float] = {}
#         self._semaphore = asyncio.Semaphore(concurrency)

#     @abc.abstractmethod
#     async def scan_target(self, target: str, scope: TargetScope) -> List[ScanResult]:
#         """
#         Scan a specific target and return results.

#         Args:
#             target: The domain or IP to scan
#             scope: Authorization scope information

#         Returns:
#             List of ScanResult objects
#         """
#         pass

#     @property
#     @abc.abstractmethod
#     def scanner_name(self) -> str:
#         """Return the name of this scanner."""
#         pass

#     @property
#     @abc.abstractmethod
#     def scanner_description(self) -> str:
#         """Return a description of what this scanner does."""
#         pass

#     @property
#     @abc.abstractmethod
#     def is_passive(self) -> bool:
#         """
#         Indicates if this scanner is passive (True) or active (False).
#         Passive scanners don't make direct contact with the target.
#         """
#         pass

#     @property
#     @abc.abstractmethod
#     def is_safe_active(self) -> bool:
#         """
#         Indicates if this scanner is safe-active.
#         Safe-active scanners make contact but are non-intrusive.
#         """
#         pass

#     async def scan_targets(self, targets: List[str],
#                            scope: TargetScope) -> Dict[str, List[ScanResult]]:
#         """
#         Scan multiple targets with proper rate limiting.

#         Args:
#             targets: List of targets to scan
#             scope: Authorization scope

#         Returns:
#             Dictionary mapping targets to their scan results
#         """
#         results: Dict[str, List[ScanResult]] = {}
#         tasks = []

#         for target in targets:
#             task = asyncio.create_task(self._scan_with_rate_limit(target, scope))
#             tasks.append(task)

#         completed_results = await asyncio.gather(*tasks)

#         for target, target_results in zip(targets, completed_results):
#             results[target] = target_results

#         return results

#     async def _scan_with_rate_limit(self, target: str, scope: TargetScope) -> List[ScanResult]:
#         """Apply rate limiting and retries to target scanning."""
#         async with self._semaphore:
#             # Calculate delay since last request to this target
#             now = time.time()
#             if target in self._last_request_time:
#                 elapsed = now - self._last_request_time[target]
#                 delay_needed = max(0, (1.0 / self.rate_limit) - elapsed)
#                 if delay_needed > 0:
#                     # Add small jitter (0-20%) to prevent thundering herd
#                     jitter = delay_needed * random.uniform(0, 0.2)
#                     await asyncio.sleep(delay_needed + jitter)

#             # Record this request time
#             self._last_request_time[target] = time.time()

#             # Perform the actual scan with retries
#             retry_count = 0
#             while retry_count <= self.DEFAULT_MAX_RETRIES:
#                 try:
#                     results = await self.scan_target(target, scope)
#                     return results
#                 except Exception as e:
#                     retry_count += 1
#                     if retry_count > self.DEFAULT_MAX_RETRIES:
#                         self.logger.error(f"Failed to scan {target} after {retry_count} retries: {str(e)}")
#                         # Return a scan error result
#                         return [ScanResult(
#                             target=target,
#                             scanner=self.scanner_name,
#                             check="connection",
#                             severity="error",
#                             finding=f"Scan failed after {retry_count} retries",
#                             evidence=str(e)
#                         )]
#                     # Exponential backoff with jitter
#                     backoff = (2 ** retry_count) + random.uniform(0, 1)
#                     self.logger.debug(f"Retrying {target} in {backoff:.2f}s (attempt {retry_count})")
#                     await asyncio.sleep(backoff)
