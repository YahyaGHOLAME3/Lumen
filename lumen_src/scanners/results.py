"""
Scan result definition and storage handling.
"""
import os
import json
import time
import logging
import base64
from typing import List, Dict, Any, Optional, NamedTuple
from pathlib import Path
from datetime import datetime
import hashlib

logger = logging.getLogger("lumen.scanners.results")

class ScanResult(NamedTuple):
    """A standardized scan result."""
    target: str
    check_name: str
    severity: str  # "info", "low", "medium", "high", "critical"
    finding: str
    evidence: str
    scanner: str
    metadata: Dict[str, Any] = {}
    timestamp: float = time.time()

    def to_dict(self) -> Dict[str, Any]:
        """Convert result to dictionary."""
        return self._asdict()

    def to_json(self) -> str:
        """Convert result to JSON string."""
        return json.dumps(self.to_dict())

class ResultStorage:
    """
    Handles storage and encryption of scan results.
    """

    def __init__(self, output_dir: Optional[str] = None):
        """
        Initialize result storage.

        Args:
            output_dir: Directory to store results in
        """
        self.output_dir = output_dir
        self.encryption_key = os.environ.get("LUMEN_ENCRYPTION_KEY")

    def store_results(self, results: List[ScanResult]) -> str:
        """
        Store scan results to file.

        Args:
            results: List of scan results

        Returns:
            Path to the output file
        """
        if not self.output_dir:
            logger.warning("No output directory specified, results not saved")
            return ""

        # Create output directory if it doesn't exist
        os.makedirs(self.output_dir, exist_ok=True)

        # Group results by target
        results_by_target = {}
        for result in results:
            if result.target not in results_by_target:
                results_by_target[result.target] = []
            results_by_target[result.target].append(result.to_dict())

        # Store results for each target
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        output_files = []

        for target, target_results in results_by_target.items():
            safe_target = self._sanitize_filename(target)
            output_file = os.path.join(
                self.output_dir, f"{safe_target}_{timestamp}.json"
            )

            # Convert results to JSON
            results_json = json.dumps(target_results, indent=2)

            # Encrypt if encryption key is available
            if self.encryption_key:
                encrypted_data = self._encrypt_data(results_json)
                with open(output_file, "wb") as f:
                    f.write(encrypted_data)
            else:
                with open(output_file, "w") as f:
                    f.write(results_json)

            output_files.append(output_file)
            logger.info(f"Stored {len(target_results)} results for {target} to {output_file}")

        # Update scan history
        self._update_scan_history(results)

        return ",".join(output_files)

    def _update_scan_history(self, results: List[ScanResult]) -> None:
        """
        Update scan history log.

        Args:
            results: List of scan results
        """
        if not self.output_dir:
            return

        history_file = os.path.join(self.output_dir, "scan_history.jsonl")

        # Group targets and counts
        targets = set(r.target for r in results)
        severity_counts = {
            "info": 0, "low": 0, "medium": 0, "high": 0, "critical": 0
        }

        for result in results:
            if result.severity in severity_counts:
                severity_counts[result.severity] += 1

        # Create history entry
        history_entry = {
            "timestamp": datetime.now().isoformat(),
            "user": os.environ.get("USER", "unknown"),
            "targets": list(targets),
            "target_count": len(targets),
            "finding_count": len(results),
            "severity_counts": severity_counts,
            # Calculate hash for audit verification
            "result_hash": self._calculate_result_hash(results)
        }

        # Append to history file
        with open(history_file, "a") as f:
            f.write(json.dumps(history_entry) + "\n")

    def _sanitize_filename(self, filename: str) -> str:
        """
        Sanitize a filename to be safe for filesystem.

        Args:
            filename: Original filename

        Returns:
            Sanitized filename
        """
        # Replace characters that might be problematic in filenames
        return "".join(c if c.isalnum() or c in ".-_" else "_" for c in filename)

    def _encrypt_data(self, data: str) -> bytes:
        """
        Encrypt data using the encryption key.

        Args:
            data: Data to encrypt

        Returns:
            Encrypted data
        """
        if not self.encryption_key:
            raise ValueError("Encryption key not available")

        # This is a simple example - in production, use proper crypto libraries
        from cryptography.fernet import Fernet

        # Derive a key from the encryption key
        key = base64.urlsafe_b64encode(
            hashlib.sha256(self.encryption_key.encode()).digest()
        )

        # Create Fernet cipher
        cipher = Fernet(key)

        # Encrypt the data
        return cipher.encrypt(data.encode())

    def _calculate_result_hash(self, results: List[ScanResult]) -> str:
        """Calculate a hash of results for audit verification."""
        # Sort results to ensure consistent hashing
        sorted_results = sorted(
            (r.target, r.check_name, r.severity, r.finding) for r in results
        )
        hash_data = json.dumps(sorted_results).encode()
        return hashlib.sha256(hash_data).hexdigest()
