"""
Authorization module for verifying scan targets are explicitly authorized.
"""
import os
import json
import hashlib
import ipaddress
from datetime import datetime
from pathlib import Path
from typing import List, Dict, Any, Optional, Set, Union

class AuthorizationError(Exception):
    """Raised when a target is not authorized for scanning."""
    pass

class AuthorizationVerifier:
    """Verifies that scanning targets are authorized."""

    def __init__(self, auth_file: str = None):
        """
        Initialize the authorization verifier.

        Args:
            auth_file: Path to the authorization file
        """
        self.auth_file = auth_file
        self.authorized_targets: Set[str] = set()
        self.auth_metadata: Dict[str, Any] = {}
        self.expiration: Optional[datetime] = None

        if auth_file and os.path.exists(auth_file):
            self._load_auth_file(auth_file)

    def _load_auth_file(self, auth_file: str) -> None:
        """
        Load and parse the authorization file.

        Args:
            auth_file: Path to the authorization file

        Raises:
            AuthorizationError: If the auth file is invalid or expired
        """
        try:
            with open(auth_file, 'r') as f:
                auth_data = json.load(f)

            # Validate required fields
            required_fields = ['targets', 'authorized_by', 'expires', 'signature']
            for field in required_fields:
                if field not in auth_data:
                    raise AuthorizationError(f"Missing required field '{field}' in authorization file")

            # Check expiration
            try:
                self.expiration = datetime.fromisoformat(auth_data['expires'])
                if datetime.now() > self.expiration:
                    raise AuthorizationError(f"Authorization expired on {self.expiration}")
            except ValueError:
                raise AuthorizationError("Invalid expiration date format in authorization file")

            # Store targets
            if isinstance(auth_data['targets'], list):
                self.authorized_targets = set(auth_data['targets'])
            else:
                raise AuthorizationError("Targets must be a list of domain names or IP addresses")

            # Store metadata
            self.auth_metadata = {
                'authorized_by': auth_data['authorized_by'],
                'expires': auth_data['expires'],
                'signature': auth_data['signature'],
                'scope': auth_data.get('scope', 'safe-active')
            }

        except json.JSONDecodeError:
            raise AuthorizationError("Authorization file is not valid JSON")
        except Exception as e:
            raise AuthorizationError(f"Failed to load authorization file: {str(e)}")

    def verify_target(self, target: str) -> bool:
        """
        Verify if a target is authorized for scanning.

        Args:
            target: Domain name or IP address to verify

        Returns:
            bool: True if authorized, False otherwise
        """
        # No authorization file means no authorization
        if not self.auth_file:
            return False

        # Check if target is directly authorized
        if target in self.authorized_targets:
            return True

        # Check if target is a subdomain of an authorized domain
        for authorized in self.authorized_targets:
            # Check if authorized target is a domain with wildcard
            if authorized.startswith('*.') and target.endswith(authorized[1:]):
                return True
            # Check if target is a subdomain of authorized domain
            if authorized.startswith('.') and target.endswith(authorized):
                return True

        return False

    def verify_targets(self, targets: List[str], raise_on_unauthorized: bool = True) -> List[str]:
        """
        Verify multiple targets against authorization.

        Args:
            targets: List of domain names or IPs to verify
            raise_on_unauthorized: Whether to raise an exception for unauthorized targets

        Returns:
            List of unauthorized targets (empty if all authorized)

        Raises:
            AuthorizationError: If any target is not authorized (when raise_on_unauthorized is True)
        """
        unauthorized = [t for t in targets if not self.verify_target(t)]

        if unauthorized and raise_on_unauthorized:
            raise AuthorizationError(
                f"Unauthorized targets: {', '.join(unauthorized)}. "
                f"Provide a valid authorization file with --auth"
            )

        return unauthorized

    def is_intrusive_authorized(self) -> bool:
        """Check if intrusive scanning is authorized."""
        return self.auth_metadata.get('scope') == 'intrusive'

    def get_target_hash(self) -> str:
        """Generate a hash of authorized targets for audit log."""
        target_str = ','.join(sorted(self.authorized_targets))
        return hashlib.sha256(target_str.encode()).hexdigest()[:16]
