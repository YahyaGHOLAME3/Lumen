"""
Utility functions for scanners.
"""
import re
import logging
import ipaddress
from typing import List, Dict, Any, Optional, Set, Union
import urllib.parse
import aiohttp
import asyncio

logger = logging.getLogger("lumen.scanners.utils")

async def check_robots_txt(base_url: str, user_agent: str) -> bool:
    """
    Check if scanning is allowed by robots.txt.

    Args:
        base_url: Base URL of the site (e.g., https://example.com)
        user_agent: User agent to check permissions for

    Returns:
        True if scanning is allowed, False if disallowed
    """
    try:
        # Parse the base URL and build robots.txt URL
        url_parts = urllib.parse.urlparse(base_url)
        robots_url = f"{url_parts.scheme}://{url_parts.netloc}/robots.txt"

        # Fetch robots.txt with a short timeout
        timeout = aiohttp.ClientTimeout(total=5)
        async with aiohttp.ClientSession(timeout=timeout) as session:
            async with session.get(robots_url) as response:
                if response.status != 200:
                    # No robots.txt or can't access it, assume allowed
                    return True

                robots_txt = await response.text()

                # Simple robots.txt parsing
                user_agent_sections = _parse_robots_txt(robots_txt)

                # Check if our user agent or * is disallowed
                for section_agent, rules in user_agent_sections.items():
                    if section_agent == '*' or section_agent.lower() in user_agent.lower():
                        # Check if any rules disallow scanning
                        for rule_type, pattern in rules:
                            if rule_type == 'disallow' and pattern == '/' or pattern == '*':
                                return False

                # No explicit disallow found
                return True
    except Exception as e:
        logger.debug(f"Error checking robots.txt: {str(e)}")
        # In case of error, assume scanning is allowed
        return True

def _parse_robots_txt(robots_txt: str) -> Dict[str, List[tuple]]:
    """
    Parse robots.txt content into user agent sections and rules.

    Args:
        robots_txt: Content of robots.txt file

    Returns:
        Dictionary mapping user agents to lists of (rule_type, pattern) tuples
    """
    sections: Dict[str, List[tuple]] = {}
    current_agent = None

    for line in robots_txt.splitlines():
        # Remove comments and trim whitespace
        line = line.split('#', 1)[0].strip()
        if not line:
            continue

        # Parse user agent lines
        if line.lower().startswith('user-agent:'):
            agent = line[11:].strip()
            current_agent = agent
            if current_agent not in sections:
                sections[current_agent] = []

        # Parse allow/disallow rules
        elif current_agent is not None:
            if line.lower().startswith('disallow:'):
                pattern = line[9:].strip()
                sections[current_agent].append(('disallow', pattern))
            elif line.lower().startswith('allow:'):
                pattern = line[6:].strip()
                sections[current_agent].append(('allow', pattern))

    return sections

def is_valid_domain(domain: str) -> bool:
    """
    Check if a string is a valid domain name.

    Args:
        domain: Domain name to validate

    Returns:
        True if valid domain, False otherwise
    """
    if not domain:
        return False

    # Simple regex for domain validation
    domain_regex = r'^([a-z0-9]+(-[a-z0-9]+)*\.)+[a-z]{2,}$'
    return bool(re.match(domain_regex, domain, re.IGNORECASE))

def is_valid_ip(ip: str) -> bool:
    """
    Check if a string is a valid IP address.

    Args:
        ip: IP address to validate

    Returns:
        True if valid IP, False otherwise
    """
    try:
        ipaddress.ip_address(ip)
        return True
    except ValueError:
        return False

def load_targets_from_file(file_path: str) -> List[str]:
    """
    Load targets from a file (one target per line).

    Args:
        file_path: Path to target file

    Returns:
        List of targets
    """
    with open(file_path, 'r') as f:
        targets = [line.strip() for line in f.readlines()]

    # Filter out empty lines and comments
    targets = [t for t in targets if t and not t.startswith('#')]

    return targets
