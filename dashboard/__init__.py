"""Helpers for launching the Lumen dashboard."""

from __future__ import annotations

import os
import subprocess
import sys
import time
from pathlib import Path
from typing import Iterable, Optional, Tuple

import requests

_HEALTH_PATH = "_stcore/health"
DEFAULT_PORT = 8501


def _is_port_serving(port: int, timeout: float = 0.5) -> bool:
    url = f"http://127.0.0.1:{port}/{_HEALTH_PATH}"
    try:
        response = requests.get(url, timeout=timeout)
        return response.status_code == 200
    except requests.RequestException:
        return False


def ensure_dashboard_running(
    *,
    port: int = DEFAULT_PORT,
    extra_args: Optional[Iterable[str]] = None,
) -> Tuple[Optional[int], bool]:
    """Start the Streamlit dashboard in the background if it is not already running.

    Returns the port number where the dashboard should be available, or ``None`` if
    launching failed (for example when the ``streamlit`` module is missing).
    """
    if _is_port_serving(port):
        return port, False

    app_path = Path(__file__).with_name("app.py")
    if not app_path.exists():  # pragma: no cover - defensive safeguard
        return None, False

    cmd = [
        sys.executable,
        "-m",
        "streamlit",
        "run",
        str(app_path),
        f"--server.port={port}",
        "--server.headless=true",
        "--server.address=127.0.0.1",
    ]

    if extra_args:
        cmd.extend(extra_args)

    env = os.environ.copy()
    env.setdefault("STREAMLIT_SERVER_RUN_ON_SAVE", "false")

    try:
        subprocess.Popen(
            cmd,
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
            env=env,
            start_new_session=True,
        )
    except (FileNotFoundError, OSError):
        return None

    for _ in range(20):
        if _is_port_serving(port):
            return port, True
        time.sleep(0.5)
    return None, False


__all__ = ["ensure_dashboard_running", "DEFAULT_PORT"]
