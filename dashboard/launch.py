"""Command-line entry point for the Lumen dashboard."""

from __future__ import annotations

import sys
from pathlib import Path

try:
    from streamlit.web import bootstrap
except ImportError as exc:  # pragma: no cover
    raise SystemExit(
        "Streamlit is required to launch the dashboard. Install with 'pip install streamlit'."
    ) from exc


def main(argv: list[str] | None = None) -> int:
    """Launch the Streamlit dashboard programmatically."""
    args = argv or sys.argv[1:]

    dashboard_path = Path(__file__).with_name("app.py")
    if not dashboard_path.exists():
        raise SystemExit(f"Cannot locate dashboard app at {dashboard_path}")

    # Streamlit expects to manage sys.argv itself.
    sys.argv = [str(dashboard_path), *args]
    bootstrap.run(str(dashboard_path), "streamlit run", args)
    return 0


if __name__ == "__main__":  # pragma: no cover
    main()
