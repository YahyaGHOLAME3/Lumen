"""Helpers for building structured summaries of Lumen scan runs."""

from __future__ import annotations

import json
import re
from datetime import datetime
from pathlib import Path
from typing import Any, Dict, List, Optional

NMAP_PORT_PATTERN = re.compile(r"^(?P<port>\d+)/(?:tcp|udp)\s+open\s+(?P<service>\S+)", re.MULTILINE)
CVE_PATTERN = re.compile(r"CVE-\d{4}-\d{3,7}")


def _read_text(path: Path) -> str:
    if path.exists():
        return path.read_text(encoding="utf-8", errors="ignore")
    return ""


def _count_non_empty_lines(path: Path) -> int:
    if not path.exists():
        return 0
    with path.open("r", encoding="utf-8", errors="ignore") as fh:
        return sum(1 for line in fh if line.strip())


def _parse_ports(text: str) -> List[Dict[str, Any]]:
    ports: List[Dict[str, Any]] = []
    for match in NMAP_PORT_PATTERN.finditer(text):
        data = match.groupdict()
        data["port"] = int(data["port"])
        ports.append(data)
    return ports


def _collect_cves(text: str) -> List[str]:
    return sorted(set(CVE_PATTERN.findall(text)))


def load_metadata(run_dir: Path) -> Dict[str, Any]:
    meta_path = run_dir / "scan_metadata.json"
    if meta_path.exists():
        try:
            data = json.loads(meta_path.read_text(encoding="utf-8"))
            if isinstance(data, dict):
                return data
        except json.JSONDecodeError:
            pass
    return {}


def build_run_summary(run_dir: Path, metadata: Optional[Dict[str, Any]] = None) -> Dict[str, Any]:
    run_dir = run_dir.resolve()
    target = run_dir.parent.name if run_dir.parent else run_dir.name
    run_id = run_dir.name

    metadata = metadata.copy() if metadata else load_metadata(run_dir)
    metadata.setdefault("target", target)
    metadata.setdefault("run_id", run_id)
    metadata.setdefault("run_path", str(run_dir))

    timestamp = metadata.get("timestamp")
    if not timestamp:
        timestamp = datetime.fromtimestamp(run_dir.stat().st_mtime).isoformat(timespec="seconds") + "Z"
        metadata["timestamp"] = timestamp

    nmap_path = run_dir / "nmap_scan.txt"
    vulners_path = run_dir / "nmap_vulners_scan.txt"
    url_fuzz_path = run_dir / "url_fuzz.txt"
    subdomains_path = run_dir / "subdomains.txt"
    nikto_path = run_dir / "nikto_report.html"

    nmap_text = _read_text(nmap_path)
    vulners_text = _read_text(vulners_path)

    ports = _parse_ports(nmap_text)
    cves = _collect_cves(vulners_text)
    url_hits = _count_non_empty_lines(url_fuzz_path)
    subdomain_hits = _count_non_empty_lines(subdomains_path)
    has_nikto = nikto_path.exists()

    skip_nmap = bool(metadata.get("skip_nmap_scan"))
    if skip_nmap:
        nmap_status = "Skipped"
    elif ports:
        nmap_status = "Available"
    elif nmap_path.exists():
        nmap_status = "Completed"
    else:
        nmap_status = "Unavailable"

    overview = {
        "open_ports": len(ports),
        "detected_cves": len(cves),
        "url_hits": url_hits,
        "subdomains": subdomain_hits,
        "nikto_report": has_nikto,
        "nmap_status": nmap_status,
    }

    paths = {
        "run_dir": str(run_dir),
        "nmap_scan": str(nmap_path) if nmap_path.exists() else None,
        "nmap_vulners": str(vulners_path) if vulners_path.exists() else None,
        "url_fuzz": str(url_fuzz_path) if url_fuzz_path.exists() else None,
        "subdomains": str(subdomains_path) if subdomains_path.exists() else None,
        "nikto_report": str(nikto_path) if has_nikto else None,
        "metadata": str(run_dir / "scan_metadata.json") if (run_dir / "scan_metadata.json").exists() else None,
    }

    summary = {
        "target": target,
        "run_id": run_id,
        "display_name": f"{target} ({run_id})",
        "timestamp": timestamp,
        "paths": paths,
        "overview": overview,
        "data": {
            "ports": ports,
            "cves": cves,
            "metadata": metadata,
        },
    }
    return summary


def write_run_summary(run_dir: Path, summary: Dict[str, Any]) -> None:
    out_path = run_dir / "summary.json"
    out_path.write_text(json.dumps(summary, indent=2), encoding="utf-8")


def load_run_summary(run_dir: Path) -> Optional[Dict[str, Any]]:
    summary_path = run_dir / "summary.json"
    if summary_path.exists():
        try:
            return json.loads(summary_path.read_text(encoding="utf-8"))
        except json.JSONDecodeError:
            pass
    return None


def update_manifest(base_dir: Path, summary: Dict[str, Any]) -> None:
    base_dir = base_dir.expanduser()
    manifest_path = base_dir / "manifest.json"
    manifest = {
        "runs": [],
        "domains": [],
        "totals": {
            "open_ports": 0,
            "detected_cves": 0,
            "url_hits": 0,
            "subdomains": 0,
        },
    }

    if manifest_path.exists():
        try:
            data = json.loads(manifest_path.read_text(encoding="utf-8"))
            if isinstance(data, dict):
                manifest.update({k: v for k, v in data.items() if k in manifest})
        except json.JSONDecodeError:
            pass

    run_dir = summary["paths"]["run_dir"]
    manifest["runs"] = [
        entry for entry in manifest.get("runs", [])
        if entry.get("paths", {}).get("run_dir") != run_dir
    ]

    entry = {
        "target": summary["target"],
        "display_name": summary["display_name"],
        "run_id": summary["run_id"],
        "timestamp": summary["timestamp"],
        "overview": summary["overview"],
        "paths": summary["paths"],
    }
    manifest["runs"].append(entry)
    manifest["runs"].sort(key=lambda e: e["timestamp"], reverse=True)

    domains = sorted({run["target"] for run in manifest["runs"]})
    manifest["domains"] = domains

    totals = {"open_ports": 0, "detected_cves": 0, "url_hits": 0, "subdomains": 0}
    for run in manifest["runs"]:
        overview = run.get("overview", {})
        totals["open_ports"] += overview.get("open_ports", 0)
        totals["detected_cves"] += overview.get("detected_cves", 0)
        totals["url_hits"] += overview.get("url_hits", 0)
        totals["subdomains"] += overview.get("subdomains", 0)
    manifest["totals"] = totals

    manifest_path.write_text(json.dumps(manifest, indent=2), encoding="utf-8")


def load_manifest(base_dir: Path) -> Optional[Dict[str, Any]]:
    manifest_path = base_dir.expanduser() / "manifest.json"
    if not manifest_path.exists():
        return None
    try:
        data = json.loads(manifest_path.read_text(encoding="utf-8"))
        if isinstance(data, dict):
            return data
    except json.JSONDecodeError:
        return None
    return None


__all__ = [
    "NMAP_PORT_PATTERN",
    "CVE_PATTERN",
    "build_run_summary",
    "write_run_summary",
    "load_run_summary",
    "update_manifest",
    "load_manifest",
]
