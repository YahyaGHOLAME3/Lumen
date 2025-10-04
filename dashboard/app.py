from __future__ import annotations

import json
from functools import lru_cache
from pathlib import Path
from typing import Dict, Iterable, List, Optional

import pandas as pd
import plotly.express as px
import streamlit as st

from lumen_src.utils.run_summary import (
    build_run_summary,
    load_manifest,
    load_run_summary,
    update_manifest,
    write_run_summary,
)

STATE_FILE = Path(__file__).parent / "state.json"
DEFAULT_OUTPUT_ROOT = "Lumen_scan_results"
MAX_PREVIEW_CHARS = 20000


@lru_cache(maxsize=1)
def _load_state() -> Dict[str, str]:
    if STATE_FILE.exists():
        try:
            with STATE_FILE.open("r", encoding="utf-8") as fh:
                state = json.load(fh)
                if isinstance(state, dict):
                    return state
        except json.JSONDecodeError:
            pass
    return {"output_root": DEFAULT_OUTPUT_ROOT}


def _save_state(output_root: Path) -> None:
    STATE_FILE.parent.mkdir(parents=True, exist_ok=True)
    with STATE_FILE.open("w", encoding="utf-8") as fh:
        json.dump({"output_root": str(output_root)}, fh, indent=2)
    _load_state.cache_clear()


def _list_run_directories(root: Path) -> List[Path]:
    run_dirs: List[Path] = []
    if not root.exists():
        return run_dirs

    for target_dir in sorted((p for p in root.iterdir() if p.is_dir()), key=lambda p: p.name.lower()):
        child_dirs = [d for d in target_dir.iterdir() if d.is_dir()]
        if child_dirs:
            run_dirs.extend(sorted(child_dirs, key=lambda p: p.stat().st_mtime, reverse=True))
        else:
            run_dirs.append(target_dir)
    return run_dirs


def _ensure_manifest(root: Path) -> Dict[str, object]:
    root = root.expanduser()
    if not root.exists():
        return {
            "runs": [],
            "domains": [],
            "totals": {"detected_cves": 0, "open_ports": 0, "url_hits": 0, "subdomains": 0},
        }

    manifest_path = root / "manifest.json"
    try:
        if manifest_path.exists():
            manifest_path.unlink()
    except OSError:
        pass

    for run_dir in _list_run_directories(root):
        summary = load_run_summary(run_dir)
        if summary is None:
            summary = build_run_summary(run_dir)
            write_run_summary(run_dir, summary)
        update_manifest(root, summary)

    manifest = load_manifest(root)
    if manifest is None:
        manifest = {
            "runs": [],
            "domains": [],
            "totals": {"detected_cves": 0, "open_ports": 0, "url_hits": 0, "subdomains": 0},
        }
    return manifest


def _read_text_file(path: Optional[str | Path]) -> str:
    if not path:
        return ""
    path_obj = Path(path)
    if path_obj.exists():
        return path_obj.read_text(encoding="utf-8", errors="ignore")
    return ""


def _load_html(path: Optional[str | Path]) -> str:
    if not path:
        return ""
    path_obj = Path(path)
    if path_obj.exists():
        return path_obj.read_text(encoding="utf-8", errors="ignore")
    return ""


def _text_preview(path: Optional[str | Path], label: str) -> None:
    text = _read_text_file(path)
    if not text.strip():
        st.info(f"No {label} data available.")
        return

    truncated = len(text) > MAX_PREVIEW_CHARS
    st.text(text[:MAX_PREVIEW_CHARS])

    if truncated:
        st.caption("Output truncated for performance. Download the full file below.")

    filename = Path(path).name if path else f"{label}.txt"
    st.download_button(
        f"Download {label}",
        data=text,
        file_name=filename,
        mime="text/plain",
    )


def main() -> None:
    st.set_page_config(page_title="Lumen Dashboard", layout="wide")
    st.title("Lumen Recon Dashboard")
    st.caption("Listening locally on http://localhost:8501")

    state = _load_state()
    default_root = Path(state.get("output_root", DEFAULT_OUTPUT_ROOT)).expanduser()

    st.sidebar.header("Data Source")
    output_root_text = st.sidebar.text_input("Scan output directory", str(default_root))
    output_root = Path(output_root_text).expanduser()

    if st.sidebar.button("Use as default"):
        _save_state(output_root)
        st.sidebar.success(f"Default directory updated to {output_root}")

    manifest = _ensure_manifest(output_root)
    runs = manifest.get("runs", [])

    if not runs:
        st.info("No scans found. Run Lumen first or point to a directory containing scan results.")
        return

    totals = manifest.get("totals", {})
    domains = manifest.get("domains", [])

    overview_records = []
    for run in runs:
        overview = run.get("overview", {})
        overview_records.append({
            "Domain": run.get("target"),
            "Run": run.get("display_name"),
            "Timestamp": run.get("timestamp", "")[:16].replace("T", " "),
            "Open Ports": overview.get("open_ports", 0),
            "Detected CVEs": overview.get("detected_cves", 0),
            "URL Hits": overview.get("url_hits", 0),
            "Subdomains": overview.get("subdomains", 0),
            "Nikto Report": "Yes" if overview.get("nikto_report") else "No",
            "Nmap Status": overview.get("nmap_status", "Unavailable"),
        })

    overview_df = pd.DataFrame(overview_records)

    st.subheader("Scan Overview")
    col1, col2, col3, col4, col5 = st.columns(5)
    col1.metric("Tracked Domains", len(domains))
    col2.metric("Total Open Ports", totals.get("open_ports", 0))
    col3.metric("Total CVEs", totals.get("detected_cves", 0))
    col4.metric("URL Hits", totals.get("url_hits", 0))
    col5.metric("Subdomains", totals.get("subdomains", 0))

    styled = overview_df.style.applymap(
        lambda val: "color: grey" if val == "Skipped"
        else "color: #F0AD4E" if val == "Unavailable"
        else "color: #0275d8" if val == "Yes"
        else "color: #5cb85c" if val in {"Available", "Completed"}
        else ""
        , subset=pd.IndexSlice[:, ["Nmap Status", "Nikto Report"]]
    )
    st.dataframe(styled, use_container_width=True)

    fig_ports = px.bar(
        overview_df,
        x="Run",
        y="Open Ports",
        color="Domain",
        title="Open Ports per Scan",
        text="Open Ports",
    )
    fig_ports.update_layout(margin=dict(l=20, r=20, t=60, b=20))
    st.plotly_chart(fig_ports, use_container_width=True)

    if domains:
        selected_domain = st.sidebar.selectbox("Select domain", domains, index=0)
    else:
        selected_domain = None
    domain_runs = [run for run in runs if run.get("target") == selected_domain] if selected_domain else runs
    if not domain_runs:
        st.warning("No scans recorded for the selected domain yet.")
        return

    selected_display = st.sidebar.selectbox(
        "Select scan",
        [run.get("display_name") for run in domain_runs],
        index=0,
    )
    selected_run = next(run for run in domain_runs if run.get("display_name") == selected_display)
    run_dir = Path(selected_run["paths"]["run_dir"])
    summary = load_run_summary(run_dir)
    if summary is None:
        summary = build_run_summary(run_dir)
        write_run_summary(run_dir, summary)

    st.subheader(f"Details for {selected_run['display_name']}")
    overview = summary.get("overview", selected_run.get("overview", {}))
    detail_col1, detail_col2, detail_col3, detail_col4 = st.columns(4)
    detail_col1.metric("Open Ports", overview.get("open_ports", 0))
    detail_col2.metric("CVEs", overview.get("detected_cves", 0))
    detail_col3.metric("URL Hits", overview.get("url_hits", 0))
    detail_col4.metric("Subdomains", overview.get("subdomains", 0))

    tabs = st.tabs(["Overview", "Nmap", "Vulners", "URL Fuzzing", "Subdomains", "Nikto", "Raw Files"])

    paths = summary.get("paths", {})
    metadata = summary.get("data", {}).get("metadata", {})

    with tabs[0]:
        st.markdown("### Key Files")
        files = [
            ("summary.json", paths.get("run_dir")),
            ("scan_metadata.json", paths.get("metadata")),
            ("nmap_scan.txt", paths.get("nmap_scan")),
            ("nmap_vulners_scan.txt", paths.get("nmap_vulners")),
            ("url_fuzz.txt", paths.get("url_fuzz")),
            ("subdomains.txt", paths.get("subdomains")),
            ("nikto_report.html", paths.get("nikto_report")),
        ]
        for filename, path_str in files:
            if path_str:
                st.write(f"- **{filename}** ✅ ({path_str})")
            else:
                st.write(f"- **{filename}** ❌")

    with tabs[1]:
        st.markdown("### Open Ports")
        ports = summary.get("data", {}).get("ports", [])
        nmap_path = paths.get("nmap_scan")
        if metadata.get("skip_nmap_scan"):
            st.info("Nmap scan was skipped for this run.")
        elif ports:
            ports_df = pd.DataFrame(ports)
            ports_df = ports_df.rename(columns={"port": "Port", "service": "Service"})
            st.table(ports_df)
            st.markdown("### Raw Nmap Output (preview)")
            _text_preview(nmap_path, "nmap_scan.txt")
        elif nmap_path:
            st.warning("Nmap completed but no open ports were detected.")
            st.markdown("### Raw Nmap Output (preview)")
            _text_preview(nmap_path, "nmap_scan.txt")
        else:
            st.info("No Nmap data available for this scan.")

    with tabs[2]:
        st.markdown("### Detected CVEs")
        cves = summary.get("data", {}).get("cves", [])
        if cves:
            st.write(pd.DataFrame(sorted(cves), columns=["CVE"]))
        else:
            st.info("No CVEs detected in the Vulners scan.")
        st.markdown("### Raw Vulners Output (preview)")
        _text_preview(paths.get("nmap_vulners"), "nmap_vulners_scan.txt")

    with tabs[3]:
        st.markdown("### URL Fuzzing Results")
        _text_preview(paths.get("url_fuzz"), "url_fuzz.txt")

    with tabs[4]:
        st.markdown("### Subdomain Enumeration")
        _text_preview(paths.get("subdomains"), "subdomains.txt")

    with tabs[5]:
        st.markdown("### Nikto Report")
        nikto_html = _load_html(paths.get("nikto_report"))
        if nikto_html:
            st.download_button(
                "Download nikto_report.html",
                data=nikto_html,
                file_name=f"{selected_run['target']}_{selected_run['run_id']}_nikto_report.html",
                mime="text/html",
            )
            st.components.v1.html(nikto_html, height=600, scrolling=True)
        else:
            st.info("No Nikto report found for this scan.")

    with tabs[6]:
        st.markdown("### Additional Files")
        run_dir_path = Path(paths.get("run_dir")) if paths.get("run_dir") else run_dir
        for file_path in sorted(run_dir_path.glob("*")):
            if file_path.is_file():
                with st.expander(file_path.name):
                    st.code(file_path.read_text(encoding="utf-8", errors="ignore"))


if __name__ == "__main__":
    main()
