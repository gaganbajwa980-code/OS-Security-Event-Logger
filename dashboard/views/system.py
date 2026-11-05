"""
SENTINEL — System & Diagnostics View
Displays host environment specs, pywin32 module compatibility,
Windows Event Log channel accessibility matrix, audit policy reports, and engine configuration.
Uses native Streamlit components to prevent raw HTML leakage.
"""

from __future__ import annotations

import html
import platform
import sys
from typing import Any
import pandas as pd
import psutil
import streamlit as st

from monitor.controller import SentinelController
from dashboard.components import (
    card_container,
    clean_html,
    format_timestamp,
    get_source_badge_html,
    get_status_pill_html,
    render_card_header,
    render_kpi_strip,
    render_monitoring_toolbar,
    render_secondary_nav,
)
from dashboard.theme import get_theme

SYSTEM_TABS = [
    "Environment",
    "Windows Channels",
    "Collector Diagnostics",
    "Configuration",
]

def render_system(ctrl: SentinelController) -> None:
    """Render the System diagnostics and configuration view."""
    active_theme = st.session_state.get("theme", "dark")
    t = get_theme(active_theme)

    active_tab = render_secondary_nav(SYSTEM_TABS, "system_subnav_tab")
    render_monitoring_toolbar(ctrl, "system")

    # Refresh and fetch current diagnostics
    diag = ctrl.get_system_diagnostics()
    snap = ctrl.get_dashboard_snapshot()

    # ── Summary KPI Strip ─────────────────────────────────────────────────────
    channels = diag.get("channels", {})
    acc_count = sum(1 for ch in channels.values() if ch.get("accessible", False))
    total_chans = len(channels) if channels else 3
    pywin32_ok = diag.get("pywin32", {}).get("is_compatible", False)
    readiness = diag.get("readiness", "SAMPLE_ONLY")

    kpis = [
        {
            "title": "Windows OS Subsystem",
            "value": f"{platform.system()} {platform.release()}",
            "subtitle": f"Python {sys.version.split()[0]}",
            "accent": "blue",
        },
        {
            "title": "Accessible Channels",
            "value": f"{acc_count} / {total_chans}",
            "subtitle": "Read-only EventLog APIs",
            "accent": "green" if acc_count > 0 else "amber",
        },
        {
            "title": "pywin32 Integration",
            "value": "COMPATIBLE" if pywin32_ok else "UNAVAILABLE",
            "subtitle": diag.get("pywin32", {}).get("version", "Builtin"),
            "accent": "green" if pywin32_ok else "red",
        },
        {
            "title": "Collector Readiness",
            "value": readiness,
            "subtitle": "Safe non-invasive monitoring",
            "accent": "ice",
        },
    ]
    render_kpi_strip(kpis)

    # ── TAB SPECIFIC CONTENT ──────────────────────────────────────────────────
    if active_tab == "Environment":
        _render_environment_tab(diag, t)
    elif active_tab == "Windows Channels":
        _render_channels_tab(diag, t)
    elif active_tab == "Collector Diagnostics":
        _render_collector_tab(ctrl, snap, diag, t)
    elif active_tab == "Configuration":
        _render_configuration_tab(ctrl, snap)


def _render_environment_tab(diag: dict[str, Any], t: dict[str, str]) -> None:
    """Render OS, Python, hardware telemetry."""
    col1, col2 = st.columns(2, gap="small")

    with col1:
        with card_container():
            render_card_header("Operating System & Runtime Platform", "PLATFORM")

            plat = diag.get("platform", {})
            df_plat = pd.DataFrame([
                {"Parameter": "Operating System", "Value": str(plat.get('os', platform.system()))},
                {"Parameter": "OS Release", "Value": str(plat.get('release', platform.release()))},
                {"Parameter": "Python Version", "Value": str(plat.get('python_version', sys.version.split()[0]))},
                {"Parameter": "Executable Path", "Value": str(plat.get('executable', sys.executable))},
                {"Parameter": "Host Architecture", "Value": str(platform.machine())},
            ])
            st.dataframe(df_plat, hide_index=True, use_container_width=True, height=210)

    with col2:
        with card_container():
            render_card_header("System Resources & Hardware", "HARDWARE")

            try:
                cores_logical = psutil.cpu_count(logical=True)
                cores_physical = psutil.cpu_count(logical=False)
                mem = psutil.virtual_memory()
                disk = psutil.disk_usage("C:\\")

                df_hw = pd.DataFrame([
                    {"Hardware Sensor": "Logical Processors", "Measurement": f"{cores_logical} cores"},
                    {"Hardware Sensor": "Physical CPU Cores", "Measurement": f"{cores_physical} cores"},
                    {"Hardware Sensor": "Total System RAM", "Measurement": f"{mem.total / (1024**3):.1f} GB"},
                    {"Hardware Sensor": "Available RAM", "Measurement": f"{mem.available / (1024**3):.1f} GB ({mem.percent}% used)"},
                    {"Hardware Sensor": "System Disk (C:)", "Measurement": f"{disk.free / (1024**3):.0f} GB Free / {disk.total / (1024**3):.0f} GB Total"},
                ])
                st.dataframe(df_hw, hide_index=True, use_container_width=True, height=210)
            except Exception as exc:
                st.write(f"Hardware sensors unavailable: {exc}")


def _render_channels_tab(diag: dict[str, Any], t: dict[str, str]) -> None:
    """Render Windows Event Log channels and audit policy."""
    with card_container():
        render_card_header("Windows Event Log Channel Accessibility Matrix", "SUBSYSTEM STATUS")

        channels = diag.get("channels", {})
        chan_records = []
        for ch_name, info in channels.items():
            acc = info.get("accessible", False)
            status = info.get("status", "UNKNOWN").upper()
            details = info.get("details", "")

            status_text = "🟢 ONLINE" if acc else ("⚠️ ACCESS DENIED" if "ACCESS_DENIED" in status else "✕ ERROR")
            chan_records.append({
                "Channel": ch_name,
                "Access Status": status_text,
                "Diagnostic Details": details,
            })

        df_chans = pd.DataFrame(chan_records)
        st.dataframe(
            df_chans,
            column_config={
                "Channel": st.column_config.TextColumn("Channel", width="small"),
                "Access Status": st.column_config.TextColumn("Access Status", width="small"),
                "Diagnostic Details": st.column_config.TextColumn("Diagnostic Details", width="large"),
            },
            hide_index=True,
            use_container_width=True,
            height=180,
        )

        audit = diag.get("audit_policy", {})
        audit_box_html = clean_html(f"""
        <div style="margin-top:12px;padding:10px 14px;background:{t['elevated_surface']};border:1px solid {t['border']};border-radius:6px;">
            <div style="font-size:11px;font-weight:700;color:{t['text_primary']};text-transform:uppercase;margin-bottom:4px;">
                Logon Audit Policy Verification
            </div>
            <div style="font-size:12px;color:{t['text_secondary']};">
                <strong>Setting:</strong> <span class="mono" style="color:{t['text_primary']};">{html.escape(str(audit.get('setting', 'Unknown')))}</span> |
                <strong>Status:</strong> <span class="mono" style="color:{t['text_primary']};">{html.escape(str(audit.get('status', 'UNVERIFIED')))}</span><br>
                <span>{html.escape(str(audit.get('details', '')))}</span>
            </div>
        </div>
        """)
        st.markdown(audit_box_html, unsafe_allow_html=True)


def _render_collector_tab(ctrl: SentinelController, snap: dict[str, Any], diag: dict[str, Any], t: dict[str, str]) -> None:
    """Render pywin32 details and collector checkpoint status."""
    with card_container():
        render_card_header("Collector Runtime Diagnostics", "COLLECTOR ENGINE")

        pyw = diag.get("pywin32", {})
        modules = pyw.get("modules_loaded", [])

        diag_info_html = clean_html(f"""
        <div style="font-size:12px;color:{t['text_primary']};line-height:1.8;">
            <strong>pywin32 Available:</strong> <span class="mono" style="color:{t['success'] if pyw.get('pywin32_available') else t['critical']};">{'YES' if pyw.get('pywin32_available') else 'NO'}</span><br>
            <strong>Loaded Modules:</strong> <span class="mono">{html.escape(', '.join(modules)) if modules else 'None'}</span><br>
            <strong>Background Worker Thread:</strong> <span class="mono">{'ACTIVE (Alive)' if ctrl.is_worker_alive() else 'INACTIVE (Stopped)'}</span><br>
            <strong>Last Collection Cycle:</strong> <span class="mono">{format_timestamp(snap.get('last_collection_time'))}</span><br>
            <strong>Last Engine Error:</strong> <span class="mono">{html.escape(str(snap.get('last_error') or 'None'))}</span>
        </div>
        """)
        st.markdown(diag_info_html, unsafe_allow_html=True)

        # Checkpoint information
        checkpoints = getattr(ctrl.collector, "checkpoints", {})
        chk_title = (
            f'<div style="margin-top:14px;font-size:11px;font-weight:700;color:{t["text_secondary"]};text-transform:uppercase;margin-bottom:6px;">'
            f'Active Checkpoints (Highest EventRecordID Processed)'
            f'</div>'
        )
        st.markdown(chk_title, unsafe_allow_html=True)

        if not checkpoints:
            st.markdown(f'<div style="color:{t["text_secondary"]};font-size:12px;">No persistent checkpoints saved yet.</div>', unsafe_allow_html=True)
        else:
            st.json(checkpoints)


def _render_configuration_tab(ctrl: SentinelController, snap: dict[str, Any]) -> None:
    """Render channel selection and detection configuration."""
    with card_container():
        render_card_header("Monitoring Channel Configuration", "SETTINGS")

        current_chans = ctrl.channels
        all_chans = ["System", "Application", "Security"]

        selected_chans = st.multiselect(
            "Monitored Windows Channels",
            options=all_chans,
            default=current_chans,
            key="cfg_chans_sel"
        )

        if st.button("Apply Monitored Channels", key="btn_apply_chans"):
            ctrl.set_channels(selected_chans)
            st.session_state.feedback_msg = f"Monitored channels updated: {', '.join(selected_chans)}."
            st.rerun()
