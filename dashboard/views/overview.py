"""
SENTINEL — Overview View
Follows EventLog Analyzer reference layout:
- Section A: KPI strip (5 horizontally aligned metrics)
- Section B: Three-column analytics grid:
    * Col 1: Security Event Trend (Line chart) + Events by Channel (Bar chart)
    * Col 2: Threat Detection Breakdown (Streamlit native Progress Table) + Top Users (Horizontal bar chart)
    * Col 3: Recent Events Activity (Streamlit native structured Table)
- Section C: Secondary analytical row (Source distribution, Threat severity distribution, Incident lifecycle status)
- Section D: System & Hardware Overview (CPU, RAM, Disk, Channels, Readiness)
"""

from __future__ import annotations

import html
from collections import Counter
from datetime import datetime, timezone
from typing import Any, Optional

import pandas as pd
import plotly.express as px
import plotly.graph_objects as go
import psutil
import streamlit as st

from monitor.controller import SentinelController
from monitor.event_models import Incident, SecurityEvent
from detection.rules import ALL_RULES
from dashboard.components import (
    card_container,
    clean_html,
    format_timestamp,
    get_severity_badge_html,
    get_source_badge_html,
    render_card_header,
    render_kpi_strip,
    render_monitoring_toolbar,
    render_secondary_nav,
)
from dashboard.theme import (
    apply_plotly_theme,
    get_theme,
)

OVERVIEW_TABS = [
    "Event Overview",
    "Host Overview",
    "Security Overview",
    "Incident Overview",
]

def render_overview(ctrl: SentinelController) -> None:
    """Render the Sentinel Overview Page according to reference layout."""
    active_theme = st.session_state.get("theme", "dark")
    t = get_theme(active_theme)

    # 1. Secondary Navigation Tabs
    active_tab = render_secondary_nav(OVERVIEW_TABS, "overview_subnav_tab")

    # 2. Monitoring Controls Toolbar
    render_monitoring_toolbar(ctrl, "overview")

    # Fetch snapshot and data from controller
    snap = ctrl.get_dashboard_snapshot()
    all_events = ctrl.get_recent_events(limit=500)
    all_incidents = ctrl.get_incidents()

    # ── SECTION A: KPI STRIP (5 Metrics) ──────────────────────────────────────
    total_events = snap.get("total_events_processed", 0)
    total_threats = snap.get("total_detections_generated", 0)
    open_incidents = snap.get("open_incidents", 0)
    critical_incidents = sum(1 for inc in all_incidents if (inc.severity or "").upper() == "CRITICAL")
    engine_status = snap.get("status", "IDLE")

    status_accent = {
        "RUNNING": "green",
        "PAUSED": "amber",
        "ERROR": "red",
    }.get(engine_status, "ice")

    kpis = [
        {
            "title": "Total Events Processed",
            "value": total_events,
            "subtitle": "Ingested across all channels",
            "accent": "blue",
        },
        {
            "title": "Detected Threats",
            "value": total_threats,
            "subtitle": "Security rule triggers",
            "accent": "ice",
        },
        {
            "title": "Open Incidents",
            "value": open_incidents,
            "subtitle": "Active investigation queue",
            "accent": "amber",
        },
        {
            "title": "Critical Incidents",
            "value": critical_incidents,
            "subtitle": "High priority security alerts",
            "accent": "red" if critical_incidents > 0 else "blue",
        },
        {
            "title": "Monitoring Status",
            "value": engine_status,
            "subtitle": f"Source: {snap.get('active_source', 'STATIC_SAMPLE_FILE')}",
            "accent": status_accent,
        },
    ]
    render_kpi_strip(kpis)

    # ── TAB SPECIFIC VIEW ROUTING ─────────────────────────────────────────────
    if active_tab == "Host Overview":
        _render_host_telemetry_expanded(ctrl, snap, t)
        return
    elif active_tab == "Security Overview":
        _render_security_threats_expanded(ctrl, all_events, all_incidents, t)
        return
    elif active_tab == "Incident Overview":
        _render_incidents_summary_expanded(ctrl, all_incidents, t)
        return

    # Default tab: "Event Overview" -> Renders full reference layout
    # ── SECTION B: THREE-COLUMN ANALYTICS GRID ────────────────────────────────
    col1, col2, col3 = st.columns([4.0, 4.0, 4.0], gap="small")

    # ─────────────────────────────────────────────────────────────
    # COLUMN 1: Event Activity & Timeline
    # ─────────────────────────────────────────────────────────────
    with col1:
        # Panel 1: Security Event Trend (Line Chart)
        with card_container():
            render_card_header("Security Event Trend", "TIMELINE")

            if not all_events:
                empty_msg = f'<div style="padding:40px 10px;text-align:center;color:{t["text_secondary"]};font-size:12px;">No event history in buffer.<br>Events will appear chronologically here.</div>'
                st.markdown(empty_msg, unsafe_allow_html=True)
            else:
                time_rows = []
                for ev in all_events:
                    try:
                        ts = pd.to_datetime(ev.timestamp)
                    except Exception:
                        ts = pd.Timestamp.now(tz=timezone.utc)
                    time_rows.append({
                        "timestamp": ts,
                        "is_suspicious": ev.is_suspicious,
                        "severity": (ev.severity or "INFO").upper(),
                    })
                df_time = pd.DataFrame(time_rows).sort_values("timestamp")
                df_time["bin"] = df_time["timestamp"].dt.floor("1min")

                grouped = df_time.groupby(["bin", "is_suspicious"]).size().unstack(fill_value=0)
                if False not in grouped.columns:
                    grouped[False] = 0
                if True not in grouped.columns:
                    grouped[True] = 0

                fig_trend = go.Figure()
                fig_trend.add_trace(go.Scatter(
                    x=grouped.index.astype(str),
                    y=grouped[False],
                    mode="lines+markers",
                    name="Normal Events",
                    line=dict(color=t["success"], width=2),
                    marker=dict(size=4),
                ))
                fig_trend.add_trace(go.Scatter(
                    x=grouped.index.astype(str),
                    y=grouped[True],
                    mode="lines+markers",
                    name="Suspicious Events",
                    line=dict(color=t["critical"], width=2),
                    marker=dict(size=5),
                ))
                apply_plotly_theme(fig_trend, theme_name=active_theme, height=210)
                st.plotly_chart(fig_trend, use_container_width=True, config={"displayModeBar": False})

        # Panel 2: Events by Channel / Subsystem
        with card_container():
            render_card_header("Events by Channel", "CHANNELS")

            chan_counts = Counter(ev.channel for ev in all_events)
            if not chan_counts:
                empty_chan = f'<div style="padding:30px 10px;text-align:center;color:{t["text_secondary"]};font-size:12px;">No channel activity recorded.</div>'
                st.markdown(empty_chan, unsafe_allow_html=True)
            else:
                fig_chan = go.Figure(go.Bar(
                    x=list(chan_counts.keys()),
                    y=list(chan_counts.values()),
                    marker=dict(color=t["primary_blue"]),
                    text=list(chan_counts.values()),
                    textposition="auto",
                    textfont=dict(family="JetBrains Mono", size=10, color="#FFFFFF"),
                ))
                apply_plotly_theme(fig_chan, theme_name=active_theme, height=190)
                fig_chan.update_layout(bargap=0.45)
                st.plotly_chart(fig_chan, use_container_width=True, config={"displayModeBar": False})

    # ─────────────────────────────────────────────────────────────
    # COLUMN 2: Detection Analytics & Top Users
    # ─────────────────────────────────────────────────────────────
    with col2:
        # Panel 1: Threat Detection Breakdown (Streamlit native table)
        with card_container():
            render_card_header("Threat Detection Breakdown", "RULES TRIGGERED")

            detections = ctrl.get_recent_detections(limit=500)
            rule_counts = Counter()
            rule_users = {}
            for ev in detections:
                matched_rule_name = "Threat Detected"
                for alert in (ev.alerts or []):
                    for r in ALL_RULES:
                        if r.name.lower() in alert.lower() or r.rule_id.lower() in alert.lower():
                            matched_rule_name = r.name
                            break
                rule_counts[matched_rule_name] += 1
                if matched_rule_name not in rule_users:
                    rule_users[matched_rule_name] = ev.user or "unknown"

            if not rule_counts:
                empty_threat = f'<div style="padding:40px 10px;text-align:center;color:{t["text_secondary"]};font-size:12px;">No threat detections recorded.<br>System operating normally.</div>'
                st.markdown(empty_threat, unsafe_allow_html=True)
            else:
                total_det = sum(rule_counts.values())
                table_records = []
                for rule_name, count in rule_counts.most_common(5):
                    user_name = rule_users.get(rule_name, "N/A")
                    pct = (count / total_det) if total_det > 0 else 0.0
                    table_records.append({
                        "Rule": rule_name,
                        "Target": user_name,
                        "Count": count,
                        "Ratio": pct,
                    })

                df_threat_table = pd.DataFrame(table_records)
                st.dataframe(
                    df_threat_table,
                    column_config={
                        "Rule": st.column_config.TextColumn("Detection Rule", width="medium"),
                        "Target": st.column_config.TextColumn("Target", width="small"),
                        "Count": st.column_config.NumberColumn("Count", format="%d", width="small"),
                        "Ratio": st.column_config.ProgressColumn("Ratio", format="%.0f%%", min_value=0.0, max_value=1.0, width="small"),
                    },
                    hide_index=True,
                    use_container_width=True,
                    height=200,
                )

        # Panel 2: Top Users (Horizontal Bar Chart)
        with card_container():
            render_card_header("Top Active Users", "USER TELEMETRY")

            user_counts = Counter(ev.user for ev in all_events if ev.user and ev.user not in ("-", "unknown", "UNKNOWN"))
            if not user_counts:
                user_counts = Counter(ev.user for ev in all_events if ev.user)

            if not user_counts:
                empty_users = f'<div style="padding:30px 10px;text-align:center;color:{t["text_secondary"]};font-size:12px;">No user activity recorded.</div>'
                st.markdown(empty_users, unsafe_allow_html=True)
            else:
                top_users = user_counts.most_common(6)
                top_users.reverse()  # Reverse for clean horizontal display
                u_names = [u[0][:16] for u in top_users]
                u_vals = [u[1] for u in top_users]

                fig_users = go.Figure(go.Bar(
                    x=u_vals,
                    y=u_names,
                    orientation="h",
                    marker=dict(color=t["primary_blue"]),
                    text=u_vals,
                    textposition="auto",
                    textfont=dict(family="JetBrains Mono", size=10, color="#FFFFFF"),
                ))
                apply_plotly_theme(fig_users, theme_name=active_theme, height=190)
                st.plotly_chart(fig_users, use_container_width=True, config={"displayModeBar": False})

    # ─────────────────────────────────────────────────────────────
    # COLUMN 3: Recent Security Activity Table
    # ─────────────────────────────────────────────────────────────
    with col3:
        with card_container():
            render_card_header("Recent Security Events", "EVENT LOG")

            recent_events = ctrl.get_recent_events(limit=9)
            if not recent_events:
                empty_recent = f'<div style="padding:60px 10px;text-align:center;color:{t["text_secondary"]};font-size:12px;">No recent security events.<br>Waiting for collection cycle.</div>'
                st.markdown(empty_recent, unsafe_allow_html=True)
            else:
                recent_rows = []
                for ev in recent_events:
                    t_str = format_timestamp(ev.timestamp)[11:19]  # Just HH:MM:SS
                    user_str = (ev.user or "—")[:12]
                    msg_short = (ev.message or f"Event {ev.event_id}")[:30]
                    sev = (ev.severity or "INFO").upper()

                    if ev.is_suspicious or sev in ("CRITICAL", "HIGH"):
                        status_lbl = "🚨 Threat"
                    elif sev == "WARNING":
                        status_lbl = "⚠️ Warning"
                    else:
                        status_lbl = "🟢 Normal"

                    recent_rows.append({
                        "Time": t_str,
                        "User": user_str,
                        "Activity": msg_short,
                        "Status": status_lbl,
                    })

                df_recent = pd.DataFrame(recent_rows)
                st.dataframe(
                    df_recent,
                    column_config={
                        "Time": st.column_config.TextColumn("Time", width="small"),
                        "User": st.column_config.TextColumn("User", width="small"),
                        "Activity": st.column_config.TextColumn("Activity", width="medium"),
                        "Status": st.column_config.TextColumn("Status", width="small"),
                    },
                    hide_index=True,
                    use_container_width=True,
                    height=435,
                )

    # ── SECTION C: SECONDARY ANALYTICAL ROW ───────────────────────────────────
    sec_c_title = (
        f'<div style="font-size:12px;font-weight:700;color:{t["text_secondary"]};letter-spacing:0.06em;text-transform:uppercase;margin:12px 0 8px 2px;">'
        f'Analytics Breakdown'
        f'</div>'
    )
    st.markdown(clean_html(sec_c_title), unsafe_allow_html=True)

    sec_c1, sec_c2, sec_c3 = st.columns([4, 4, 4], gap="small")

    # C1: Event Source Distribution
    with sec_c1:
        with card_container():
            render_card_header("Event Source Distribution", "SOURCES")

            src_counts = Counter(ev.source_type.value if hasattr(ev.source_type, 'value') else str(ev.source_type) for ev in all_events)
            if not src_counts:
                empty_src = f'<div style="padding:24px;text-align:center;color:{t["text_secondary"]};font-size:11.5px;">No source data available.</div>'
                st.markdown(empty_src, unsafe_allow_html=True)
            else:
                fig_src = go.Figure(go.Pie(
                    labels=list(src_counts.keys()),
                    values=list(src_counts.values()),
                    hole=0.6,
                    marker=dict(colors=[t["primary_blue"], t["ice_blue"], t["success"]]),
                ))
                apply_plotly_theme(fig_src, theme_name=active_theme, height=170)
                fig_src.update_layout(margin=dict(l=10, r=10, t=10, b=10))
                st.plotly_chart(fig_src, use_container_width=True, config={"displayModeBar": False})

    # C2: Threat Severity Distribution
    with sec_c2:
        with card_container():
            render_card_header("Threat Severity Distribution", "SEVERITY")

            sev_counts = Counter((ev.severity or "INFO").upper() for ev in all_events)
            sev_order = ["CRITICAL", "HIGH", "WARNING", "INFO"]
            labels = [s for s in sev_order if s in sev_counts]
            values = [sev_counts[s] for s in labels]
            color_map = {
                "CRITICAL": t["critical"],
                "HIGH": "#E67E22",
                "WARNING": t["warning"],
                "INFO": t["text_muted"],
            }

            if not values or sum(values) == 0:
                empty_sev = f'<div style="padding:24px;text-align:center;color:{t["text_secondary"]};font-size:11.5px;">No severity metrics available.</div>'
                st.markdown(empty_sev, unsafe_allow_html=True)
            else:
                fig_sev = go.Figure(go.Pie(
                    labels=labels,
                    values=values,
                    hole=0.6,
                    marker=dict(colors=[color_map.get(s, t["primary_blue"]) for s in labels]),
                ))
                apply_plotly_theme(fig_sev, theme_name=active_theme, height=170)
                fig_sev.update_layout(margin=dict(l=10, r=10, t=10, b=10))
                st.plotly_chart(fig_sev, use_container_width=True, config={"displayModeBar": False})

    # C3: Incident Lifecycle Status
    with sec_c3:
        with card_container():
            render_card_header("Incident Lifecycle Status", "INCIDENTS")

            inc_counts = Counter((inc.status or "OPEN").upper() for inc in all_incidents)
            if not inc_counts:
                empty_inc = f'<div style="padding:24px;text-align:center;color:{t["text_secondary"]};font-size:11.5px;">No active or resolved incidents.</div>'
                st.markdown(empty_inc, unsafe_allow_html=True)
            else:
                status_order = ["OPEN", "INVESTIGATING", "RESOLVED"]
                s_labels = [s for s in status_order if s in inc_counts]
                s_vals = [inc_counts[s] for s in s_labels]
                s_colors = {
                    "OPEN": t["critical"],
                    "INVESTIGATING": t["warning"],
                    "RESOLVED": t["success"],
                }

                fig_inc = go.Figure(go.Bar(
                    x=s_labels,
                    y=s_vals,
                    marker=dict(color=[s_colors.get(s, t["primary_blue"]) for s in s_labels]),
                    text=s_vals,
                    textposition="auto",
                    textfont=dict(family="JetBrains Mono", size=10, color="#FFFFFF"),
                ))
                apply_plotly_theme(fig_inc, theme_name=active_theme, height=170)
                fig_inc.update_layout(bargap=0.55)
                st.plotly_chart(fig_inc, use_container_width=True, config={"displayModeBar": False})

    # ── SECTION D: SYSTEM & HOST OVERVIEW ─────────────────────────────────────
    sec_d_title = (
        f'<div style="font-size:12px;font-weight:700;color:{t["text_secondary"]};letter-spacing:0.06em;text-transform:uppercase;margin:12px 0 8px 2px;">'
        f'Host Telemetry & Monitoring Health'
        f'</div>'
    )
    st.markdown(clean_html(sec_d_title), unsafe_allow_html=True)

    _render_system_health_strip(ctrl, snap, t)


# ══════════════════════════════════════════════════════════════════════════════
# SYSTEM & HEALTH SUB-PANEL
# ══════════════════════════════════════════════════════════════════════════════

def _render_system_health_strip(ctrl: SentinelController, snap: dict[str, Any], t: dict[str, str]) -> None:
    """Render compact system health cards and channel statuses inside proper card containers."""
    sys_col1, sys_col2 = st.columns([6, 6], gap="small")

    # Hardware Sensors (psutil genuine telemetry)
    with sys_col1:
        with card_container():
            render_card_header("Host Hardware Telemetry", "REAL SENSORS")

            try:
                cpu_pct = psutil.cpu_percent(interval=None)
                cpu_cores = psutil.cpu_count(logical=True)
                mem = psutil.virtual_memory()
                mem_pct = mem.percent
                mem_used_gb = mem.used / (1024**3)
                mem_total_gb = mem.total / (1024**3)
                disk = psutil.disk_usage("C:\\")
                disk_pct = disk.percent
                disk_free_gb = disk.free / (1024**3)
            except Exception:
                cpu_pct, cpu_cores = None, None
                mem_pct, mem_used_gb, mem_total_gb = None, None, None
                disk_pct, disk_free_gb = None, None

            m1, m2, m3 = st.columns(3, gap="small")
            with m1:
                val_txt = f"{cpu_pct:.1f}%" if cpu_pct is not None else "N/A"
                sub_txt = f"{cpu_cores} Cores" if cpu_cores else "Sensors Offline"
                st.metric("CPU Load", val_txt, sub_txt)

            with m2:
                val_txt = f"{mem_pct:.1f}%" if mem_pct is not None else "N/A"
                sub_txt = f"{mem_used_gb:.1f}/{mem_total_gb:.1f} GB" if mem_used_gb else "Sensors Offline"
                st.metric("RAM Usage", val_txt, sub_txt)

            with m3:
                val_txt = f"{disk_pct:.1f}%" if disk_pct is not None else "N/A"
                sub_txt = f"{disk_free_gb:.0f} GB Free" if disk_free_gb else "Sensors Offline"
                st.metric("Disk (C:)", val_txt, sub_txt)

    # Windows Channels Diagnostic Status
    with sys_col2:
        with card_container():
            render_card_header("Windows Event Log Channel Status", "PERMISSIONS")

            diag_channels = snap.get("diagnostics", {}).get("channels", {})
            c1, c2, c3 = st.columns(3, gap="small")
            chan_configs = [
                ("System", c1),
                ("Application", c2),
                ("Security", c3),
            ]

            for ch_name, col_dest in chan_configs:
                with col_dest:
                    ch_info = diag_channels.get(ch_name, {})
                    acc = ch_info.get("accessible", False)
                    status_raw = (ch_info.get("status") or ("ONLINE" if acc else "ACCESS_DENIED")).upper()

                    if acc:
                        st.metric(ch_name, "ONLINE", "✓ Accessible")
                    elif "ACCESS_DENIED" in status_raw:
                        st.metric(ch_name, "DENIED", "⚠ Access Restricted", delta_color="inverse")
                    else:
                        st.metric(ch_name, status_raw, "✕ Offline", delta_color="inverse")

            readiness = snap.get("diagnostics", {}).get("readiness", "SAMPLE_ONLY")
            guidance = snap.get("diagnostics", {}).get("guidance", "Read-only non-invasive telemetry operational.")

            readiness_html = (
                f'<div style="margin-top:10px;font-size:11px;color:{t["text_secondary"]};line-height:1.4;border-top:1px solid {t["border_subtle"]};padding-top:8px;">'
                f'<strong style="color:{t["text_primary"]};">Collector Readiness:</strong> {html.escape(readiness)} — {html.escape(guidance)}'
                f'</div>'
            )
            st.markdown(clean_html(readiness_html), unsafe_allow_html=True)


# ══════════════════════════════════════════════════════════════════════════════
# EXPANDED SUBNAV TABS
# ══════════════════════════════════════════════════════════════════════════════

def _render_host_telemetry_expanded(ctrl: SentinelController, snap: dict[str, Any], t: dict[str, str]) -> None:
    """Detailed view for Host Overview tab."""
    with card_container():
        render_card_header("Host Telemetry & System Diagnostics", "HARDWARE & SENSORS")
        _render_system_health_strip(ctrl, snap, t)

def _render_security_threats_expanded(ctrl: SentinelController, all_events: list[SecurityEvent], all_incidents: list[Incident], t: dict[str, str]) -> None:
    """Detailed view for Security Overview tab."""
    detections = ctrl.get_recent_detections(limit=500)
    with card_container():
        render_card_header("Security Overview & Threat Correlation", "INCIDENT CORRELATION")
        m1, m2, m3 = st.columns(3, gap="small")
        with m1:
            st.metric("Total Events Buffer", f"{len(all_events):,}")
        with m2:
            st.metric("Active Detections", f"{len(detections):,}")
        with m3:
            st.metric("Correlated Incidents", f"{len(all_incidents):,}")

def _render_incidents_summary_expanded(ctrl: SentinelController, all_incidents: list[Incident], t: dict[str, str]) -> None:
    """Detailed view for Incident Overview tab."""
    open_c = sum(1 for i in all_incidents if i.status == "OPEN")
    inv_c = sum(1 for i in all_incidents if i.status == "INVESTIGATING")
    res_c = sum(1 for i in all_incidents if i.status == "RESOLVED")

    with card_container():
        render_card_header("Incident Management Summary", "LIFECYCLE STATUS")
        m1, m2, m3 = st.columns(3, gap="small")
        with m1:
            st.metric("Open Incidents", f"{open_c}")
        with m2:
            st.metric("In Triage (Investigating)", f"{inv_c}")
        with m3:
            st.metric("Resolved Incidents", f"{res_c}")
