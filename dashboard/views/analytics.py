"""
SENTINEL — Analytics View
Dedicated analytical dashboards with event activity trends,
threat detection trends, severity breakdown, and source distributions.
"""

from __future__ import annotations

import html
from collections import Counter
from datetime import datetime, timezone
import pandas as pd
import plotly.express as px
import plotly.graph_objects as go
import streamlit as st

from monitor.controller import SentinelController
from detection.rules import ALL_RULES
from dashboard.components import (
    card_container,
    clean_html,
    render_card_header,
    render_kpi_strip,
    render_monitoring_toolbar,
    render_secondary_nav,
)
from dashboard.theme import (
    apply_plotly_theme,
    get_theme,
)

ANALYTICS_TABS = [
    "Event Trends",
    "Threat Trends",
    "Source Distribution",
]

def render_analytics(ctrl: SentinelController) -> None:
    """Render the Security Analytics interface."""
    active_theme = st.session_state.get("theme", "dark")
    t = get_theme(active_theme)

    active_tab = render_secondary_nav(ANALYTICS_TABS, "analytics_subnav_tab")
    render_monitoring_toolbar(ctrl, "analytics")

    events = ctrl.get_recent_events(limit=1000)
    detections = ctrl.get_recent_detections(limit=1000)
    incidents = ctrl.get_incidents()

    # ── Summary KPI Strip ─────────────────────────────────────────────────────
    total_ev = len(events)
    total_det = len(detections)
    total_inc = len(incidents)
    active_rules_cnt = len(set(
        r.rule_id for ev in detections for alert in (ev.alerts or [])
        for r in ALL_RULES if r.rule_id.lower() in alert.lower() or r.name.lower() in alert.lower()
    ))

    kpis = [
        {
            "title": "Historical Events Analyzed",
            "value": total_ev,
            "subtitle": "Ring buffer sample depth",
            "accent": "blue",
        },
        {
            "title": "Threat Detections",
            "value": total_det,
            "subtitle": "Security rule anomalies",
            "accent": "red" if total_det > 0 else "blue",
        },
        {
            "title": "Active Rule Types Triggered",
            "value": active_rules_cnt,
            "subtitle": f"Out of {len(ALL_RULES)} configured rules",
            "accent": "amber" if active_rules_cnt > 0 else "blue",
        },
        {
            "title": "Total Correlated Incidents",
            "value": total_inc,
            "subtitle": "Across all severity tiers",
            "accent": "ice",
        },
    ]
    render_kpi_strip(kpis)

    if not events and not detections:
        with card_container():
            st.markdown(clean_html(f"""
            <div style="padding:50px;text-align:center;color:{t['text_secondary']};">
                <h4 style="color:{t['text_primary']};margin-bottom:8px;">No Analytics Telemetry Available</h4>
                <p>Start monitoring or execute a manual Poll cycle to populate security trend data.</p>
            </div>
            """), unsafe_allow_html=True)
        return

    # ── TAB SPECIFIC CONTENT ──────────────────────────────────────────────────
    if active_tab == "Event Trends":
        _render_event_trends_tab(events, active_theme, t)
    elif active_tab == "Threat Trends":
        _render_threat_trends_tab(detections, incidents, active_theme, t)
    elif active_tab == "Source Distribution":
        _render_source_distribution_tab(events, active_theme, t)


def _render_event_trends_tab(events: list, active_theme: str, t: dict[str, str]) -> None:
    """Render event activity timeline and channels."""
    with card_container():
        render_card_header("Event Ingestion Activity Over Time", "CHRONOLOGICAL DENSITY")

        if not events:
            st.markdown(f'<div style="padding:40px;text-align:center;color:{t["text_secondary"]};">No events in current buffer.</div>', unsafe_allow_html=True)
            return

        time_rows = []
        for ev in events:
            try:
                ts = pd.to_datetime(ev.timestamp)
            except Exception:
                ts = pd.Timestamp.now(tz=timezone.utc)
            time_rows.append({
                "timestamp": ts,
                "channel": ev.channel,
                "severity": (ev.severity or "INFO").upper(),
                "is_suspicious": ev.is_suspicious,
            })
        df = pd.DataFrame(time_rows).sort_values("timestamp")
        df["minute"] = df["timestamp"].dt.floor("1min")

        grouped = df.groupby(["minute", "is_suspicious"]).size().unstack(fill_value=0)
        if False not in grouped.columns: grouped[False] = 0
        if True not in grouped.columns: grouped[True] = 0

        fig = go.Figure()
        fig.add_trace(go.Bar(
            x=grouped.index.astype(str),
            y=grouped[False],
            name="Benign Events",
            marker_color=t["primary_blue"],
        ))
        fig.add_trace(go.Bar(
            x=grouped.index.astype(str),
            y=grouped[True],
            name="Threats / Anomalies",
            marker_color=t["critical"],
        ))
        fig.update_layout(barmode="stack")
        apply_plotly_theme(fig, theme_name=active_theme, height=280)
        st.plotly_chart(fig, use_container_width=True, config={"displayModeBar": False})


def _render_threat_trends_tab(detections: list, incidents: list, active_theme: str, t: dict[str, str]) -> None:
    """Render detection rules breakdown and incident lifecycle distribution."""
    col_l, col_r = st.columns(2, gap="small")

    with col_l:
        with card_container():
            render_card_header("Threat Detections by Rule", "RULE METRICS")

            rule_counts = Counter()
            for ev in detections:
                matched = False
                for alert in (ev.alerts or []):
                    for r in ALL_RULES:
                        if r.rule_id.lower() in alert.lower() or r.name.lower() in alert.lower():
                            rule_counts[r.name] += 1
                            matched = True
                            break
                if not matched:
                    rule_counts["General Anomaly"] += 1

            if not rule_counts:
                st.markdown(f'<div style="padding:40px;text-align:center;color:{t["text_secondary"]};">No threats detected.</div>', unsafe_allow_html=True)
            else:
                fig = go.Figure(go.Bar(
                    x=list(rule_counts.values()),
                    y=list(rule_counts.keys()),
                    orientation="h",
                    marker=dict(color=t["critical"]),
                    text=list(rule_counts.values()),
                    textposition="auto",
                    textfont=dict(family="JetBrains Mono", size=10, color="#FFFFFF"),
                ))
                apply_plotly_theme(fig, theme_name=active_theme, height=240)
                st.plotly_chart(fig, use_container_width=True, config={"displayModeBar": False})

    with col_r:
        with card_container():
            render_card_header("Incident Status & Resolution Breakdown", "INCIDENTS")

            inc_counts = Counter((i.status or "OPEN").upper() for i in incidents)
            if not inc_counts:
                st.markdown(f'<div style="padding:40px;text-align:center;color:{t["text_secondary"]};">No incidents recorded.</div>', unsafe_allow_html=True)
            else:
                fig = go.Figure(go.Pie(
                    labels=list(inc_counts.keys()),
                    values=list(inc_counts.values()),
                    hole=0.6,
                    marker=dict(colors=[t["critical"], t["warning"], t["success"]]),
                ))
                apply_plotly_theme(fig, theme_name=active_theme, height=240)
                st.plotly_chart(fig, use_container_width=True, config={"displayModeBar": False})


def _render_source_distribution_tab(events: list, active_theme: str, t: dict[str, str]) -> None:
    """Render events by ingestion source and channel."""
    c1, c2 = st.columns(2, gap="small")

    with c1:
        with card_container():
            render_card_header("Events by Ingestion Source Type", "SOURCE")

            src_counts = Counter(
                ev.source_type.value if hasattr(ev.source_type, 'value') else str(ev.source_type)
                for ev in events
            )
            if not src_counts:
                st.markdown(f'<div style="padding:40px;text-align:center;color:{t["text_secondary"]};">No source events recorded.</div>', unsafe_allow_html=True)
            else:
                fig = go.Figure(go.Pie(
                    labels=list(src_counts.keys()),
                    values=list(src_counts.values()),
                    hole=0.6,
                    marker=dict(colors=[t["primary_blue"], t["ice_blue"], t["success"]]),
                ))
                apply_plotly_theme(fig, theme_name=active_theme, height=240)
                st.plotly_chart(fig, use_container_width=True, config={"displayModeBar": False})

    with c2:
        with card_container():
            render_card_header("Events by Windows Channel", "CHANNEL")

            chan_counts = Counter(ev.channel for ev in events)
            if not chan_counts:
                st.markdown(f'<div style="padding:40px;text-align:center;color:{t["text_secondary"]};">No channel events recorded.</div>', unsafe_allow_html=True)
            else:
                fig = go.Figure(go.Bar(
                    x=list(chan_counts.keys()),
                    y=list(chan_counts.values()),
                    marker=dict(color=t["primary_blue"]),
                    text=list(chan_counts.values()),
                    textposition="auto",
                    textfont=dict(family="JetBrains Mono", size=10, color="#FFFFFF"),
                ))
                apply_plotly_theme(fig, theme_name=active_theme, height=240)
                st.plotly_chart(fig, use_container_width=True, config={"displayModeBar": False})
