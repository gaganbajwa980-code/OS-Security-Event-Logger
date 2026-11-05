"""
SENTINEL — Threat Detection View
Displays all 7 security correlation rules, MITRE ATT&CK references,
real detection counts, sliding-window threshold configuration, and severity analysis.
"""

from __future__ import annotations

import html
from collections import Counter
from typing import Optional
import plotly.express as px
import plotly.graph_objects as go
import streamlit as st

from monitor.controller import SentinelController
from detection.rules import ALL_RULES, DetectionRule
from dashboard.components import (
    card_container,
    clean_html,
    format_timestamp,
    get_severity_badge_html,
    render_card_header,
    render_kpi_strip,
    render_monitoring_toolbar,
    render_secondary_nav,
)
from dashboard.theme import (
    apply_plotly_theme,
    get_theme,
)

THREATS_TABS = [
    "Detection Overview",
    "Detection Rules",
    "Severity Analysis",
]

def render_threats(ctrl: SentinelController) -> None:
    """Render the Threat Detection Rules & Analytics page."""
    active_theme = st.session_state.get("theme", "dark")
    t = get_theme(active_theme)

    active_tab = render_secondary_nav(THREATS_TABS, "threats_subnav_tab")
    render_monitoring_toolbar(ctrl, "threats")

    # Fetch detections from controller
    detections = ctrl.get_recent_detections(limit=1000)

    # Calculate actual rule detection counts and last triggered timestamps
    rule_counts: dict[str, int] = Counter()
    rule_last_triggered: dict[str, Optional[str]] = {}

    for ev in detections:
        for alert in (ev.alerts or []):
            for r in ALL_RULES:
                if r.rule_id.lower() in alert.lower() or r.name.lower() in alert.lower():
                    rule_counts[r.rule_id] += 1
                    if r.rule_id not in rule_last_triggered:
                        rule_last_triggered[r.rule_id] = ev.timestamp
                    break

    # ── Summary KPI Strip ─────────────────────────────────────────────────────
    total_detections = len(detections)
    active_rules_triggered = len([rid for rid, cnt in rule_counts.items() if cnt > 0])
    current_threshold = getattr(ctrl.detector, "threshold", 3)
    current_window = getattr(ctrl.detector, "window_seconds", 60)

    kpis = [
        {
            "title": "Total Detections Generated",
            "value": total_detections,
            "subtitle": "Security rule alerts triggered",
            "accent": "red" if total_detections > 0 else "blue",
        },
        {
            "title": "Active Rules Triggered",
            "value": f"{active_rules_triggered} / {len(ALL_RULES)}",
            "subtitle": "Detection rules firing",
            "accent": "amber" if active_rules_triggered > 0 else "blue",
        },
        {
            "title": "Failed-Login Threshold",
            "value": f"{current_threshold} attempts",
            "subtitle": "Sliding correlation limit",
            "accent": "ice",
        },
        {
            "title": "Time Window",
            "value": f"{current_window}s",
            "subtitle": "Sliding evaluation span",
            "accent": "blue",
        },
    ]
    render_kpi_strip(kpis)

    # ── Configuration Controls Panel ──────────────────────────────────────────
    with card_container():
        render_card_header("Detection Engine Parameters", "SLIDING WINDOW CONFIG")

        cfg_c1, cfg_c2, cfg_c3 = st.columns([3, 3, 2], gap="small")
        with cfg_c1:
            new_th = st.slider(
                "Failed Logins Threshold (attempts)",
                min_value=1,
                max_value=15,
                value=current_threshold,
                key="th_slider",
                help="Number of failed logins required within the window to trigger SEC-R01"
            )
        with cfg_c2:
            new_win = st.slider(
                "Sliding Window (seconds)",
                min_value=10,
                max_value=300,
                value=current_window,
                step=10,
                key="win_slider",
                help="Sliding correlation window duration in seconds"
            )
        with cfg_c3:
            st.markdown('<div style="padding-top:24px;"></div>', unsafe_allow_html=True)
            if st.button("⚙ Update Parameters", key="btn_apply_detector_params", use_container_width=True):
                ctrl.set_detection_parameters(threshold=new_th, window_seconds=new_win)
                st.session_state.feedback_msg = f"Detection parameters updated: Threshold={new_th}, Window={new_win}s."
                st.rerun()

    # ── TAB SPECIFIC CONTENT ──────────────────────────────────────────────────
    if active_tab == "Severity Analysis":
        _render_severity_analysis_tab(detections, active_theme, t)
        return

    # Default / "Detection Overview" & "Detection Rules"
    with card_container():
        render_card_header("Configured Security Detection Rules (All 7 Rules)", "MITRE ATT&CK MAPPED")

        for rule in ALL_RULES:
            count = rule_counts.get(rule.rule_id, 0)
            last_seen = rule_last_triggered.get(rule.rule_id)
            last_seen_str = format_timestamp(last_seen) if last_seen else "Never in session"
            sev_badge = get_severity_badge_html(rule.severity)

            mitre_tag = f'<span style="font-family:JetBrains Mono,monospace;font-size:9.5px;font-weight:700;color:{t["primary_blue"]};background:{t["elevated_surface"]};border:1px solid {t["border"]};padding:2px 7px;border-radius:3px;">MITRE {html.escape(rule.mitre_attack_id)}</span>' if rule.mitre_attack_id else '<span style="font-size:10px;color:#94A3B8;">N/A</span>'

            eids_str = ", ".join(str(eid) for eid in rule.target_event_ids) if rule.target_event_ids else "Pattern Matching"

            count_badge_style = f"color:{t['critical']};background:rgba(241,107,117,0.12);border:1px solid rgba(241,107,117,0.35);" if count > 0 else f"color:{t['text_secondary']};background:{t['elevated_surface']};border:1px solid {t['border']};"

            rule_card_html = clean_html(f"""
            <div style="background:{t['elevated_surface']};border:1px solid {t['border']};border-radius:6px;padding:12px 14px;margin-bottom:8px;">
                <div style="display:flex;justify-content:space-between;align-items:center;margin-bottom:4px;">
                    <div style="display:flex;align-items:center;gap:8px;">
                        <span class="mono" style="font-size:12px;font-weight:700;color:{t['primary_blue']};">{html.escape(rule.rule_id)}</span>
                        <span style="font-size:13px;font-weight:700;color:{t['text_primary']};">{html.escape(rule.name)}</span>
                        {sev_badge}
                        {mitre_tag}
                    </div>
                    <div>
                        <span class="mono" style="font-size:11px;font-weight:700;padding:2px 8px;border-radius:4px;{count_badge_style}">
                            {count:,} detections
                        </span>
                    </div>
                </div>
                <div style="font-size:11.5px;color:{t['text_secondary']};margin-bottom:6px;">
                    {html.escape(rule.description)}
                </div>
                <div style="display:flex;justify-content:space-between;align-items:center;font-size:10.5px;color:{t['text_secondary']};border-top:1px solid {t['border_subtle']};padding-top:6px;">
                    <span>Target Event IDs: <strong class="mono" style="color:{t['text_primary']};">{html.escape(eids_str)}</strong></span>
                    <span>Last Triggered: <strong class="mono" style="color:{t['text_primary']};">{html.escape(last_seen_str)}</strong></span>
                </div>
            </div>
            """)
            st.markdown(rule_card_html, unsafe_allow_html=True)


def _render_severity_analysis_tab(detections: list, active_theme: str, t: dict[str, str]) -> None:
    """Detailed severity analysis view."""
    with card_container():
        render_card_header("Threat Severity Distribution & Risk Analysis", "RISK MATRIX")

        if not detections:
            st.markdown(f'<div style="padding:40px;text-align:center;color:{t["text_secondary"]};">No threat detections recorded in the current session.</div>', unsafe_allow_html=True)
            return

        sev_counts = Counter((d.severity or "INFO").upper() for d in detections)
        sev_order = ["CRITICAL", "HIGH", "WARNING", "INFO"]
        labels = [s for s in sev_order if s in sev_counts]
        vals = [sev_counts[s] for s in labels]
        colors = {
            "CRITICAL": t["critical"],
            "HIGH": "#E67E22",
            "WARNING": t["warning"],
            "INFO": t["text_muted"],
        }

        fig = go.Figure(go.Bar(
            x=labels,
            y=vals,
            marker=dict(color=[colors.get(s, t["primary_blue"]) for s in labels]),
            text=vals,
            textposition="auto",
            textfont=dict(family="JetBrains Mono", size=10, color="#FFFFFF"),
        ))
        apply_plotly_theme(fig, theme_name=active_theme, height=240)
        st.plotly_chart(fig, use_container_width=True, config={"displayModeBar": False})
