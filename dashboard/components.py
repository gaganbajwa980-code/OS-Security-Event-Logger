"""
SENTINEL — Shared UI Components & Layout Helpers
Includes top navigation bar with Theme Switcher, secondary context tabs,
monitoring toolbar, KPI cards, formatting helpers, and export utilities.
"""

from __future__ import annotations

import csv
import html
import io
import json
from datetime import datetime
from typing import Any, Callable, Optional, Sequence
import streamlit as st

from monitor.controller import SentinelController
from monitor.event_models import Incident, SecurityEvent, SourceType
from dashboard.theme import get_theme

# ══════════════════════════════════════════════════════════════════════════════
# FORMATTING & BADGE HELPERS
# ══════════════════════════════════════════════════════════════════════════════

def clean_html(text: str) -> str:
    """Strip all newlines and indentation so HTML is never interpreted as a Markdown indented code block."""
    return " ".join(line.strip() for line in text.strip().splitlines() if line.strip())

def format_timestamp(ts: Optional[str]) -> str:
    """Format ISO timestamp to readable date-time string."""
    if not ts:
        return "—"
    try:
        dt = datetime.fromisoformat(str(ts).replace("Z", "+00:00"))
        return dt.strftime("%Y-%m-%d %H:%M:%S")
    except Exception:
        return str(ts)[:19] if len(str(ts)) >= 19 else str(ts)

def get_severity_badge_html(severity: str) -> str:
    """Return HTML for severity classification badge."""
    sev = (severity or "INFO").upper()
    css = {
        "CRITICAL": "sev-critical",
        "HIGH": "sev-high",
        "WARNING": "sev-warning",
    }.get(sev, "sev-info")
    return f'<span class="sev-badge {css}">{html.escape(sev)}</span>'

def get_source_badge_html(source_type: str) -> str:
    """Return HTML badge for event ingestion source."""
    src = (source_type or "").upper()
    label, css = {
        "LIVE_WINDOWS": ("LIVE WINDOWS", "src-live"),
        "SIMULATED_REPLAY": ("SIMULATED REPLAY", "src-sim"),
        "STATIC_SAMPLE_FILE": ("STATIC SAMPLE FILE", "src-sample"),
    }.get(src, (src, "src-sample"))
    return f'<span class="src-badge {css}">{html.escape(label)}</span>'

def get_status_pill_html(status: str) -> str:
    """Return HTML pill badge for engine monitoring status."""
    st_val = (status or "IDLE").upper()
    dot, label, css = {
        "RUNNING": ("●", "RUNNING", "pill-running"),
        "PAUSED":  ("◌", "PAUSED",  "pill-paused"),
        "IDLE":    ("○", "IDLE",    "pill-idle"),
        "STOPPED": ("○", "STOPPED", "pill-idle"),
        "ERROR":   ("✕", "ERROR",   "pill-error"),
    }.get(st_val, ("○", st_val, "pill-idle"))
    return f'<span class="status-pill {css}">{dot} {html.escape(label)}</span>'

# ══════════════════════════════════════════════════════════════════════════════
# CARD CONTAINER & HEADER HELPERS
# ══════════════════════════════════════════════════════════════════════════════

def card_container():
    """Return a styled Streamlit container that properly encapsulates card content."""
    return st.container(border=True)

def render_card_header(title: str, badge: Optional[str] = None) -> None:
    """Render a standard card header with title and optional badge without indentation."""
    badge_html = f'<span class="sentinel-card-badge">{html.escape(badge)}</span>' if badge else ""
    header_html = (
        f'<div class="sentinel-card-header">'
        f'<span class="sentinel-card-title">{html.escape(title)}</span>'
        f'{badge_html}'
        f'</div>'
    )
    st.markdown(header_html, unsafe_allow_html=True)

# ══════════════════════════════════════════════════════════════════════════════
# DATA EXPORT HELPERS
# ══════════════════════════════════════════════════════════════════════════════

def events_to_csv(events: Sequence[SecurityEvent]) -> str:
    """Convert a sequence of SecurityEvents to CSV text."""
    buf = io.StringIO()
    writer = csv.writer(buf)
    writer.writerow([
        "timestamp", "event_id", "channel", "provider", "severity",
        "user", "ip_address", "computer", "source_type", "message", "is_suspicious"
    ])
    for ev in events:
        writer.writerow([
            ev.timestamp, ev.event_id or "", ev.channel, ev.provider,
            ev.severity, ev.user, ev.ip_address, ev.computer,
            ev.source_type.value if hasattr(ev.source_type, 'value') else str(ev.source_type),
            ev.message, ev.is_suspicious
        ])
    return buf.getvalue()

def events_to_json(events: Sequence[SecurityEvent]) -> str:
    """Convert a sequence of SecurityEvents to formatted JSON text."""
    return json.dumps([ev.to_dict() for ev in events], indent=2, default=str)

def incidents_to_csv(incidents: Sequence[Incident]) -> str:
    """Convert a sequence of Incidents to CSV text."""
    buf = io.StringIO()
    writer = csv.writer(buf)
    writer.writerow([
        "incident_id", "title", "rule_id", "severity", "status",
        "user", "source_ip", "timestamp_first", "timestamp_last",
        "event_count", "mitre_attack_id", "description"
    ])
    for inc in incidents:
        writer.writerow([
            inc.incident_id, inc.title, inc.rule_id, inc.severity, inc.status,
            inc.user, inc.source_ip, inc.timestamp_first, inc.timestamp_last,
            inc.event_count, inc.mitre_attack_id or "", inc.description
        ])
    return buf.getvalue()

def incidents_to_json(incidents: Sequence[Incident]) -> str:
    """Convert a sequence of Incidents to formatted JSON text."""
    return json.dumps([inc.to_dict() for inc in incidents], indent=2, default=str)

# ══════════════════════════════════════════════════════════════════════════════
# MAIN TOP HORIZONTAL NAVIGATION BAR WITH THEME TOGGLE
# ══════════════════════════════════════════════════════════════════════════════

MAIN_PAGES = [
    "Overview",
    "Events",
    "Threats",
    "Investigations",
    "Analytics",
    "System",
]

def render_top_navbar(ctrl: SentinelController) -> None:
    """
    Renders top horizontal navigation bar:
    Left: SENTINEL Vector Shield Logo and subtitle (0 leading spaces, perfectly rendered)
    Center: Navigation links with proportional widths (no truncation)
    Right: Status pill, Active Incidents badge, Theme toggle, Refresh button
    """
    current_page = st.session_state.get("page", "Overview")
    current_theme = st.session_state.get("theme", "dark")
    t = get_theme(current_theme)
    is_dark = (current_theme == "dark")

    snap = ctrl.get_dashboard_snapshot()
    status = snap.get("status", "IDLE")
    open_inc = snap.get("open_incidents", 0)

    with st.container(key="top_navbar"):
        col_brand, col_nav, col_controls = st.columns([2.0, 6.2, 3.8], gap="small")

        # 1. Left Brand Block (Transparent Vector Shield + Theme-Aware Wordmark)
        with col_brand:
            shield_svg = (
                f'<svg width="24" height="28" viewBox="0 0 24 28" fill="none" xmlns="http://www.w3.org/2000/svg" style="flex-shrink:0;">'
                f'<defs><linearGradient id="sentinelShieldGrad" x1="0%" y1="0%" x2="100%" y2="100%">'
                f'<stop offset="0%" stop-color="#1689D5"/>'
                f'<stop offset="100%" stop-color="#7AAEFF"/>'
                f'</linearGradient></defs>'
                f'<path d="M12 1.5 L22 5.5 V13 C22 20.5 12 26.5 12 26.5 C12 26.5 2 20.5 2 13 V5.5 L12 1.5 Z" fill="url(#sentinelShieldGrad)" stroke="{t["primary_blue"]}" stroke-width="0.8"/>'
                f'<path d="M12 5.5 L18 8.2 V12.5 C18 17 12 21.5 12 21.5 C12 21.5 6 17 6 12.5 V8.2 L12 5.5 Z" fill="none" stroke="rgba(255,255,255,0.8)" stroke-width="1.2" stroke-linejoin="round"/>'
                f'<circle cx="12" cy="12.5" r="2.2" fill="#FFFFFF"/>'
                f'</svg>'
            )
            brand_html = (
                f'<div style="display:flex;align-items:center;gap:10px;padding-top:4px;">'
                f'{shield_svg}'
                f'<div>'
                f'<div style="font-size:15px;font-weight:700;letter-spacing:0.12em;color:{t["brand_wordmark"]};text-transform:uppercase;line-height:1;font-family:Inter,sans-serif;">SENTINEL</div>'
                f'<div style="font-size:8.5px;font-weight:600;letter-spacing:0.15em;color:{t["brand_subtitle"]};text-transform:uppercase;margin-top:3px;font-family:Inter,sans-serif;">OS SECURITY MONITORING</div>'
                f'</div>'
                f'</div>'
            )
            st.markdown(clean_html(brand_html), unsafe_allow_html=True)

        # 2. Center Navigation Links (Proportional widths so Investigations never truncates)
        with col_nav:
            nav_cols = st.columns([1.0, 0.9, 0.95, 1.45, 1.05, 0.85], gap="small")
            for i, page_name in enumerate(MAIN_PAGES):
                with nav_cols[i]:
                    is_active = (current_page == page_name)
                    btn_type = "primary" if is_active else "secondary"
                    if st.button(page_name, key=f"top_nav_{page_name}", type=btn_type, use_container_width=True):
                        if st.session_state.get("page") != page_name:
                            st.session_state.page = page_name
                            st.rerun()

        # 3. Right Status & Actions: Status Pill + Incidents + Theme Switcher + Refresh
        with col_controls:
            c_status, c_inc, c_theme, c_refresh = st.columns([1.0, 1.1, 1.4, 0.35], gap="small")

            with c_status:
                status_html = get_status_pill_html(status)
                st.markdown(f'<div style="padding-top:4px;text-align:right;">{status_html}</div>', unsafe_allow_html=True)

            with c_inc:
                if open_inc > 0:
                    if is_dark:
                        inc_html = f'<span style="background:rgba(255,105,120,0.18);color:#FFA5AC;border:1px solid rgba(255,105,120,0.35);font-size:10px;font-weight:700;padding:2px 7px;border-radius:4px;font-family:JetBrains Mono,monospace;">⚠ {open_inc} Incidents</span>'
                    else:
                        inc_html = f'<span style="background:rgba(214,69,80,0.12);color:#D64550;border:1px solid rgba(214,69,80,0.35);font-size:10px;font-weight:700;padding:2px 7px;border-radius:4px;font-family:JetBrains Mono,monospace;">⚠ {open_inc} Incidents</span>'
                else:
                    if is_dark:
                        inc_html = f'<span style="background:rgba(53,201,138,0.18);color:#85E5B5;border:1px solid rgba(53,201,138,0.35);font-size:10px;font-weight:700;padding:2px 7px;border-radius:4px;font-family:JetBrains Mono,monospace;">✓ No Threats</span>'
                    else:
                        inc_html = f'<span style="background:rgba(22,134,93,0.12);color:#16865D;border:1px solid rgba(22,134,93,0.35);font-size:10px;font-weight:700;padding:2px 7px;border-radius:4px;font-family:JetBrains Mono,monospace;">✓ No Threats</span>'
                st.markdown(f'<div style="padding-top:4px;">{inc_html}</div>', unsafe_allow_html=True)

            with c_theme:
                # Theme Switcher button: Sun icon + Light Mode / Moon icon + Dark Mode
                if current_theme == "dark":
                    if st.button("☀️ Light Mode", key="btn_theme_toggle", help="Switch to Light Mode", use_container_width=True):
                        st.session_state.theme = "light"
                        st.rerun()
                else:
                    if st.button("🌙 Dark Mode", key="btn_theme_toggle", help="Switch to Dark Mode", use_container_width=True):
                        st.session_state.theme = "dark"
                        st.rerun()

            with c_refresh:
                if st.button("↻", key="nav_quick_refresh", help="Refresh snapshot", use_container_width=True):
                    ctrl.refresh_diagnostics()
                    st.session_state.feedback_msg = "Snapshot refreshed."
                    st.rerun()

# ══════════════════════════════════════════════════════════════════════════════
# SECONDARY CONTEXT SUB-NAVIGATION BAR
# ══════════════════════════════════════════════════════════════════════════════

def render_secondary_nav(tabs: list[str], current_tab_key: str) -> str:
    """
    Renders context-specific sub-navigation tabs below the main navigation.
    Returns the selected active tab name.
    """
    active_tab = st.session_state.get(current_tab_key, tabs[0] if tabs else "")
    if active_tab not in tabs and tabs:
        active_tab = tabs[0]
        st.session_state[current_tab_key] = active_tab

    with st.container(key="secondary_nav"):
        tab_cols = st.columns(len(tabs) + 1, gap="small")
        for i, tab_name in enumerate(tabs):
            with tab_cols[i]:
                is_active = (active_tab == tab_name)
                btn_type = "primary" if is_active else "secondary"
                if st.button(tab_name, key=f"subnav_{current_tab_key}_{tab_name}", type=btn_type, use_container_width=True):
                    st.session_state[current_tab_key] = tab_name
                    st.rerun()

    return active_tab

# ══════════════════════════════════════════════════════════════════════════════
# COMPACT MONITORING TOOLBAR
# ══════════════════════════════════════════════════════════════════════════════

def render_monitoring_toolbar(ctrl: SentinelController, page_key: str) -> None:
    """
    Renders compact toolbar with:
    - Event Source selector (LIVE WINDOWS, SIMULATED REPLAY, STATIC SAMPLE FILE)
    - Monitoring controls (Start, Pause, Resume, Stop, Poll Now, Refresh)
    - Last collection timestamp display
    """
    current_theme = st.session_state.get("theme", "dark")
    t = get_theme(current_theme)

    snap = ctrl.get_dashboard_snapshot()
    cur_status = snap.get("status", "IDLE")
    active_src = snap.get("active_source", "STATIC_SAMPLE_FILE")
    last_col = snap.get("last_collection_time")
    hint_time = format_timestamp(last_col) if last_col else "No events collected"

    # Display feedback message if action triggered
    feedback = st.session_state.get("feedback_msg")
    if feedback:
        st.markdown(f'<div class="sentinel-feedback"><span>ℹ</span> {html.escape(feedback)}</div>', unsafe_allow_html=True)
        st.session_state.feedback_msg = None

    with st.container(key="monitoring_toolbar"):
        c_src, c_btns, c_meta = st.columns([3.0, 5.5, 3.5], gap="small")

        with c_src:
            source_options = ["STATIC_SAMPLE_FILE", "SIMULATED_REPLAY", "LIVE_WINDOWS"]
            curr_idx = source_options.index(active_src) if active_src in source_options else 0
            is_locked = cur_status in ("RUNNING", "PAUSED")

            if is_locked:
                badge_html = get_source_badge_html(active_src)
                src_html = (
                    f'<div style="display:flex;align-items:center;gap:8px;padding-top:4px;">'
                    f'<span style="font-size:11px;font-weight:600;color:{t["text_secondary"]};">SOURCE:</span>'
                    f'{badge_html}'
                    f'</div>'
                )
                st.markdown(src_html, unsafe_allow_html=True)
            else:
                selected_source = st.selectbox(
                    "Ingestion Source",
                    options=source_options,
                    index=curr_idx,
                    key=f"sel_src_{page_key}",
                    label_visibility="collapsed"
                )
                if selected_source != active_src:
                    ctrl.set_source_type(selected_source)
                    st.session_state.feedback_msg = f"Source switched to {selected_source}."
                    st.rerun()

        with c_btns:
            b1, b2, b3, b4, b5, b6 = st.columns(6, gap="small")

            # 1. START
            with b1:
                can_start = cur_status in ("IDLE", "STOPPED", "ERROR")
                if st.button("▶ Start", key=f"btn_start_{page_key}", disabled=not can_start, use_container_width=True, help="Start background monitoring worker"):
                    ctrl.start_monitoring()
                    if ctrl.is_worker_alive():
                        st.session_state.feedback_msg = f"Monitoring active in {ctrl.source_type.value} mode."
                    st.rerun()

            # 2. PAUSE
            with b2:
                can_pause = (cur_status == "RUNNING")
                if st.button("⏸ Pause", key=f"btn_pause_{page_key}", disabled=not can_pause, use_container_width=True, help="Temporarily pause collection"):
                    if ctrl.pause_monitoring():
                        st.session_state.feedback_msg = "Monitoring paused. Ingestion suspended."
                    st.rerun()

            # 3. RESUME
            with b3:
                can_resume = (cur_status == "PAUSED")
                if st.button("▶ Resume", key=f"btn_resume_{page_key}", disabled=not can_resume, use_container_width=True, help="Resume monitoring worker"):
                    if ctrl.resume_monitoring():
                        st.session_state.feedback_msg = "Monitoring resumed from checkpoint."
                    st.rerun()

            # 4. STOP
            with b4:
                can_stop = cur_status in ("RUNNING", "PAUSED")
                if st.button("■ Stop", key=f"btn_stop_{page_key}", disabled=not can_stop, use_container_width=True, help="Gracefully stop monitoring thread"):
                    ctrl.stop_monitoring(timeout=2.0)
                    st.session_state.feedback_msg = "Monitoring stopped. Worker terminated."
                    st.rerun()

            # 5. POLL NOW (Single Cycle)
            with b5:
                if st.button("↺ Poll", key=f"btn_poll_{page_key}", use_container_width=True, help="Run exactly 1 collection cycle without daemon"):
                    polled = ctrl.run_once()
                    st.session_state.feedback_msg = f"Poll cycle completed: {len(polled)} event(s) processed."
                    st.rerun()

            # 6. REFRESH (No collection)
            with b6:
                if st.button("↻ Refresh", key=f"btn_ref_{page_key}", use_container_width=True, help="Refresh dashboard metrics snapshot"):
                    ctrl.refresh_diagnostics()
                    st.session_state.feedback_msg = "Telemetry snapshot updated."
                    st.rerun()

        with c_meta:
            meta_html = (
                f'<div style="text-align:right;padding-top:6px;font-size:11px;color:{t["text_secondary"]};">'
                f'<span>Last Collection:</span> <strong class="mono" style="color:{t["text_primary"]};">{hint_time}</strong>'
                f'</div>'
            )
            st.markdown(meta_html, unsafe_allow_html=True)

    if cur_status == "ERROR":
        err_msg = snap.get("last_error") or "A collection or processing error occurred."
        err_html = (
            f'<div style="background-color:rgba(214,69,80,0.12);border:1px solid rgba(214,69,80,0.3);color:{t["critical"]};padding:8px 12px;border-radius:5px;font-size:11.5px;margin-bottom:12px;">'
            f'<strong>Engine Error:</strong> {html.escape(err_msg)}'
            f'</div>'
        )
        st.markdown(err_html, unsafe_allow_html=True)

# ══════════════════════════════════════════════════════════════════════════════
# KPI STRIP COMPONENT
# ══════════════════════════════════════════════════════════════════════════════

def render_kpi_strip(kpi_data: list[dict[str, Any]]) -> None:
    """
    Renders 4 or 5 horizontally aligned KPI cards matching reference layout.
    """
    cols = st.columns(len(kpi_data), gap="small")
    for i, kpi in enumerate(kpi_data):
        with cols[i]:
            accent = kpi.get("accent", "blue")
            val_str = f"{kpi['value']:,}" if isinstance(kpi['value'], int) else str(kpi['value'])
            kpi_html = (
                f'<div class="sentinel-kpi-card kpi-accent-{accent}">'
                f'<div class="sentinel-kpi-title">{html.escape(kpi["title"])}</div>'
                f'<div class="sentinel-kpi-value">{html.escape(val_str)}</div>'
                f'<div class="sentinel-kpi-sub">{html.escape(kpi.get("subtitle", ""))}</div>'
                f'</div>'
            )
            st.markdown(kpi_html, unsafe_allow_html=True)
    st.markdown('<div style="height:10px;"></div>', unsafe_allow_html=True)
