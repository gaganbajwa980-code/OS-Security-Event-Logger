"""
SENTINEL — Events View
Professional event analysis interface with channel-specific tabs,
multi-attribute filters, full-text search, event inspection, and data export.
Uses clean Streamlit native tables to avoid raw HTML rendering defects.
"""

from __future__ import annotations

import html
from collections import Counter
from typing import Optional
import pandas as pd
import streamlit as st

from monitor.controller import SentinelController
from monitor.event_models import SecurityEvent, SourceType
from dashboard.components import (
    card_container,
    clean_html,
    events_to_csv,
    events_to_json,
    format_timestamp,
    get_severity_badge_html,
    get_source_badge_html,
    render_card_header,
    render_kpi_strip,
    render_monitoring_toolbar,
    render_secondary_nav,
)
from dashboard.theme import get_theme

EVENTS_TABS = [
    "All Events",
    "Windows System",
    "Windows Application",
    "Windows Security",
    "Simulated Events",
]

def render_events(ctrl: SentinelController) -> None:
    """Render the Events page with tabs, filters, table, inspect view, and export."""
    active_theme = st.session_state.get("theme", "dark")
    t = get_theme(active_theme)

    active_tab = render_secondary_nav(EVENTS_TABS, "events_subnav_tab")
    render_monitoring_toolbar(ctrl, "events")

    # Fetch events
    raw_events = ctrl.get_recent_events(limit=1000)

    # Filter by selected secondary tab
    tab_events = raw_events
    if active_tab == "Windows System":
        tab_events = [e for e in tab_events if e.channel.lower() == "system"]
    elif active_tab == "Windows Application":
        tab_events = [e for e in tab_events if e.channel.lower() == "application"]
    elif active_tab == "Windows Security":
        tab_events = [e for e in tab_events if e.channel.lower() == "security"]
    elif active_tab == "Simulated Events":
        tab_events = [
            e for e in tab_events
            if e.source_type in (SourceType.SIMULATED_REPLAY, SourceType.STATIC_SAMPLE_FILE)
            or "sample" in e.channel.lower()
        ]

    # ── Summary KPI Strip ─────────────────────────────────────────────────────
    total_cnt = len(tab_events)
    susp_cnt = sum(1 for e in tab_events if e.is_suspicious)
    norm_cnt = total_cnt - susp_cnt
    crit_cnt = sum(1 for e in tab_events if (e.severity or "").upper() == "CRITICAL")

    kpis = [
        {
            "title": f"{active_tab} Total",
            "value": total_cnt,
            "subtitle": "Records in buffer",
            "accent": "blue",
        },
        {
            "title": "Normal Events",
            "value": norm_cnt,
            "subtitle": "Benign activity",
            "accent": "green",
        },
        {
            "title": "Suspicious / Threats",
            "value": susp_cnt,
            "subtitle": "Security rule matches",
            "accent": "amber" if susp_cnt > 0 else "blue",
        },
        {
            "title": "Critical Events",
            "value": crit_cnt,
            "subtitle": "Audit clear or privilege abuse",
            "accent": "red" if crit_cnt > 0 else "blue",
        },
    ]
    render_kpi_strip(kpis)

    # ── Search & Filter Controls Panel ────────────────────────────────────────
    with card_container():
        render_card_header("Filter & Search Log Stream", "QUERY CONTROLS")

        fc1, fc2, fc3, fc4 = st.columns([3, 2, 2, 2], gap="small")
        with fc1:
            keyword = st.text_input("Search Keyword / Message / User", value="", placeholder="Type keyword to filter...", key="ev_kw")
        with fc2:
            sev_options = ["CRITICAL", "HIGH", "WARNING", "INFO"]
            selected_sevs = st.multiselect("Severity", options=sev_options, default=[], key="ev_sev")
        with fc3:
            src_options = ["ALL", "LIVE_WINDOWS", "SIMULATED_REPLAY", "STATIC_SAMPLE_FILE"]
            selected_src = st.selectbox("Source Type", options=src_options, index=0, key="ev_src")
        with fc4:
            max_limit = st.slider("Max Display Limit", min_value=25, max_value=500, value=100, step=25, key="ev_limit")

    # Apply filters
    filtered_events = tab_events

    if selected_sevs:
        filtered_events = [e for e in filtered_events if (e.severity or "INFO").upper() in selected_sevs]

    if selected_src != "ALL":
        filtered_events = [
            e for e in filtered_events
            if (e.source_type.value if hasattr(e.source_type, 'value') else str(e.source_type)) == selected_src
        ]

    if keyword.strip():
        kw_lower = keyword.strip().lower()
        filtered_events = [
            e for e in filtered_events
            if kw_lower in (e.message or "").lower()
            or kw_lower in (e.user or "").lower()
            or kw_lower in (e.ip_address or "").lower()
            or kw_lower in str(e.event_id or "")
            or kw_lower in (e.channel or "").lower()
        ]

    display_events = filtered_events[:max_limit]

    # ── Export & Summary Row ──────────────────────────────────────────────────
    exp_c1, exp_c2, exp_count = st.columns([1.5, 1.5, 7.0], gap="small")
    with exp_c1:
        if display_events:
            csv_data = events_to_csv(display_events)
            st.download_button(
                "⬇ Export CSV",
                data=csv_data,
                file_name=f"sentinel_{active_tab.lower().replace(' ', '_')}.csv",
                mime="text/csv",
                use_container_width=True,
                key="btn_exp_events_csv"
            )
    with exp_c2:
        if display_events:
            json_data = events_to_json(display_events)
            st.download_button(
                "⬇ Export JSON",
                data=json_data,
                file_name=f"sentinel_{active_tab.lower().replace(' ', '_')}.json",
                mime="application/json",
                use_container_width=True,
                key="btn_exp_events_json"
            )
    with exp_count:
        count_str = (
            f'<div class="mono" style="text-align:right;font-size:11px;color:{t["text_secondary"]};padding-top:6px;">'
            f'Showing <strong>{len(display_events):,}</strong> of <strong>{len(filtered_events):,}</strong> matching records'
            f'</div>'
        )
        st.markdown(count_str, unsafe_allow_html=True)

    # ── Events Data Table (Native Streamlit DataFrame) ────────────────────────
    if not display_events:
        with card_container():
            empty_msg = f'<div style="padding:40px;text-align:center;color:{t["text_secondary"]};">No events found matching the active filters.</div>'
            st.markdown(empty_msg, unsafe_allow_html=True)
    else:
        ev_records = []
        for ev in display_events:
            ev_records.append({
                "Timestamp": format_timestamp(ev.timestamp),
                "EID": ev.event_id if ev.event_id else "—",
                "Channel": ev.channel,
                "Severity": (ev.severity or "INFO").upper(),
                "User": ev.user or "—",
                "IP Address": ev.ip_address or "UNKNOWN",
                "Description": ev.message,
                "Source": ev.source_type.value if hasattr(ev.source_type, 'value') else str(ev.source_type),
            })

        df_evs = pd.DataFrame(ev_records)
        st.dataframe(
            df_evs,
            column_config={
                "Timestamp": st.column_config.TextColumn("Timestamp", width="medium"),
                "EID": st.column_config.TextColumn("Event ID", width="small"),
                "Channel": st.column_config.TextColumn("Channel", width="small"),
                "Severity": st.column_config.TextColumn("Severity", width="small"),
                "User": st.column_config.TextColumn("User", width="small"),
                "IP Address": st.column_config.TextColumn("IP Address", width="small"),
                "Description": st.column_config.TextColumn("Description", width="large"),
                "Source": st.column_config.TextColumn("Source", width="medium"),
            },
            hide_index=True,
            use_container_width=True,
            height=420,
        )

    # ── Event Inspection Detail Panel ─────────────────────────────────────────
    with card_container():
        render_card_header("Inspect Security Event Details", "DEEP INSPECTION")

        if display_events:
            inspect_options = [
                f"[{format_timestamp(e.timestamp)[11:19]}] EID {e.event_id or 'N/A'} - {e.user} - {(e.message or '')[:40]}"
                for e in display_events
            ]
            chosen_idx = st.selectbox(
                "Select an event to inspect full metadata:",
                options=range(len(display_events)),
                format_func=lambda i: inspect_options[i],
                key="ev_inspect_select"
            )
            selected_event = display_events[chosen_idx]

            ic1, ic2, ic3 = st.columns(3, gap="small")
            with ic1:
                ic1_html = clean_html(f"""
                <div style="font-size:11.5px;color:{t['text_secondary']};line-height:1.7;">
                    <strong>Event ID:</strong> <span class="mono" style="color:{t['text_primary']};">{selected_event.event_id or 'N/A'}</span><br>
                    <strong>Record ID:</strong> <span class="mono" style="color:{t['text_primary']};">{selected_event.record_id or 'N/A'}</span><br>
                    <strong>Channel:</strong> <span class="mono" style="color:{t['text_primary']};">{html.escape(selected_event.channel)}</span><br>
                    <strong>Provider:</strong> <span class="mono" style="color:{t['text_primary']};">{html.escape(selected_event.provider)}</span>
                </div>
                """)
                st.markdown(ic1_html, unsafe_allow_html=True)
            with ic2:
                ic2_html = clean_html(f"""
                <div style="font-size:11.5px;color:{t['text_secondary']};line-height:1.7;">
                    <strong>User:</strong> <span class="mono" style="color:{t['text_primary']};">{html.escape(selected_event.user)}</span><br>
                    <strong>IP Address:</strong> <span class="mono" style="color:{t['text_primary']};">{html.escape(selected_event.ip_address)}</span><br>
                    <strong>Computer:</strong> <span class="mono" style="color:{t['text_primary']};">{html.escape(selected_event.computer)}</span><br>
                    <strong>Timestamp:</strong> <span class="mono" style="color:{t['text_primary']};">{html.escape(str(selected_event.timestamp))}</span>
                </div>
                """)
                st.markdown(ic2_html, unsafe_allow_html=True)
            with ic3:
                src_val = selected_event.source_type.value if hasattr(selected_event.source_type, 'value') else str(selected_event.source_type)
                ic3_html = clean_html(f"""
                <div style="font-size:11.5px;color:{t['text_secondary']};line-height:1.7;">
                    <strong>Severity:</strong> {get_severity_badge_html(selected_event.severity)}<br>
                    <strong>Source:</strong> {get_source_badge_html(src_val)}<br>
                    <strong>Suspicious:</strong> <span class="mono" style="color:{t['critical'] if selected_event.is_suspicious else t['success']};font-weight:700;">{'YES' if selected_event.is_suspicious else 'NO'}</span><br>
                    <strong>Alerts:</strong> <span style="color:{t['text_primary']};">{html.escape(', '.join(selected_event.alerts)) if selected_event.alerts else 'None'}</span>
                </div>
                """)
                st.markdown(ic3_html, unsafe_allow_html=True)

            msg_box_html = clean_html(f"""
            <div style="margin-top:10px;padding:8px 12px;background:{t['elevated_surface']};border:1px solid {t['border']};border-radius:4px;">
                <div style="font-size:10.5px;font-weight:600;color:{t['text_secondary']};text-transform:uppercase;margin-bottom:4px;">Full Message</div>
                <div style="font-size:12px;color:{t['text_primary']};">{html.escape(selected_event.message or 'No message text')}</div>
            </div>
            """)
            st.markdown(msg_box_html, unsafe_allow_html=True)

            if selected_event.raw_data:
                with st.expander("Raw Data & Normalized XML Attributes", expanded=False):
                    st.json(selected_event.raw_data)
        else:
            st.write("No events to inspect.")
