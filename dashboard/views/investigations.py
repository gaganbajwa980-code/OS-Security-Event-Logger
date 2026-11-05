"""
SENTINEL — Investigations & Incident Management View
Professional security triage interface with lifecycle status transitions,
correlated event inspect view, and atomic persistence.
Uses clean Streamlit native tables to eliminate raw HTML rendering bugs.
"""

from __future__ import annotations

import html
from typing import Optional
import pandas as pd
import streamlit as st

from monitor.controller import SentinelController
from monitor.event_models import Incident, IncidentStatus
from dashboard.components import (
    card_container,
    clean_html,
    format_timestamp,
    get_severity_badge_html,
    incidents_to_csv,
    incidents_to_json,
    render_card_header,
    render_kpi_strip,
    render_monitoring_toolbar,
    render_secondary_nav,
)
from dashboard.theme import get_theme

INVESTIGATIONS_TABS = [
    "All Incidents",
    "Open",
    "Investigating",
    "Resolved",
]

def render_investigations(ctrl: SentinelController) -> None:
    """Render the Incident Management & Forensic Triage interface."""
    active_theme = st.session_state.get("theme", "dark")
    t = get_theme(active_theme)

    active_tab = render_secondary_nav(INVESTIGATIONS_TABS, "inv_subnav_tab")
    render_monitoring_toolbar(ctrl, "investigations")

    # Fetch all incidents from controller
    all_incidents = ctrl.get_incidents()

    # ── Summary KPI Strip ─────────────────────────────────────────────────────
    total_inc = len(all_incidents)
    open_inc = sum(1 for i in all_incidents if i.status == "OPEN")
    inv_inc = sum(1 for i in all_incidents if i.status == "INVESTIGATING")
    res_inc = sum(1 for i in all_incidents if i.status == "RESOLVED")

    kpis = [
        {
            "title": "Total Incidents",
            "value": total_inc,
            "subtitle": "Tracked security incidents",
            "accent": "blue",
        },
        {
            "title": "Open Incidents",
            "value": open_inc,
            "subtitle": "Awaiting triage",
            "accent": "red" if open_inc > 0 else "blue",
        },
        {
            "title": "Investigating",
            "value": inv_inc,
            "subtitle": "Active analyst triage",
            "accent": "amber" if inv_inc > 0 else "blue",
        },
        {
            "title": "Resolved Incidents",
            "value": res_inc,
            "subtitle": "Closed & remediated",
            "accent": "green",
        },
    ]
    render_kpi_strip(kpis)

    # Filter incidents by active subnav tab
    displayed_incidents = all_incidents
    if active_tab == "Open":
        displayed_incidents = [i for i in displayed_incidents if i.status == "OPEN"]
    elif active_tab == "Investigating":
        displayed_incidents = [i for i in displayed_incidents if i.status == "INVESTIGATING"]
    elif active_tab == "Resolved":
        displayed_incidents = [i for i in displayed_incidents if i.status == "RESOLVED"]

    # ── Export & Summary Row ──────────────────────────────────────────────────
    exp_c1, exp_c2, exp_count = st.columns([1.5, 1.5, 7.0], gap="small")
    with exp_c1:
        if displayed_incidents:
            csv_data = incidents_to_csv(displayed_incidents)
            st.download_button(
                "⬇ Export CSV",
                data=csv_data,
                file_name=f"sentinel_incidents_{active_tab.lower()}.csv",
                mime="text/csv",
                use_container_width=True,
                key="btn_exp_incidents_csv"
            )
    with exp_c2:
        if displayed_incidents:
            json_data = incidents_to_json(displayed_incidents)
            st.download_button(
                "⬇ Export JSON",
                data=json_data,
                file_name=f"sentinel_incidents_{active_tab.lower()}.json",
                mime="application/json",
                use_container_width=True,
                key="btn_exp_incidents_json"
            )
    with exp_count:
        count_html = (
            f'<div class="mono" style="text-align:right;font-size:11px;color:{t["text_secondary"]};padding-top:6px;">'
            f'Showing <strong>{len(displayed_incidents)}</strong> of <strong>{total_inc}</strong> total tracked incidents'
            f'</div>'
        )
        st.markdown(count_html, unsafe_allow_html=True)

    # ── Incidents Table (Native Streamlit DataFrame) ──────────────────────────
    if not displayed_incidents:
        with card_container():
            empty_html = (
                f'<div style="padding:40px;text-align:center;color:{t["text_secondary"]};">'
                f'No incidents present in category: <strong>{html.escape(active_tab)}</strong>.'
                f'</div>'
            )
            st.markdown(empty_html, unsafe_allow_html=True)
    else:
        inc_records = []
        for inc in displayed_incidents:
            inc_records.append({
                "Incident ID": inc.incident_id,
                "Title": inc.title,
                "Severity": (inc.severity or "INFO").upper(),
                "User": inc.user or "—",
                "Source IP": inc.source_ip or "UNKNOWN",
                "First Seen": format_timestamp(inc.timestamp_first),
                "Last Activity": format_timestamp(inc.timestamp_last),
                "Events": inc.event_count,
                "Status": inc.status,
            })

        df_incs = pd.DataFrame(inc_records)
        st.dataframe(
            df_incs,
            column_config={
                "Incident ID": st.column_config.TextColumn("Incident ID", width="small"),
                "Title": st.column_config.TextColumn("Title / Rule", width="medium"),
                "Severity": st.column_config.TextColumn("Severity", width="small"),
                "User": st.column_config.TextColumn("User", width="small"),
                "Source IP": st.column_config.TextColumn("Source IP", width="small"),
                "First Seen": st.column_config.TextColumn("First Seen", width="medium"),
                "Last Activity": st.column_config.TextColumn("Last Activity", width="medium"),
                "Events": st.column_config.NumberColumn("Events", format="%d", width="small"),
                "Status": st.column_config.TextColumn("Status", width="small"),
            },
            hide_index=True,
            use_container_width=True,
            height=340,
        )

    # ── Interactive Incident Triage & Inspection View ─────────────────────────
    with card_container():
        render_card_header("Incident Investigation & Status Transitions", "ANALYST WORKSPACE")

        if displayed_incidents:
            inc_options = [
                f"{i.incident_id} — {i.title} [{i.status}] ({i.event_count} events)"
                for i in displayed_incidents
            ]
            sel_idx = st.selectbox(
                "Select an incident to investigate and update lifecycle status:",
                options=range(len(displayed_incidents)),
                format_func=lambda idx: inc_options[idx],
                key="inv_sel_idx"
            )
            selected_inc = displayed_incidents[sel_idx]

            # Top Incident Summary
            inc_summary_html = clean_html(f"""
            <div style="background:{t['elevated_surface']};border:1px solid {t['border']};border-radius:6px;padding:12px 14px;margin-bottom:12px;">
                <div style="display:flex;justify-content:space-between;align-items:center;margin-bottom:6px;">
                    <div style="display:flex;align-items:center;gap:8px;">
                        <span class="mono" style="font-size:14px;font-weight:700;color:{t['primary_blue']};">{html.escape(selected_inc.incident_id)}</span>
                        <span style="font-size:14px;font-weight:700;color:{t['text_primary']};">{html.escape(selected_inc.title)}</span>
                        {get_severity_badge_html(selected_inc.severity)}
                    </div>
                    <div>
                        <span style="font-size:11px;color:{t['text_secondary']};">Status:</span> <strong class="mono" style="color:{t['text_primary']};font-size:12px;">{html.escape(selected_inc.status)}</strong>
                    </div>
                </div>
                <div style="font-size:12px;color:{t['text_primary']};margin-bottom:8px;">
                    {html.escape(selected_inc.description)}
                </div>
                <div style="font-size:11px;color:{t['text_secondary']};display:flex;gap:18px;border-top:1px solid {t['border_subtle']};padding-top:6px;">
                    <span>User: <strong class="mono" style="color:{t['text_primary']};">{html.escape(selected_inc.user)}</strong></span>
                    <span>Source IP: <strong class="mono" style="color:{t['text_primary']};">{html.escape(selected_inc.source_ip)}</strong></span>
                    <span>Rule ID: <strong class="mono" style="color:{t['text_primary']};">{html.escape(selected_inc.rule_id)}</strong></span>
                    <span>MITRE ATT&CK: <strong class="mono" style="color:{t['text_primary']};">{html.escape(selected_inc.mitre_attack_id or 'N/A')}</strong></span>
                </div>
            </div>
            """)
            st.markdown(inc_summary_html, unsafe_allow_html=True)

            # Status Transition Action Buttons (genuinely calling controller API)
            trans_lbl = f"<div style='font-size:11.5px;font-weight:600;color:{t['text_secondary']};text-transform:uppercase;margin-bottom:6px;'>Transition Incident Lifecycle Status:</div>"
            st.markdown(trans_lbl, unsafe_allow_html=True)
            b_c1, b_c2, b_c3 = st.columns(3, gap="small")
            with b_c1:
                if st.button("Mark OPEN", key=f"btn_st_open_{selected_inc.incident_id}", disabled=(selected_inc.status == "OPEN"), use_container_width=True):
                    updated = ctrl.update_incident_status(selected_inc.incident_id, IncidentStatus.OPEN)
                    if updated:
                        st.session_state.feedback_msg = f"{selected_inc.incident_id} moved to OPEN."
                    st.rerun()

            with b_c2:
                if st.button("Mark INVESTIGATING", key=f"btn_st_inv_{selected_inc.incident_id}", disabled=(selected_inc.status == "INVESTIGATING"), use_container_width=True):
                    updated = ctrl.update_incident_status(selected_inc.incident_id, IncidentStatus.INVESTIGATING)
                    if updated:
                        st.session_state.feedback_msg = f"{selected_inc.incident_id} marked as INVESTIGATING."
                    st.rerun()

            with b_c3:
                if st.button("Mark RESOLVED", key=f"btn_st_res_{selected_inc.incident_id}", disabled=(selected_inc.status == "RESOLVED"), use_container_width=True):
                    updated = ctrl.update_incident_status(selected_inc.incident_id, IncidentStatus.RESOLVED)
                    if updated:
                        st.session_state.feedback_msg = f"{selected_inc.incident_id} marked as RESOLVED."
                    st.rerun()

            # Related Events Timeline for this Incident (rendered with native st.dataframe)
            if selected_inc.related_events:
                rel_header = (
                    f'<div style="margin-top:14px;margin-bottom:6px;font-size:11px;font-weight:700;color:{t["text_secondary"]};text-transform:uppercase;">'
                    f'Correlated Contributing Events'
                    f'</div>'
                )
                st.markdown(rel_header, unsafe_allow_html=True)

                rel_data = []
                for rev in selected_inc.related_events:
                    rel_data.append({
                        "Timestamp": format_timestamp(rev.get("timestamp")),
                        "Event ID": rev.get("event_id") or "—",
                        "Channel": rev.get("channel") or "—",
                        "Message": rev.get("message") or "",
                    })

                df_rel = pd.DataFrame(rel_data)
                st.dataframe(
                    df_rel,
                    column_config={
                        "Timestamp": st.column_config.TextColumn("Timestamp", width="medium"),
                        "Event ID": st.column_config.TextColumn("Event ID", width="small"),
                        "Channel": st.column_config.TextColumn("Channel", width="small"),
                        "Message": st.column_config.TextColumn("Message", width="large"),
                    },
                    hide_index=True,
                    use_container_width=True,
                    height=220,
                )
        else:
            st.write("No incidents available for triage.")
