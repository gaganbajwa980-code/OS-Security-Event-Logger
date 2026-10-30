import json
from datetime import datetime

import pandas as pd
import plotly.express as px
import streamlit as st

from monitor.log_monitor import read_logs
from detection.detector import detect_security_events


# ------------------------------------------------------------
# Page setup
# ------------------------------------------------------------
st.set_page_config(
    page_title="Sentinel | OS Security Event Logger",
    page_icon="🛡️",
    layout="wide",
    initial_sidebar_state="expanded",
)

# Custom styling: dark security-operations look, without extra UI libraries.
st.markdown(
    """
    <style>
    @import url('https://fonts.googleapis.com/css2?family=DM+Sans:wght@400;500;600;700&family=Space+Grotesk:wght@500;600;700&display=swap');

    :root {
        --bg: #0b1020;
        --panel: #121a2b;
        --panel2: #172238;
        --line: #27354c;
        --text: #e8eef8;
        --muted: #92a2ba;
        --cyan: #55d6e8;
        --green: #55d6a7;
        --amber: #ffca72;
        --red: #ff6b7a;
    }

    html, body, [class*="css"] {
        font-family: 'DM Sans', sans-serif;
    }
    .stApp {
        background:
            radial-gradient(ellipse at 15% 0%, rgba(43, 94, 150, .20), transparent 36%),
            radial-gradient(ellipse at 95% 5%, rgba(27, 178, 177, .10), transparent 28%),
            var(--bg);
        color: var(--text);
    }
    [data-testid="stHeader"] {
        background: rgba(11, 16, 32, .86);
    }
    [data-testid="stSidebar"] {
        background: #0d1526;
        border-right: 1px solid var(--line);
    }
    [data-testid="stSidebar"] * {
        color: var(--text);
    }
    .block-container {
        max-width: 1500px;
        padding-top: 2rem;
        padding-bottom: 3rem;
    }
    h1, h2, h3 {
        font-family: 'Space Grotesk', sans-serif !important;
        color: var(--text) !important;
        letter-spacing: -.025em;
    }
    p, label, .stMarkdown, [data-testid="stCaptionContainer"] {
        color: var(--muted);
    }
    [data-testid="stMetric"] {
        background: linear-gradient(145deg, #17243a, #111a2b);
        border: 1px solid var(--line);
        border-radius: 16px;
        padding: 18px 20px;
        box-shadow: 0 10px 28px rgba(0,0,0,.12);
    }
    [data-testid="stMetricLabel"] p {
        color: #aab8cc !important;
        font-size: .83rem !important;
    }
    [data-testid="stMetricValue"] {
        color: #f3f7ff !important;
        font-family: 'Space Grotesk', sans-serif;
    }
    div[data-testid="stVerticalBlockBorderWrapper"] {
        border-color: var(--line) !important;
        border-radius: 16px !important;
        background: rgba(18, 26, 43, .78);
    }
    div.stButton > button, div.stDownloadButton > button {
        border-radius: 10px;
        border: 1px solid #36506c;
        background: #1b2b43;
        color: #e8eef8;
        font-weight: 600;
    }
    div.stButton > button:hover, div.stDownloadButton > button:hover {
        border-color: var(--cyan);
        color: var(--cyan);
    }
    .hero {
        display: flex;
        align-items: center;
        justify-content: space-between;
        gap: 20px;
        padding: 26px 30px;
        margin-bottom: 22px;
        border-radius: 22px;
        border: 1px solid #2b415c;
        background: linear-gradient(120deg, rgba(25, 43, 67, .98), rgba(15, 31, 48, .92));
        box-shadow: 0 18px 45px rgba(0,0,0,.20);
    }
    .hero-kicker {
        color: var(--cyan);
        font-size: .74rem;
        font-weight: 700;
        letter-spacing: .18em;
        text-transform: uppercase;
        margin-bottom: 8px;
    }
    .hero-title {
        font-family: 'Space Grotesk', sans-serif;
        font-size: clamp(1.8rem, 3vw, 2.8rem);
        line-height: 1.1;
        font-weight: 700;
        color: #f5f8ff;
        margin: 0;
    }
    .hero-subtitle {
        color: #a5b5cb;
        margin-top: 10px;
        font-size: .98rem;
    }
    .hero-badge {
        display: inline-flex;
        align-items: center;
        gap: 8px;
        white-space: nowrap;
        padding: 10px 14px;
        border-radius: 999px;
        border: 1px solid rgba(85,214,167,.35);
        color: #83f0c4;
        background: rgba(85,214,167,.09);
        font-size: .82rem;
        font-weight: 700;
    }
    .section-head {
        display: flex;
        align-items: center;
        justify-content: space-between;
        margin: 8px 0 12px 0;
    }
    .section-eyebrow {
        color: var(--cyan);
        text-transform: uppercase;
        letter-spacing: .14em;
        font-size: .70rem;
        font-weight: 700;
        margin-bottom: 5px;
    }
    .section-title {
        color: #eef4ff;
        font-family: 'Space Grotesk', sans-serif;
        font-size: 1.22rem;
        font-weight: 600;
    }
    .status-chip {
        display: inline-block;
        padding: 5px 9px;
        border-radius: 7px;
        font-size: .75rem;
        font-weight: 700;
        letter-spacing: .02em;
    }
    .chip-red { color: #ff9ca7; background: rgba(255,107,122,.12); border: 1px solid rgba(255,107,122,.28); }
    .chip-green { color: #8af0c6; background: rgba(85,214,167,.10); border: 1px solid rgba(85,214,167,.25); }
    .alert-card {
        background: #171f31;
        border: 1px solid #354158;
        border-left: 4px solid var(--red);
        border-radius: 12px;
        padding: 14px 16px;
        margin-bottom: 10px;
    }
    .alert-card-title {
        color: #f3f6fc;
        font-weight: 700;
        margin-bottom: 5px;
    }
    .alert-card-detail {
        color: #aab8cc;
        font-size: .85rem;
    }
    .small-note {
        border: 1px solid #4b3c24;
        background: rgba(255, 202, 114, .07);
        border-radius: 12px;
        padding: 12px 15px;
        color: #e6c995;
        font-size: .86rem;
    }
    .footer-note {
        border-top: 1px solid var(--line);
        margin-top: 28px;
        padding-top: 16px;
        color: #71839e;
        font-size: .78rem;
    }
    [data-testid="stDataFrame"] {
        border: 1px solid var(--line);
        border-radius: 12px;
        overflow: hidden;
    }
    </style>
    """,
    unsafe_allow_html=True,
)


# ------------------------------------------------------------
# Sidebar controls
# ------------------------------------------------------------
with st.sidebar:
    st.markdown("## 🛡️ Sentinel")
    st.caption("OS SECURITY EVENT LOGGER")
    st.divider()

    st.markdown("### Detection settings")
    threshold = st.slider(
        "Failed-login threshold",
        min_value=2,
        max_value=10,
        value=3,
        help="Flag failed-login entries when the number for one user reaches this threshold.",
    )
    show_only_suspicious = st.toggle(
        "Suspicious events only",
        value=False,
    )
    selected_severities = st.multiselect(
        "Severity levels",
        options=["INFO", "WARNING", "ERROR", "HIGH"],
        default=["INFO", "WARNING", "ERROR", "HIGH"],
    )
    search = st.text_input(
        "Search messages",
        placeholder="e.g. failed login",
    )
    st.divider()
    st.markdown("### About this prototype")
    st.caption(
        "This version analyzes the included sample log file. "
        "It does not yet monitor live operating-system logs."
    )


# ------------------------------------------------------------
# Load and analyze logs
# ------------------------------------------------------------
try:
    raw_events = read_logs()
    events = detect_security_events(raw_events, threshold=threshold)
except (OSError, ValueError) as error:
    st.error(f"Could not read or analyze logs: {error}")
    st.stop()

df = pd.DataFrame(events)

if df.empty:
    st.warning("No valid log events were found.")
    st.stop()

for column, default in {
    "timestamp": "",
    "severity": "INFO",
    "event_type": "system_event",
    "user": "unknown",
    "message": "",
    "is_suspicious": False,
    "alerts": None,
}.items():
    if column not in df.columns:
        df[column] = default

df["is_suspicious"] = df["is_suspicious"].fillna(False).astype(bool)

# ------------------------------------------------------------
# Hero
# ------------------------------------------------------------
st.markdown(
    """
    <div class="hero">
      <div>
        <div class="hero-kicker">Security operations · Event intelligence</div>
        <div class="hero-title">OS Security Event Logger</div>
        <div class="hero-subtitle">A clear view of system events, suspicious activity, and detection outcomes.</div>
      </div>
      <div class="hero-badge">● SAMPLE LOG ANALYSIS</div>
    </div>
    """,
    unsafe_allow_html=True,
)

# Filter all content consistently.
filtered = df.copy()

if show_only_suspicious:
    filtered = filtered[filtered["is_suspicious"]]

if selected_severities:
    filtered = filtered[filtered["severity"].isin(selected_severities)]
else:
    filtered = filtered.iloc[0:0]

if search.strip():
    filtered = filtered[
        filtered["message"].str.contains(
            search.strip(), case=False, na=False, regex=False
        )
    ]

total = len(filtered)
suspicious = int(filtered["is_suspicious"].sum()) if total else 0
high = int((filtered["severity"] == "HIGH").sum()) if total else 0
normal = total - suspicious

# KPI row: metrics now reflect the active filters.
k1, k2, k3, k4 = st.columns(4)
k1.metric("Events in view", total)
k2.metric("Suspicious events", suspicious)
k3.metric("High-severity events", high)
k4.metric("Normal events", normal)

st.markdown("<br>", unsafe_allow_html=True)

# ------------------------------------------------------------
# Charts
# ------------------------------------------------------------
chart_col1, chart_col2 = st.columns([1, 1], gap="large")

plot_bg = "rgba(0,0,0,0)"
grid_color = "#27354c"
font_color = "#b8c5d8"

with chart_col1:
    with st.container(border=True):
        st.markdown(
            '<div class="section-eyebrow">Event distribution</div><div class="section-title">Events by severity</div>',
            unsafe_allow_html=True,
        )
        if total:
            sev_order = ["HIGH", "ERROR", "WARNING", "INFO"]
            counts = filtered["severity"].value_counts().reindex(sev_order, fill_value=0)
            counts = counts[counts > 0].rename_axis("Severity").reset_index(name="Events")
            if not counts.empty:
                fig = px.bar(
                    counts,
                    x="Severity",
                    y="Events",
                    color="Severity",
                    category_orders={"Severity": sev_order},
                    color_discrete_map={
                        "HIGH": "#ff6b7a",
                        "ERROR": "#ff9d70",
                        "WARNING": "#ffca72",
                        "INFO": "#55d6e8",
                    },
                )
                fig.update_layout(
                    paper_bgcolor=plot_bg,
                    plot_bgcolor=plot_bg,
                    font=dict(color=font_color, family="DM Sans"),
                    showlegend=False,
                    margin=dict(l=8, r=8, t=18, b=8),
                    xaxis=dict(showgrid=False, title="", tickfont=dict(color=font_color)),
                    yaxis=dict(showgrid=True, gridcolor=grid_color, title="", rangemode="tozero"),
                    height=270,
                )
                st.plotly_chart(fig, use_container_width=True, config={"displayModeBar": False})
            else:
                st.info("No events match the current filters.")
        else:
            st.info("No events match the current filters.")

with chart_col2:
    with st.container(border=True):
        st.markdown(
            '<div class="section-eyebrow">Detection outcome</div><div class="section-title">Normal vs suspicious</div>',
            unsafe_allow_html=True,
        )
        if total:
            status = pd.DataFrame(
                {
                    "Status": ["Normal", "Suspicious"],
                    "Events": [normal, suspicious],
                }
            )
            status = status[status["Events"] > 0]
            fig = px.pie(
                status,
                names="Status",
                values="Events",
                hole=0.72,
                color="Status",
                color_discrete_map={
                    "Normal": "#55d6a7",
                    "Suspicious": "#ff6b7a",
                },
            )
            fig.update_traces(
                textposition="outside",
                textinfo="label+value",
                marker=dict(line=dict(color="#121a2b", width=3)),
            )
            fig.update_layout(
                paper_bgcolor=plot_bg,
                plot_bgcolor=plot_bg,
                font=dict(color=font_color, family="DM Sans"),
                showlegend=False,
                margin=dict(l=8, r=8, t=18, b=8),
                height=270,
            )
            st.plotly_chart(fig, use_container_width=True, config={"displayModeBar": False})
        else:
            st.info("No events match the current filters.")

# ------------------------------------------------------------
# Alerts
# ------------------------------------------------------------
st.markdown(
    '<div class="section-eyebrow">Priority review</div><div class="section-title">Security alerts</div>',
    unsafe_allow_html=True,
)

alerts_df = filtered[filtered["is_suspicious"]]

if alerts_df.empty:
    st.success("No suspicious events match the current filters.")
else:
    alert_left, alert_right = st.columns([1.3, 1], gap="large")
    with alert_left:
        for _, event in alerts_df.iterrows():
            timestamp = str(event.get("timestamp", ""))
            message = str(event.get("message", "Unknown event"))
            user = str(event.get("user", "unknown"))
            st.markdown(
                f"""
                <div class="alert-card">
                  <div class="alert-card-title">⚠ &nbsp; {message}</div>
                  <div class="alert-card-detail">{timestamp} &nbsp;·&nbsp; User: {user}</div>
                </div>
                """,
                unsafe_allow_html=True,
            )
    with alert_right:
        st.markdown("#### Why was this flagged?")
        unique_alerts = []
        for _, event in alerts_df.iterrows():
            for alert in (event.get("alerts") or []):
                if alert not in unique_alerts:
                    unique_alerts.append(alert)
        for alert in unique_alerts:
            st.markdown(f"- {alert}")
        st.markdown(
            f'<span class="status-chip chip-red">{len(alerts_df)} flagged event(s)</span>',
            unsafe_allow_html=True,
        )

st.markdown("<br>", unsafe_allow_html=True)

# ------------------------------------------------------------
# Event table
# ------------------------------------------------------------
st.markdown(
    '<div class="section-eyebrow">Event explorer</div><div class="section-title">Log records</div>',
    unsafe_allow_html=True,
)

display_columns = [
    "timestamp",
    "severity",
    "event_type",
    "user",
    "message",
    "is_suspicious",
]
st.caption(f"Showing {len(filtered)} of {len(df)} events after applying the current filters.")

if filtered.empty:
    st.info("No events match these filters. Adjust the sidebar settings.")
else:
    st.dataframe(
        filtered[display_columns],
        use_container_width=True,
        hide_index=True,
        column_config={
            "timestamp": st.column_config.TextColumn("Timestamp", width="medium"),
            "severity": st.column_config.TextColumn("Severity", width="small"),
            "event_type": st.column_config.TextColumn("Event type", width="small"),
            "user": st.column_config.TextColumn("User", width="small"),
            "message": st.column_config.TextColumn("Event message", width="large"),
            "is_suspicious": st.column_config.CheckboxColumn("Suspicious", width="small"),
        },
    )

# ------------------------------------------------------------
# Export
# ------------------------------------------------------------
st.markdown(
    '<div class="section-eyebrow">Reporting</div><div class="section-title">Export filtered results</div>',
    unsafe_allow_html=True,
)
download_col1, download_col2, download_col3 = st.columns([1, 1, 2])

csv_data = filtered.to_csv(index=False).encode("utf-8")
json_data = json.dumps(filtered.to_dict(orient="records"), indent=2, default=str).encode("utf-8")

with download_col1:
    st.download_button(
        "↓  Download CSV",
        data=csv_data,
        file_name="security_events_report.csv",
        mime="text/csv",
        use_container_width=True,
    )
with download_col2:
    st.download_button(
        "↓  Download JSON",
        data=json_data,
        file_name="security_events_report.json",
        mime="application/json",
        use_container_width=True,
    )
with download_col3:
    st.markdown(
        '<div class="small-note">Prototype scope: these insights are generated from simulated sample logs. Live operating-system log ingestion and continuous monitoring are future enhancements.</div>',
        unsafe_allow_html=True,
    )

st.markdown(
    '<div class="footer-note">SENTINEL · OS Security Event Logger &nbsp; / &nbsp; Built with Python, Streamlit and Pandas</div>',
    unsafe_allow_html=True,
)
