
import streamlit as st
import pandas as pd

from monitor.log_monitor import read_logs
from detection.detector import detect_security_events


st.set_page_config(
    page_title="OS Security Event Logger",
    page_icon="🛡️",
    layout="wide",
)

st.title("🛡️ OS Security Event Logger")
st.caption("Operating System Security Monitoring and Event Analysis")

# Sidebar controls
st.sidebar.header("Monitoring Controls")
threshold = st.sidebar.slider(
    "Failed-login threshold",
    min_value=2,
    max_value=10,
    value=3,
)
show_only_suspicious = st.sidebar.checkbox(
    "Show suspicious events only",
    value=False,
)

try:
    raw_events = read_logs()
    events = detect_security_events(raw_events, threshold=threshold)
except (OSError, ValueError) as error:
    st.error(f"Unable to read or process logs: {error}")
    st.stop()

df = pd.DataFrame(events)

if df.empty:
    st.warning("No valid events were found in the log file.")
    st.stop()

# Summary metrics
total = len(df)
suspicious = int(df["is_suspicious"].sum())
high = int((df["severity"] == "HIGH").sum())
normal = total - suspicious

col1, col2, col3, col4 = st.columns(4)
col1.metric("Total Events", total)
col2.metric("Suspicious Events", suspicious)
col3.metric("High-Severity Events", high)
col4.metric("Other Events", normal)

st.divider()

# Charts
left, right = st.columns(2)

with left:
    st.subheader("Events by Severity")
    severity_counts = df["severity"].value_counts()
    st.bar_chart(severity_counts)

with right:
    st.subheader("Security Status")
    status_counts = (
        df["is_suspicious"]
        .map({True: "Suspicious", False: "Normal"})
        .value_counts()
    )
    st.bar_chart(status_counts)

# Search and filter
st.subheader("Event Log")

search = st.text_input(
    "Search event messages",
    placeholder="Try: failed login or unauthorized access",
)

filtered = df.copy()

if show_only_suspicious:
    filtered = filtered[filtered["is_suspicious"]]

if search.strip():
    filtered = filtered[
        filtered["message"].str.contains(
            search.strip(), case=False, na=False, regex=False
        )
    ]

display_columns = [
    "timestamp",
    "severity",
    "event_type",
    "user",
    "message",
    "is_suspicious",
]

st.dataframe(
    filtered[display_columns],
    use_container_width=True,
    hide_index=True,
)

# Detailed alerts
st.subheader("Security Alerts")

alerts = df[df["is_suspicious"]]

if alerts.empty:
    st.success("No suspicious events found for the current threshold.")
else:
    for _, event in alerts.iterrows():
        with st.expander(
            f"{event['severity']} — {event['timestamp']} — "
            f"{event['message']}"
        ):
            for alert in event["alerts"]:
                st.write(f"• {alert}")

# Export filtered events
st.subheader("Export Report")

csv_data = filtered.to_csv(index=False).encode("utf-8")

st.download_button(
    label="Download Events as CSV",
    data=csv_data,
    file_name="security_events_report.csv",
    mime="text/csv",
)

st.caption(
    "Prototype note: this dashboard currently analyzes simulated sample logs. "
    "It does not yet monitor live system logs automatically."
)
