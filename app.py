import streamlit as st
import json
import subprocess
import sys
from pathlib import Path

st.set_page_config(page_title="SFTMS - SecOps Dashboard", page_icon="🛡️", layout="wide")

st.title("🛡️ Secure File Transfer Monitoring System (SFTMS)")
st.caption("Endpoint Data Loss Prevention (DLP) & File Integrity Monitoring (FIM) Console")

LOG_FILE = Path(__file__).resolve().parent / "transfer_audit_logs.json"
REPORT_FILE = Path(__file__).resolve().parent / "FINAL_SECURITY_AUDIT_REPORT.md"

# Sidebar controls for the mentor to test the simulation live on the web!
st.sidebar.header("⚡ Live Mentor Controls")
if st.sidebar.button("🚀 Run 3-Scenario Attack Simulation"):
    with st.spinner("Executing 6-Stage DLP/FIM Simulation..."):
        subprocess.run([sys.executable, "SFTMS.py", "--simulate"])
    st.sidebar.success("Simulation Complete! Logs & Report Updated.")

# Load JSON Logs
logs = []
if LOG_FILE.exists():
    try:
        logs = json.loads(LOG_FILE.read_text(encoding="utf-8"))
    except Exception:
        logs = []

# Top Metrics Row
total_events = len(logs)
sensitive_events = sum(1 for l in logs if l.get("classification") == "SENSITIVE")
violations = sum(1 for l in logs if l.get("authorization_status") != "ALLOWED")
hash_failures = sum(1 for l in logs if l.get("integrity_status") == "INTEGRITY_FAILURE")

col1, col2, col3, col4 = st.columns(4)
col1.metric("Total File Events", total_events)
col2.metric("Sensitive Asset Events", sensitive_events)
col3.metric("Policy Violations", violations)
col4.metric("SHA256/MD5 Mismatches", hash_failures)

st.divider()

# Triggered Security Alerts Section
st.subheader("🚨 Triggered Real-Time Security Alerts")
alerts_list = [
    {"Timestamp": l["timestamp"], "Event": l["event_type"], "File": l["source_path"], "Alert": a}
    for l in logs if l.get("alerts") for a in l["alerts"]
]
if alerts_list:
    st.error(f"Detected {len(alerts_list)} High-Priority Security Violations!")
    st.dataframe(alerts_list, use_container_width=True)
else:
    st.success("No security policy violations detected.")

# Full Audit Telemetry Table
st.subheader("📋 6-Stage File Transfer Telemetry Log")
if logs:
    st.dataframe(logs, use_container_width=True)
else:
    st.info("Click 'Run 3-Scenario Attack Simulation' in the left sidebar to generate telemetry.")

# Executive Audit Report Preview
if REPORT_FILE.exists():
    with st.expander("📄 View Full Generated Security Audit Report (Markdown)", expanded=False):
        st.markdown(REPORT_FILE.read_text(encoding="utf-8"))
        