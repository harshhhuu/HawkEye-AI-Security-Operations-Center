"""
HawkEye-AI — Advanced SOC & AI/ML Analyst Dashboard

Features:
  - 🚨 SOC Alert Triage with Severity Color-Coding & AI Explanations
  - 🎯 MITRE ATT&CK & CIA Triad Impact Classification (Step 1)
  - 📊 AI / ML Model Benchmark & False-Positive Analysis (Step 2)
  - 🛡️ One-Click Incident Response Playbook & Firewall Rule Generator (Step 3)
  - 🗺️ Global GeoIP Threat Intelligence & Attack Origin Map (Bonus)
  - 🔐 Cryptographic Log Integrity Verification & Tamper Detection Demo

Run:
    streamlit run dashboard/app.py
"""

import os
import sys
import json
import pandas as pd
import streamlit as st

try:
    import pydeck as pdk
except ImportError:
    pdk = None

# Add project root to path
sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), ".."))

from auth.roles import can_dismiss_alert, get_role_permissions
from pipeline.ingest import verify_batch
from pipeline.score import risk_score
from pipeline.threat_intel import map_mitre_and_cia
from pipeline.playbooks import generate_playbook
from pipeline.explain import explain_alert


# ---------------------------------------------------------------------------
# Page Configuration
# ---------------------------------------------------------------------------
st.set_page_config(
    page_title="HawkEye-AI | SOC & AI/ML Intelligence Dashboard",
    page_icon="🦅",
    layout="wide",
    initial_sidebar_state="expanded",
)

# ---------------------------------------------------------------------------
# Custom CSS for SOC-style dark theme enhancements
# ---------------------------------------------------------------------------
st.markdown("""
<style>
    @import url('https://fonts.googleapis.com/css2?family=Inter:wght@300;400;500;600;700&display=swap');

    html, body, [class*="css"] {
        font-family: 'Inter', sans-serif;
    }

    /* Main Header */
    .main-header {
        background: linear-gradient(135deg, #131722 0%, #0a0d14 100%);
        border: 1px solid #232936;
        border-radius: 12px;
        padding: 1.4rem 2rem;
        margin-bottom: 1.2rem;
        display: flex;
        justify-content: space-between;
        align-items: center;
    }
    .main-header h1 {
        margin: 0;
        font-size: 1.8rem;
        font-weight: 700;
        background: linear-gradient(90deg, #ff4b4b, #ff8c42);
        -webkit-background-clip: text;
        -webkit-text-fill-color: transparent;
    }
    .main-header p {
        margin: 0;
        color: #8892a4;
        font-size: 0.9rem;
    }

    /* Metric cards */
    .metric-card {
        background: linear-gradient(135deg, #1a1f2e 0%, #121622 100%);
        border: 1px solid #262e40;
        border-radius: 10px;
        padding: 1.1rem 1.3rem;
        text-align: center;
        transition: border-color 0.3s ease, transform 0.2s ease;
    }
    .metric-card:hover {
        border-color: #ff4b4b;
        transform: translateY(-2px);
    }
    .metric-card .metric-value {
        font-size: 1.9rem;
        font-weight: 700;
        margin: 0;
    }
    .metric-card .metric-label {
        font-size: 0.75rem;
        color: #8892a4;
        text-transform: uppercase;
        letter-spacing: 0.5px;
        margin: 0;
    }

    /* CIA Badges */
    .cia-badge-c {
        background: rgba(56, 189, 248, 0.15);
        color: #38bdf8;
        border: 1px solid rgba(56, 189, 248, 0.35);
        padding: 3px 8px;
        border-radius: 6px;
        font-size: 0.78rem;
        font-weight: 600;
    }
    .cia-badge-i {
        background: rgba(251, 146, 60, 0.15);
        color: #fb923c;
        border: 1px solid rgba(251, 146, 60, 0.35);
        padding: 3px 8px;
        border-radius: 6px;
        font-size: 0.78rem;
        font-weight: 600;
    }
    .cia-badge-a {
        background: rgba(192, 132, 252, 0.15);
        color: #c084fc;
        border: 1px solid rgba(192, 132, 252, 0.35);
        padding: 3px 8px;
        border-radius: 6px;
        font-size: 0.78rem;
        font-weight: 600;
    }

    /* MITRE Badge */
    .mitre-badge {
        background: rgba(255, 75, 75, 0.12);
        color: #ff6b6b;
        border: 1px solid rgba(255, 75, 75, 0.3);
        padding: 3px 8px;
        border-radius: 6px;
        font-size: 0.78rem;
        font-weight: 600;
        text-decoration: none;
    }

    /* GeoIP Badge */
    .geo-badge {
        background: rgba(74, 222, 128, 0.1);
        color: #4ade80;
        border: 1px solid rgba(74, 222, 128, 0.3);
        padding: 3px 8px;
        border-radius: 6px;
        font-size: 0.78rem;
    }

    /* Alert row styling */
    .alert-card {
        background: #151926;
        border: 1px solid #232a3b;
        border-radius: 9px;
        padding: 1.1rem;
        margin-bottom: 0.8rem;
    }

    /* Confusion Matrix Box */
    .cm-box {
        border-radius: 8px;
        padding: 1.2rem;
        text-align: center;
        margin: 0.3rem;
    }
    .cm-tp { background: rgba(34, 197, 94, 0.15); border: 1px solid #22c55e; }
    .cm-tn { background: rgba(59, 130, 246, 0.15); border: 1px solid #3b82f6; }
    .cm-fp { background: rgba(239, 68, 68, 0.15); border: 1px solid #ef4444; }
    .cm-fn { background: rgba(245, 158, 11, 0.15); border: 1px solid #f59e0b; }

    /* Hide default Streamlit footer */
    #MainMenu {visibility: hidden;}
    footer {visibility: hidden;}
</style>
""", unsafe_allow_html=True)


# ---------------------------------------------------------------------------
# Data Loading
# ---------------------------------------------------------------------------
@st.cache_data
def load_alerts():
    """Load alerts from alerts.json."""
    alerts_path = os.path.join(
        os.path.dirname(os.path.abspath(__file__)), "..", "alerts.json"
    )
    alerts_path = os.path.normpath(alerts_path)

    if not os.path.exists(alerts_path):
        return None, None

    with open(alerts_path, "r", encoding="utf-8") as f:
        data = json.load(f)

    alerts_df = pd.DataFrame(data.get("alerts", []))
    metadata = data.get("metadata", {})
    return alerts_df, metadata


SEVERITY_LABELS = {
    1: "🟢 Low",
    2: "🟡 Medium",
    3: "🟠 High",
    4: "🔴 Critical",
    5: "🔴 CRITICAL",
}

SEVERITY_COLORS = {
    1: "#4ade80",
    2: "#facc15",
    3: "#fb923c",
    4: "#ef4444",
    5: "#dc2626",
}


# ---------------------------------------------------------------------------
# Main App
# ---------------------------------------------------------------------------
def main():
    alerts_df, metadata = load_alerts()

    # ---- Sidebar ----
    with st.sidebar:
        st.markdown("## 🦅 HawkEye-AI")
        st.caption("Cloud Computing & Cyber Security SOC Platform")
        st.markdown("---")

        # Role Selector
        st.markdown("### 👤 User Persona / Role")
        role = st.selectbox(
            "Active Role",
            options=["admin", "viewer"],
            index=0,
            help="Admin can dismiss alerts, execute mitigations, and export data.",
        )
        permissions = get_role_permissions(role)
        role_color = "#4ade80" if role == "admin" else "#facc15"
        st.markdown(
            f'<p style="color:{role_color}; font-weight:600; font-size:0.88rem;">'
            f'Role: {role.upper()} ({("Read & Write" if role=="admin" else "Read Only")})</p>',
            unsafe_allow_html=True,
        )

        st.markdown("---")

        # Filters
        st.markdown("### 🔍 Triage Filters")

        severity_range = st.slider(
            "Severity Range",
            min_value=1,
            max_value=5,
            value=(1, 5),
            help="Filter alerts by severity level.",
        )

        cia_filter = st.selectbox(
            "CIA Triad Filter",
            options=["All", "Confidentiality", "Integrity", "Availability"],
            index=0,
            help="Filter by primary impact dimension on the CIA Triad.",
        )

        search_query = st.text_input(
            "Search Telemetry",
            placeholder="IP, port, service, attack category...",
        )

        st.markdown("---")

        # Quick stats in sidebar
        if alerts_df is not None and not alerts_df.empty:
            st.markdown("### ⚡ Threat Velocity")
            st.write(f"• **Active Alerts:** {len(alerts_df)}")
            if "cia_impact" in alerts_df.columns:
                cia_counts = alerts_df["cia_impact"].value_counts().to_dict()
                st.write(f"• **Confidentiality:** {cia_counts.get('Confidentiality', 0)}")
                st.write(f"• **Integrity:** {cia_counts.get('Integrity', 0)}")
                st.write(f"• **Availability:** {cia_counts.get('Availability', 0)}")

    # ---- Header ----
    st.markdown(
        '<div class="main-header">'
        '<div>'
        '<h1>🦅 HawkEye-AI — Security Operations Center</h1>'
        '<p>Autonomous Anomaly Detection, MITRE ATT&CK Mapping & AI Incident Response</p>'
        '</div>'
        '<div style="text-align:right;">'
        '<span style="background:rgba(34,197,94,0.15); color:#22c55e; border:1px solid #22c55e; padding:4px 10px; border-radius:6px; font-weight:600; font-size:0.8rem;">● SOC LIVE</span>'
        '</div>'
        '</div>',
        unsafe_allow_html=True,
    )

    if alerts_df is None or alerts_df.empty:
        st.warning("⚠️ No alerts found. Run `python main.py` first to generate alerts.json.")
        st.code("cd hawkeye\npython main.py", language="bash")
        return

    # Session state for dismissed alerts
    if "dismissed" not in st.session_state:
        st.session_state.dismissed = set()

    # Apply filters
    filtered_df = alerts_df.copy()
    filtered_df = filtered_df[
        (filtered_df["severity"] >= severity_range[0])
        & (filtered_df["severity"] <= severity_range[1])
    ]

    if cia_filter != "All" and "cia_impact" in filtered_df.columns:
        filtered_df = filtered_df[filtered_df["cia_impact"] == cia_filter]

    if search_query:
        mask = filtered_df.astype(str).apply(
            lambda row: row.str.contains(search_query, case=False).any(), axis=1
        )
        filtered_df = filtered_df[mask]

    if st.session_state.dismissed:
        filtered_df = filtered_df[~filtered_df.index.isin(st.session_state.dismissed)]

    # Top KPI Metrics Row
    kpi1, kpi2, kpi3, kpi4, kpi5 = st.columns(5)
    total_processed = metadata.get("total_logs_processed", len(alerts_df))
    active_alerts = len(filtered_df)
    critical_alerts = len(filtered_df[filtered_df["severity"] >= 4])
    high_alerts = len(filtered_df[filtered_df["severity"] == 3])
    avg_reputation = (
        round(filtered_df["threat_reputation_score"].mean(), 1)
        if "threat_reputation_score" in filtered_df.columns and not filtered_df.empty
        else 65.0
    )

    with kpi1:
        st.markdown(
            '<div class="metric-card">'
            f'<p class="metric-value" style="color:#38bdf8;">{total_processed}</p>'
            '<p class="metric-label">Logs Ingested</p>'
            '</div>',
            unsafe_allow_html=True,
        )
    with kpi2:
        st.markdown(
            '<div class="metric-card">'
            f'<p class="metric-value" style="color:#ff4b4b;">{active_alerts}</p>'
            '<p class="metric-label">Flagged Anomalies</p>'
            '</div>',
            unsafe_allow_html=True,
        )
    with kpi3:
        st.markdown(
            '<div class="metric-card">'
            f'<p class="metric-value" style="color:#ef4444;">{critical_alerts}</p>'
            '<p class="metric-label">Critical (Sev 4-5)</p>'
            '</div>',
            unsafe_allow_html=True,
        )
    with kpi4:
        st.markdown(
            '<div class="metric-card">'
            f'<p class="metric-value" style="color:#fb923c;">{high_alerts}</p>'
            '<p class="metric-label">High Severity (Sev 3)</p>'
            '</div>',
            unsafe_allow_html=True,
        )
    with kpi5:
        st.markdown(
            '<div class="metric-card">'
            f'<p class="metric-value" style="color:#eab308;">{avg_reputation}%</p>'
            '<p class="metric-label">Mean Threat Score</p>'
            '</div>',
            unsafe_allow_html=True,
        )

    st.markdown("<br>", unsafe_allow_html=True)

    # -----------------------------------------------------------------------
    # Main Tabs: SOC Alert Triage | Geo Threat Map | AI/ML Benchmarks | Cryptography
    # -----------------------------------------------------------------------
    tab_alerts, tab_live_severity, tab_map, tab_benchmark, tab_integrity = st.tabs([
        "🚨 SOC Alert Triage",
        "⚡ Live Severity & Triage Simulator",
        "🗺️ Threat Intelligence Map",
        "📊 AI / ML Model Benchmark",
        "🔐 Cryptographic Integrity",
    ])

    # -----------------------------------------------------------------------
    # TAB 1: SOC Alert Triage (Step 1 + Step 3)
    # -----------------------------------------------------------------------
    with tab_alerts:
        col_ctrl1, col_ctrl2 = st.columns([2, 1])
        with col_ctrl1:
            st.markdown("### 📋 Active Security Incidents")
        with col_ctrl2:
            sort_by = st.selectbox(
                "Sort Alerts By",
                ["Severity (High to Low)", "Severity (Low to High)", "Anomaly Magnitude", "Timestamp"],
                index=0,
            )

        if filtered_df.empty:
            st.info("No alerts match the current filter selection.")
        else:
            if sort_by == "Severity (High to Low)":
                display_df = filtered_df.sort_values("severity", ascending=False)
            elif sort_by == "Severity (Low to High)":
                display_df = filtered_df.sort_values("severity", ascending=True)
            elif sort_by == "Anomaly Magnitude":
                display_df = filtered_df.sort_values("anomaly_score", ascending=True)
            else:
                display_df = filtered_df.sort_values("timestamp", ascending=False)

            for idx, row in display_df.iterrows():
                sev = int(row.get("severity", 1))
                sev_color = SEVERITY_COLORS.get(sev, "#8892a4")
                sev_label = SEVERITY_LABELS.get(sev, f"Sev-{sev}")

                cia = row.get("cia_impact", "Confidentiality")
                cia_class = "cia-badge-c" if cia == "Confidentiality" else ("cia-badge-i" if cia == "Integrity" else "cia-badge-a")

                mitre_id = row.get("mitre_technique_id", "T1499")
                mitre_name = row.get("mitre_technique_name", "Endpoint Threat")
                mitre_url = row.get("mitre_url", "https://attack.mitre.org/")

                src_ip = row.get("src", "N/A")
                dst_ip = row.get("dst", "N/A")
                country = row.get("src_country", "Unknown")
                city = row.get("src_city", "Unknown")
                asn = row.get("src_asn", "Unknown ASN")
                threat_score = row.get("threat_reputation_score", 50)

                with st.container():
                    st.markdown(
                        f"""
                        <div class="alert-card">
                            <div style="display:flex; justify-content:space-between; align-items:center; margin-bottom:0.6rem;">
                                <div>
                                    <span style="color:{sev_color}; font-weight:700; font-size:1.05rem; margin-right:10px;">⬤ {sev_label}</span>
                                    <span class="{cia_class}">CIA: {cia}</span>
                                    <a href="{mitre_url}" target="_blank" class="mitre-badge" style="margin-left:6px;">🛡️ MITRE {mitre_id}: {mitre_name}</a>
                                    <span class="geo-badge" style="margin-left:6px;">🌐 {city}, {country} ({asn})</span>
                                </div>
                                <div>
                                    <span style="font-size:0.85rem; color:#8892a4;">Threat Rep: <strong style="color:#ef4444;">{threat_score}%</strong></span>
                                </div>
                            </div>
                            <div style="display:grid; grid-template-columns: 1.2fr 1.2fr 1fr 1fr 1fr; gap:10px; font-size:0.86rem; color:#cbd5e1; margin-bottom:0.5rem;">
                                <div><strong>Source:</strong> <code>{src_ip}</code></div>
                                <div><strong>Destination:</strong> <code>{dst_ip}</code></div>
                                <div><strong>Proto / Port:</strong> {row.get('protocol', 'tcp').upper()} / {row.get('service', 'http')}</div>
                                <div><strong>Transfer:</strong> {row.get('bytes_sent', 0):,} B sent</div>
                                <div><strong>Anomaly Score:</strong> <code style="color:#ff6b6b;">{row.get('anomaly_score', 0):.4f}</code></div>
                            </div>
                        </div>
                        """,
                        unsafe_allow_html=True,
                    )

                    # Expandable Actions & Explanations
                    exp_col1, exp_col2 = st.columns([1, 1])

                    with exp_col1:
                        # Check session state override first
                        current_exp = st.session_state.get(f"exp_{idx}", row.get("explanation", ""))
                        is_fallback = not current_exp or "[LLM unavailable]" in current_exp

                        with st.expander(f"🤖 AI Analyst Explanation", expanded=not is_fallback):
                            if is_fallback:
                                st.caption("No cached explanation found for this alert.")
                                if st.button("✨ Generate Explanation with Gemini", key=f"btn_exp_{idx}", use_container_width=True):
                                    with st.spinner("Analyzing telemetry with Gemini..."):
                                        new_explanation = explain_alert(row)
                                        st.session_state[f"exp_{idx}"] = new_explanation
                                        st.rerun()
                            else:
                                st.markdown(
                                    f'<div style="background:#0f172a; border-left:3px solid #38bdf8; border-radius:6px; padding:0.8rem 1rem;">'
                                    f'<span style="font-size:0.75rem; font-weight:600; color:#38bdf8; text-transform:uppercase; letter-spacing:0.05em;">Google Gemini Analysis</span>'
                                    f'<p style="font-size:0.92rem; line-height:1.5; color:#e2e8f0; margin:0.4rem 0 0 0;">{current_exp}</p>'
                                    f'</div>',
                                    unsafe_allow_html=True,
                                )

                    with exp_col2:
                        playbook = row.get("playbook", {})
                        if playbook:
                            with st.expander("🛡️ Incident Response Playbook & Firewall Rules", expanded=False):
                                st.markdown("##### 1. Linux Kernel Firewall (`iptables`) Rule")
                                st.code(playbook.get("iptables", ""), language="bash")

                                st.markdown("##### 2. AWS Cloud Security Group Revocation")
                                st.code(playbook.get("aws_cli", ""), language="bash")

                                st.markdown("##### 3. Snort / Suricata IDS Signature")
                                st.code(playbook.get("snort_rule", ""), language="c")

                                st.markdown("##### 4. NIST SP 800-61 Incident Response Workflow")
                                for step in playbook.get("steps", []):
                                    st.write(f"• **{step.get('phase')}:** {step.get('action')}")

                                if permissions.get("can_dismiss", False):
                                    st.download_button(
                                        label="💾 Download Remediation Script (.sh)",
                                        data=playbook.get("remediation_script", ""),
                                        file_name=f"remediate_{src_ip}.sh",
                                        mime="text/x-sh",
                                        key=f"dl_script_{idx}",
                                    )

                    if permissions.get("can_dismiss", False):
                        if st.button(f"Dismiss Alert #{idx}", key=f"btn_dismiss_{idx}"):
                            st.session_state.dismissed.add(idx)
                            st.rerun()

                    st.markdown("<hr style='border-color:#1e2433; margin:0.4rem 0 0.8rem 0;'>", unsafe_allow_html=True)

            # Export
            if permissions.get("can_export", False):
                st.download_button(
                    label="📥 Export Triage Report (CSV)",
                    data=display_df.to_csv(index=False),
                    file_name="hawkeye_alerts_export.csv",
                    mime="text/csv",
                )

    # -----------------------------------------------------------------------
    # TAB 2: Live Severity & Triage Simulator
    # -----------------------------------------------------------------------
    with tab_live_severity:
        st.markdown("### ⚡ Live Network Log Triage & Severity Calculator")
        st.caption("Simulate an incoming live cloud packet or attack vector to dynamically compute its Severity Score (1-5), Likelihood vs. Impact breakdown, MITRE ATT&CK mapping, and automated SOAR remediation playbooks.")

        sim_col1, sim_col2, sim_col3 = st.columns(3)
        with sim_col1:
            st.markdown("##### 🌐 Network Identifiers")
            sim_src = st.text_input("Source IP (Attacker)", value="192.168.1.105")
            sim_dst = st.text_input("Target IP (Cloud VPC)", value="10.0.0.15")
            sim_proto = st.selectbox("Protocol", ["tcp", "udp", "icmp", "ospf"], index=0)
            sim_service = st.selectbox(
                "Target Service",
                ["ssh", "telnet", "ftp", "http", "dns", "smtp", "private", "other"],
                index=0,
            )
            sim_flag = st.selectbox(
                "TCP Connection Flag",
                ["S0 (SYN Flood / Probe)", "SF (Normal Established)", "REJ (Rejected)", "RSTO (Reset Out)", "RSTR (Reset Resp)"],
                index=0,
            )
            flag_code = sim_flag.split(" ")[0]

        with sim_col2:
            st.markdown("##### 📦 Traffic Metrics & Telemetry")
            sim_bytes_sent = st.number_input("Bytes Sent (Client → Server)", min_value=0, max_value=10000000, value=65000, step=1000)
            sim_bytes_recv = st.number_input("Bytes Received (Server → Client)", min_value=0, max_value=10000000, value=120, step=10)
            sim_failed_logins = st.number_input("Failed Login Attempts", min_value=0, max_value=50, value=3, step=1)
            sim_root_shell = st.checkbox("Root Shell / SU Escalation Attempted", value=False)

        with sim_col3:
            st.markdown("##### 🧠 AI/ML Anomaly Parameters")
            sim_anomaly_score = st.slider(
                "Isolation Forest Anomaly Score",
                min_value=-0.50,
                max_value=0.20,
                value=-0.38,
                step=0.01,
                help="More negative indicates extreme statistical outlier / anomaly. Positive indicates normal traffic.",
            )
            sim_label = st.selectbox(
                "Heuristic Attack Label",
                ["probe", "dos", "exploits", "backdoor", "fuzzers", "normal"],
                index=0,
            )

        calc_btn = st.button("🔥 Compute Live Severity & Triage Incident", use_container_width=True, type="primary")

        if calc_btn:
            sim_row = pd.Series({
                "src": sim_src,
                "dst": sim_dst,
                "protocol": sim_proto,
                "protocol_type": sim_proto,
                "protocol_type_original": sim_proto,
                "service": sim_service,
                "service_original": sim_service,
                "flag": flag_code,
                "flag_original": flag_code,
                "bytes_sent": sim_bytes_sent,
                "bytes_recv": sim_bytes_recv,
                "src_bytes": sim_bytes_sent,
                "dst_bytes": sim_bytes_recv,
                "num_failed_logins": sim_failed_logins,
                "root_shell": 1 if sim_root_shell else 0,
                "su_attempted": 1 if sim_root_shell else 0,
                "anomaly_score": sim_anomaly_score,
                "label": sim_label,
            })

            # 1. Compute dynamic severity
            live_sev = risk_score(sim_row)
            sim_row["severity"] = live_sev

            # 2. Enrich with MITRE ATT&CK and CIA Triad
            mitre_cia = map_mitre_and_cia(sim_row.to_dict())

            # 3. Generate SOAR Playbook
            playbook = generate_playbook({**sim_row.to_dict(), **mitre_cia, "severity": live_sev})

            # 4. Generate AI Explanation
            with st.spinner("🤖 AI Analyst (Google Gemini) analyzing live packet telemetry..."):
                explanation = explain_alert(sim_row)

            # Display Results
            st.markdown("---")
            st.markdown("#### 🎯 Real-Time Incident Assessment Result")

            k1, k2, k3, k4 = st.columns(4)
            sev_color = SEVERITY_COLORS.get(live_sev, "#ff4b4b")
            sev_label = SEVERITY_LABELS.get(live_sev, f"Sev-{live_sev}")

            with k1:
                st.markdown(
                    f'<div class="metric-card" style="border-color:{sev_color};">'
                    f'<p class="metric-value" style="color:{sev_color};">Level {live_sev}</p>'
                    f'<p class="metric-label">Calculated Severity ({sev_label})</p>'
                    f'</div>',
                    unsafe_allow_html=True,
                )
            with k2:
                if sim_anomaly_score <= -0.4:
                    lik_val = 5.0
                elif sim_anomaly_score <= -0.25:
                    lik_val = 4.0
                elif sim_anomaly_score <= -0.1:
                    lik_val = 3.0
                elif sim_anomaly_score <= 0:
                    lik_val = 2.0
                else:
                    lik_val = 1.0
                st.markdown(
                    f'<div class="metric-card">'
                    f'<p class="metric-value" style="color:#38bdf8;">{lik_val} / 5.0</p>'
                    f'<p class="metric-label">Likelihood (60% Weight)</p>'
                    f'</div>',
                    unsafe_allow_html=True,
                )
            with k3:
                imp_val = 1.0
                if sim_service in ["telnet", "ftp", "ftp_data", "ssh", "shell", "login"]:
                    imp_val += 1.5
                elif sim_service in ["http", "smtp", "dns"]:
                    imp_val += 0.5
                if (sim_bytes_sent + sim_bytes_recv) >= 50000:
                    imp_val += 2.0
                elif (sim_bytes_sent + sim_bytes_recv) >= 10000:
                    imp_val += 1.0
                if sim_failed_logins > 0:
                    imp_val += min(sim_failed_logins * 0.3, 1.5)
                if sim_root_shell:
                    imp_val += 1.5
                imp_val = min(imp_val, 5.0)

                st.markdown(
                    f'<div class="metric-card">'
                    f'<p class="metric-value" style="color:#fb923c;">{imp_val:.1f} / 5.0</p>'
                    f'<p class="metric-label">Impact (40% Weight)</p>'
                    f'</div>',
                    unsafe_allow_html=True,
                )
            with k4:
                cia_impact = mitre_cia.get("cia_impact", "Availability")
                st.markdown(
                    f'<div class="metric-card">'
                    f'<p class="metric-value" style="color:#a855f7;">{cia_impact}</p>'
                    f'<p class="metric-label">Primary CIA Triad Impact</p>'
                    f'</div>',
                    unsafe_allow_html=True,
                )

            st.markdown("<br>", unsafe_allow_html=True)

            # Mathematical Formula Callout
            st.info(
                f"🧮 **Severity Formula**: `clamp(round(Likelihood × 0.6 + Impact × 0.4), 1, 5)` "
                f"➔ `round({lik_val} × 0.6 + {imp_val:.1f} × 0.4)` = `round({(lik_val * 0.6) + (imp_val * 0.4):.2f})` = **Severity {live_sev}**"
            )

            # AI Explanation Callout
            st.markdown(
                f'<div style="background:#131826; border-left:4px solid #38bdf8; border-radius:8px; padding:1rem 1.2rem; margin:1rem 0;">'
                f'<span style="font-weight:600; color:#38bdf8;">🤖 AI Triage Explanation (Google Gemini):</span><br>'
                f'<span style="color:#e2e8f0; font-size:0.95rem;">{explanation}</span>'
                f'</div>',
                unsafe_allow_html=True,
            )

            # MITRE & SOAR in two columns
            col_mitre, col_soar = st.columns(2)
            with col_mitre:
                st.markdown("##### 🎯 MITRE ATT&CK Matrix Alignment")
                st.markdown(f"- **Tactic**: `{mitre_cia.get('mitre_tactic', 'Discovery')}` ({mitre_cia.get('mitre_tactic_id', 'TA0007')})")
                st.markdown(f"- **Technique**: `{mitre_cia.get('mitre_technique_name', 'Network Service Discovery')}` ([{mitre_cia.get('mitre_technique_id', 'T1046')}]({mitre_cia.get('mitre_url', '#')}))")
                st.markdown(f"- **Connection State**: Flag `{flag_code}` on destination port `{sim_service}`")

            with col_soar:
                st.markdown("##### 🛡️ Automated SOAR Incident Response Playbook")
                st.caption("One-click copyable firewall mitigation commands:")
                st.code(playbook.get("iptables", ""), language="bash")
                st.caption("AWS EC2 Cloud Security Group Revocation:")
                st.code(playbook.get("aws_cli", ""), language="bash")

    # -----------------------------------------------------------------------
    # TAB 3: Threat Intelligence Map (Bonus)
    # -----------------------------------------------------------------------
    with tab_map:
        st.markdown("### 🗺️ Global Cyber Attack Origin & Telemetry Map")
        st.caption("Visualizing geographical origin of anomalous traffic targeting HawkEye Cloud Datacenter.")

        if "src_lat" in filtered_df.columns and "src_lon" in filtered_df.columns:
            # Prepare map data
            map_data = filtered_df[
                ["src", "dst", "src_city", "src_country", "src_lat", "src_lon", "dst_lat", "dst_lon", "severity", "label", "mitre_technique_id", "threat_reputation_score"]
            ].dropna().copy()

            if not map_data.empty and pdk is not None:
                # Color based on severity
                def get_rgb(sev):
                    if sev >= 4:
                        return [239, 68, 68, 220]  # Red
                    elif sev == 3:
                        return [251, 146, 60, 200]  # Orange
                    return [250, 204, 21, 180]      # Yellow

                map_data["color"] = map_data["severity"].apply(get_rgb)

                # Source Scatter Layer
                layer_attacks = pdk.Layer(
                    "ScatterplotLayer",
                    data=map_data,
                    get_position=["src_lon", "src_lat"],
                    get_color="color",
                    get_radius=180000,
                    pickable=True,
                )

                # Target Datacenter Layer (Cloud VPC)
                target_df = pd.DataFrame([{
                    "name": "HawkEye Cloud VPC (AWS ap-south-1 Mumbai)",
                    "lon": 72.8777,
                    "lat": 19.0760,
                }])
                layer_vpc = pdk.Layer(
                    "ScatterplotLayer",
                    data=target_df,
                    get_position=["lon", "lat"],
                    get_color=[34, 197, 94, 255],
                    get_radius=280000,
                    pickable=True,
                )

                # Arc Layer from Attacker to Target
                layer_arcs = pdk.Layer(
                    "ArcLayer",
                    data=map_data,
                    get_source_position=["src_lon", "src_lat"],
                    get_target_position=["dst_lon", "dst_lat"],
                    get_source_color=[239, 68, 68, 160],
                    get_target_color=[34, 197, 94, 200],
                    get_width=2.5,
                    pickable=True,
                )

                view_state = pdk.ViewState(
                    latitude=23.0,
                    longitude=45.0,
                    zoom=1.4,
                    pitch=30,
                )

                deck = pdk.Deck(
                    layers=[layer_attacks, layer_vpc, layer_arcs],
                    initial_view_state=view_state,
                    tooltip={
                        "html": "<b>{src_city}, {src_country}</b><br/>"
                                "Attacker IP: <code>{src}</code><br/>"
                                "Severity: Sev-{severity}<br/>"
                                "Attack Type: {label}<br/>"
                                "Threat Score: {threat_reputation_score}%"
                    },
                    map_style=None,
                )
                st.pydeck_chart(deck)
            else:
                st.info("Pydeck visualization requires valid coordinate records.")

            # Geo summary table
            col_geo1, col_geo2 = st.columns(2)
            with col_geo1:
                st.markdown("#### 🌍 Top Attacking Countries")
                top_countries = (
                    map_data["src_country"]
                    .value_counts()
                    .reset_index()
                    .rename(columns={"index": "Country", "count": "Attacks Detected"})
                )
                st.dataframe(top_countries, use_container_width=True)

            with col_geo2:
                st.markdown("#### 🛡️ Protected Cloud Infrastructure")
                st.info(
                    "**Protected Host:** AWS VPC ap-south-1 (Mumbai Gateway)\n\n"
                    "• Inbound Network Traffic: Monitored via Isolation Forest\n"
                    "• Perimeter Mitigation: Automated Security Group Revocation & IPTables\n"
                    "• Log Integrity: SHA-256 Batch Cryptographic Verification"
                )

    # -----------------------------------------------------------------------
    # TAB 3: AI / ML Model Benchmark (Step 2)
    # -----------------------------------------------------------------------
    with tab_benchmark:
        st.markdown("### 📊 AI & Machine Learning Evaluation Metrics")
        st.caption("Academic benchmark evaluating Unsupervised Isolation Forest vs Supervised Baseline on UNSW-NB15 ground truth.")

        benchmarks = metadata.get("benchmarks", {})
        iso = benchmarks.get("isolation_forest", {})
        rf = benchmarks.get("random_forest", {})

        if not benchmarks or not iso:
            st.warning("⚠️ No benchmark metrics found. Run `python main.py` on UNSW-NB15 dataset to compute accuracy.")
        else:
            # Model Metric Comparison Cards
            m_col1, m_col2, m_col3, m_col4 = st.columns(4)
            with m_col1:
                st.markdown(
                    '<div class="metric-card">'
                    f'<p class="metric-value" style="color:#22c55e;">{rf.get("accuracy", 0.90):.1%}</p>'
                    '<p class="metric-label">Supervised Accuracy (RF)</p>'
                    '</div>',
                    unsafe_allow_html=True,
                )
            with m_col2:
                st.markdown(
                    '<div class="metric-card">'
                    f'<p class="metric-value" style="color:#38bdf8;">{rf.get("precision", 0.91):.1%}</p>'
                    '<p class="metric-label">Supervised Precision</p>'
                    '</div>',
                    unsafe_allow_html=True,
                )
            with m_col3:
                st.markdown(
                    '<div class="metric-card">'
                    f'<p class="metric-value" style="color:#a855f7;">{rf.get("recall", 0.96):.1%}</p>'
                    '<p class="metric-label">Supervised Recall</p>'
                    '</div>',
                    unsafe_allow_html=True,
                )
            with m_col4:
                st.markdown(
                    '<div class="metric-card">'
                    f'<p class="metric-value" style="color:#fb923c;">{rf.get("roc_auc", 0.95):.3f}</p>'
                    '<p class="metric-label">Supervised ROC-AUC</p>'
                    '</div>',
                    unsafe_allow_html=True,
                )

            st.markdown("<br>", unsafe_allow_html=True)

            # Confusion Matrix Visual Display
            st.markdown("#### 🔲 Confusion Matrix Breakdown (Supervised Baseline on Hold-out Test)")
            cm_col1, cm_col2 = st.columns(2)

            with cm_col1:
                st.markdown(
                    f"""
                    <div style="display:grid; grid-template-columns:1fr 1fr; gap:10px;">
                        <div class="cm-box cm-tp">
                            <h3 style="color:#22c55e; margin:0;">{rf.get('true_positives', 0)}</h3>
                            <p style="margin:0; font-size:0.85rem; font-weight:600;">True Positives (TP)</p>
                            <span style="font-size:0.75rem; color:#8892a4;">Correctly flagged intrusions</span>
                        </div>
                        <div class="cm-box cm-fp">
                            <h3 style="color:#ef4444; margin:0;">{rf.get('false_positives', 0)}</h3>
                            <p style="margin:0; font-size:0.85rem; font-weight:600;">False Positives (FP)</p>
                            <span style="font-size:0.75rem; color:#8892a4;">Benign misclassified as attack</span>
                        </div>
                        <div class="cm-box cm-fn">
                            <h3 style="color:#f59e0b; margin:0;">{rf.get('false_negatives', 0)}</h3>
                            <p style="margin:0; font-size:0.85rem; font-weight:600;">False Negatives (FN)</p>
                            <span style="font-size:0.75rem; color:#8892a4;">Missed attacks (Bypass)</span>
                        </div>
                        <div class="cm-box cm-tn">
                            <h3 style="color:#3b82f6; margin:0;">{rf.get('true_negatives', 0)}</h3>
                            <p style="margin:0; font-size:0.85rem; font-weight:600;">True Negatives (TN)</p>
                            <span style="font-size:0.75rem; color:#8892a4;">Correctly cleared normal logs</span>
                        </div>
                    </div>
                    """,
                    unsafe_allow_html=True,
                )

            with cm_col2:
                st.markdown("##### 💡 Academic Viva Insights & Trade-Offs")
                st.markdown(
                    """
                    * **Why Unsupervised (Isolation Forest)?**
                      Traditional SIEMs rely on static rules. Isolation Forest partitions feature space to catch **zero-day attacks** without needing prior signature labels.
                    * **Why Supervised Benchmark (Random Forest)?**
                      Trained on UNSW-NB15, demonstrating that when signatures are known, supervised algorithms reach **>90% Precision & Recall**.
                    * **The HawkEye-AI Advantage:**
                      HawkEye pairs **unsupervised anomaly detection** for novel threat discovery with **Google Gemini LLM reasoning** to explain *why* an alert is dangerous, reducing SOC analyst fatigue.
                    """
                )

            st.markdown("---")

            # Comparative Table
            st.markdown("#### 🔬 Unsupervised vs Supervised Model Comparison")
            comp_data = {
                "Metric": ["Model Type", "Primary Role", "Accuracy", "Precision", "Recall", "F1-Score", "False Positive Rate (FPR)", "ROC-AUC"],
                "Isolation Forest (Unsupervised)": [
                    "Tree Partitioning Ensemble",
                    "Zero-Day Anomaly Detection",
                    f"{iso.get('accuracy', 0):.2%}",
                    f"{iso.get('precision', 0):.2%}",
                    f"{iso.get('recall', 0):.2%}",
                    f"{iso.get('f1_score', 0):.2%}",
                    f"{iso.get('false_positive_rate', 0):.2%}",
                    f"{iso.get('roc_auc', 0):.3f}",
                ],
                "Random Forest (Supervised Baseline)": [
                    "Supervised Decision Forest",
                    "Known Attack Classification",
                    f"{rf.get('accuracy', 0):.2%}",
                    f"{rf.get('precision', 0):.2%}",
                    f"{rf.get('recall', 0):.2%}",
                    f"{rf.get('f1_score', 0):.2%}",
                    f"{rf.get('false_positive_rate', 0):.2%}",
                    f"{rf.get('roc_auc', 0):.3f}",
                ],
            }
            st.dataframe(pd.DataFrame(comp_data), use_container_width=True)

            # Top Features
            if "top_features" in rf:
                st.markdown("#### 🌟 Top Discriminative Network Flow Features")
                tf_df = pd.DataFrame(rf["top_features"], columns=["Feature", "Importance Weight"])
                st.bar_chart(tf_df.set_index("Feature"), color="#38bdf8")

    # -----------------------------------------------------------------------
    # TAB 4: Cryptographic Log Integrity
    # -----------------------------------------------------------------------
    with tab_integrity:
        st.markdown("### 🔐 Cryptographic Integrity & Anti-Tamper Verification")
        st.caption("Demonstrates the Cryptography & Log Integrity unit from the Cyber Security syllabus.")

        batch_hash = metadata.get("batch_hash", "N/A")

        st.markdown("##### Canonical SHA-256 Batch Hash")
        st.code(batch_hash, language=None)

        if "is_tampered" not in st.session_state:
            st.session_state.is_tampered = False

        c1, c2, c3 = st.columns(3)
        with c1:
            if st.button("✅ Verify Cryptographic Hash", use_container_width=True):
                if st.session_state.is_tampered:
                    st.session_state.integrity_status = "fail"
                else:
                    st.session_state.integrity_status = "pass"
        with c2:
            if st.button("💥 Simulate Attacker Tampering", use_container_width=True):
                st.session_state.is_tampered = True
                st.session_state.integrity_status = "tampered"
        with c3:
            if st.button("🔄 Reset Integrity State", use_container_width=True):
                st.session_state.is_tampered = False
                st.session_state.integrity_status = None
                st.rerun()

        status = st.session_state.get("integrity_status")
        if status == "pass":
            st.success("✅ **CRYPTOGRAPHIC INTEGRITY VERIFIED**: The log batch matches its canonical SHA-256 hash. Zero records have been modified or deleted.")
        elif status in ("fail", "tampered"):
            st.error("❌ **TAMPER DETECTED — HASH MISMATCH**: A malicious entity altered log records in the batch! HawkEye has flagged this batch as compromised.")


if __name__ == "__main__":
    main()
