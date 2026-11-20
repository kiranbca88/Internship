"""
2_threat_intelligence.py
------------------------
Threat & Vector Intelligence: Detailed behavioral analysis of attack types,
cross-departmental vector heatmaps, risk matrix scatter plots, and tactical playbooks.
"""

import streamlit as st
import pandas as pd
import plotly.express as px
import plotly.graph_objects as go

from dashboard.common import (
    load_data,
    apply_custom_css,
    render_sidebar_filters,
    SEVERITY_PALETTE
)

apply_custom_css()

st.markdown('<div class="main-header">🎯 Threat & Attack Vector Intelligence</div>', unsafe_allow_html=True)
st.markdown('<div class="sub-header">Deep-dive into threat mechanics, risk matrix positioning, cross-departmental heatmaps, and mitigation playbooks</div>', unsafe_allow_html=True)

df_raw = load_data()
if df_raw is None:
    st.error("🚨 Processed data not found.")
    st.stop()

filtered_df = render_sidebar_filters(df_raw)
if filtered_df.empty:
    st.warning("⚠️ No incidents match your selected filters.")
    st.stop()

# High-level Vector KPIs
vector_group = filtered_df.groupby("Incident_Type").agg(
    total=("Incident_ID", "count"),
    critical=("Severity", lambda s: (s == "Critical").sum()),
    high=("Severity", lambda s: (s == "High").sum()),
    resolved=("Status", lambda s: (s == "Resolved").sum()),
    avg_mttr=("Resolution_Hours", "mean")
).reset_index()

top_vector = vector_group.sort_values(by="total", ascending=False).iloc[0]["Incident_Type"]
longest_mttr_row = vector_group.dropna(subset=["avg_mttr"]).sort_values(by="avg_mttr", ascending=False).iloc[0]
most_critical_row = vector_group.sort_values(by="critical", ascending=False).iloc[0]

c1, c2, c3, c4 = st.columns(4)
with c1:
    st.markdown(f"""
    <div class="kpi-card">
        <div class="kpi-title">Dominant Threat Vector</div>
        <div class="kpi-value" style="font-size: 1.45rem; color: #1F4E78;">{top_vector}</div>
        <div class="kpi-sub">{vector_group['total'].max()} Incidents Logged</div>
    </div>
    """, unsafe_allow_html=True)

with c2:
    st.markdown(f"""
    <div class="kpi-card">
        <div class="kpi-title">Highest MTTR Threat</div>
        <div class="kpi-value" style="font-size: 1.45rem; color: #D9534F;">{longest_mttr_row['Incident_Type']}</div>
        <div class="kpi-sub">Avg MTTR: {round(longest_mttr_row['avg_mttr'], 1)} Hours</div>
    </div>
    """, unsafe_allow_html=True)

with c3:
    st.markdown(f"""
    <div class="kpi-card">
        <div class="kpi-title">Top Critical Threat</div>
        <div class="kpi-value" style="font-size: 1.45rem; color: #DC2626;">{most_critical_row['Incident_Type']}</div>
        <div class="kpi-sub">{int(most_critical_row['critical'])} Critical Escalations</div>
    </div>
    """, unsafe_allow_html=True)

with c4:
    st.markdown(f"""
    <div class="kpi-card">
        <div class="kpi-title">Threat Diversity</div>
        <div class="kpi-value" style="font-size: 1.45rem; color: #059669;">{len(vector_group)}</div>
        <div class="kpi-sub">Active Threat Categories</div>
    </div>
    """, unsafe_allow_html=True)

st.markdown("<br>", unsafe_allow_html=True)

# Row 1: Threat Risk Matrix & Attack Distribution
r1_col1, r1_col2 = st.columns([1.4, 1.0])

with r1_col1:
    st.subheader("🌐 Threat Risk Matrix (Frequency vs. MTTR Duration)")
    
    # Calculate bubble sizing
    vector_group["bubble_size"] = vector_group["critical"] + vector_group["high"] + 5
    vector_group["avg_mttr_display"] = vector_group["avg_mttr"].round(1).fillna(0)

    fig_matrix = px.scatter(
        vector_group,
        x="total",
        y="avg_mttr",
        size="bubble_size",
        color="Incident_Type",
        text="Incident_Type",
        hover_data={"total": True, "avg_mttr_display": True, "critical": True, "high": True, "bubble_size": False},
        labels={"total": "Total Incident Frequency", "avg_mttr": "Average MTTR (Hours)"}
    )
    fig_matrix.update_traces(textposition="top center", marker=dict(opacity=0.85, line=dict(width=1, color="DarkSlateGrey")))
    fig_matrix.update_layout(
        xaxis_title="Incident Frequency (Operational Volume)",
        yaxis_title="Mean Time to Resolve - MTTR (Hours)",
        showlegend=False,
        margin=dict(l=20, r=20, t=30, b=20)
    )
    st.plotly_chart(fig_matrix, width="stretch")

with r1_col2:
    st.subheader("🔥 Threat Severity Composition")
    vector_sev = filtered_df.groupby(["Incident_Type", "Severity"]).size().reset_index(name="Count")
    fig_vsev = px.bar(
        vector_sev,
        x="Incident_Type",
        y="Count",
        color="Severity",
        color_discrete_map=SEVERITY_PALETTE,
        barmode="stack"
    )
    fig_vsev.update_layout(
        xaxis_title="",
        yaxis_title="Incident Count",
        margin=dict(l=20, r=20, t=30, b=20),
        legend=dict(orientation="h", yanchor="bottom", y=1.02, xanchor="right", x=1)
    )
    st.plotly_chart(fig_vsev, width="stretch")

# Row 2: Cross-Tabulation Heatmap (Attack Vector vs Department)
st.subheader("🗺️ Cross-Departmental Threat Exposure Heatmap")
pivot_dept_type = pd.crosstab(filtered_df["Department"], filtered_df["Incident_Type"])

fig_heat = px.imshow(
    pivot_dept_type,
    text_auto=True,
    aspect="auto",
    color_continuous_scale="Reds",
    labels=dict(x="Attack Vector", y="Department", color="Incident Count")
)
fig_heat.update_layout(
    margin=dict(l=20, r=20, t=30, b=20),
    xaxis_title="Threat Vector",
    yaxis_title="Impacted Department"
)
st.plotly_chart(fig_heat, width="stretch")

# Row 3: Tactical SOC Mitigation Playbooks
st.subheader("🛡️ Tactical Threat Mitigation Playbooks")
playbooks = {
    "Phishing": {
        "threat": "Social engineering credential harvesting and malicious payload links targeting users.",
        "containment": "Automated email quarantine, URL detonation analysis, password reset, and active token revocation.",
        "soc_rule": "Enforce FIDO2 MFA hardware keys and automated Mail Transfer Agent (MTA) attachment sandboxing."
    },
    "Malware": {
        "threat": "Trojan downloaders, infostealers, and cryptominers executed on employee endpoints.",
        "containment": "Isolate endpoint via EDR agent, preserve volatile memory for forensics, and wipe infection artifacts.",
        "soc_rule": "Application whitelisting (AppLocker), PowerShell Constrained Language Mode, and USB block policy."
    },
    "Ransomware": {
        "threat": "High-impact lateral spreading payloads encrypting local drives and shared network storage.",
        "containment": "Immediate network isolation, kill shared drive SMB connections, and initiate immutable backup recovery.",
        "soc_rule": "Zero-trust microsegmentation, disable legacy SMBv1, and enforce multi-signature backup deletion protection."
    },
    "Suspicious Login": {
        "threat": "Credential stuffing, impossible travel anomalies, or brute-force against administrative portals.",
        "containment": "Terminate active sessions, enforce temporary account lockout, and analyze IP reputation / ASN.",
        "soc_rule": "Conditional access policies enforcing geolocation geofencing and risk-based step-up authentication."
    },
    "Data Leak": {
        "threat": "Unencrypted outbound transfers of sensitive PII, customer records, or misconfigured public cloud storage.",
        "containment": "Revoke public cloud bucket permissions, quarantine outbound DLP messages, and conduct access audit.",
        "soc_rule": "Automated Cloud Security Posture Management (CSPM) and egress DLP filtering on email gateways."
    },
    "Unauthorized Access": {
        "threat": "Privilege escalation attempts, unauthorized repository access, or lingering terminated contractor tokens.",
        "containment": "Deprovision compromised roles, revoke Kerberos tickets / access badges, and audit Active Directory logs.",
        "soc_rule": "Automated HR-to-IAM offboarding pipeline and quarterly Privileged Access Management (PAM) recertification."
    }
}

p_col1, p_col2 = st.columns(2)
for idx, (v_name, p_data) in enumerate(playbooks.items()):
    col = p_col1 if idx % 2 == 0 else p_col2
    with col:
        with st.expander(f"📌 Playbook: {v_name}", expanded=False):
            st.markdown(f"**Threat Mechanics:** {p_data['threat']}")
            st.markdown(f"**Immediate Containment Protocol:** {p_data['containment']}")
            st.markdown(f"**Long-term SOC Hardening Rule:** {p_data['soc_rule']}")
