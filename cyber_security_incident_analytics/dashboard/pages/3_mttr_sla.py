"""
3_mttr_sla.py
-------------
SLA Compliance & MTTR Resolution Analytics: Statistical distributions,
SLA breach detection, box plots, and outlier triage investigations.
"""

import streamlit as st
import pandas as pd
import numpy as np
import plotly.express as px
import plotly.graph_objects as go

from dashboard.common import (
    load_data,
    apply_custom_css,
    render_sidebar_filters,
    SEVERITY_PALETTE
)

apply_custom_css()

st.markdown('<div class="main-header">⏱️ SLA Compliance & Resolution Velocity</div>', unsafe_allow_html=True)
st.markdown('<div class="sub-header">Statistical MTTR distributions, SLA breach monitoring, box-whisker dispersion, and incident backlog aging</div>', unsafe_allow_html=True)

df_raw = load_data()
if df_raw is None:
    st.error("🚨 Processed data not found.")
    st.stop()

filtered_df = render_sidebar_filters(df_raw)
if filtered_df.empty:
    st.warning("⚠️ No incidents match your selected filters.")
    st.stop()

# SLA Definitions: Critical <= 24 hrs, High <= 48 hrs, Medium <= 72 hrs, Low <= 96 hrs
SLA_LIMITS = {
    "Critical": 24.0,
    "High": 48.0,
    "Medium": 72.0,
    "Low": 96.0
}

resolved_df = filtered_df[filtered_df["Status"] == "Resolved"].copy()

if resolved_df.empty:
    st.info("No resolved incidents exist under the current filter selection to compute MTTR or SLA performance.")
    st.stop()

# Compute SLA breach indicator
def check_sla(row):
    limit = SLA_LIMITS.get(row["Severity"], 72.0)
    return "Breached" if row["Resolution_Hours"] > limit else "Compliant"

resolved_df["SLA_Status"] = resolved_df.apply(check_sla, axis=1)

total_resolved = len(resolved_df)
compliant_count = int((resolved_df["SLA_Status"] == "Compliant").sum())
breached_count = int((resolved_df["SLA_Status"] == "Breached").sum())
sla_compliance_rate = round((compliant_count / total_resolved) * 100, 1)

crit_resolved = resolved_df[resolved_df["Severity"] == "Critical"]
crit_breach = int((crit_resolved["SLA_Status"] == "Breached").sum()) if len(crit_resolved) > 0 else 0
crit_compliance_rate = round(((len(crit_resolved) - crit_breach) / len(crit_resolved)) * 100, 1) if len(crit_resolved) > 0 else 100.0

overall_mean_mttr = round(resolved_df["Resolution_Hours"].mean(), 1)
overall_median_mttr = round(resolved_df["Resolution_Hours"].median(), 1)

# KPI Row
s1, s2, s3, s4 = st.columns(4)
with s1:
    st.markdown(f"""
    <div class="kpi-card">
        <div class="kpi-title">Overall SLA Compliance</div>
        <div class="kpi-value" style="color: {'#16A34A' if sla_compliance_rate >= 80 else '#DC2626'};">{sla_compliance_rate}%</div>
        <div class="kpi-sub">{compliant_count} of {total_resolved} within SLA</div>
    </div>
    """, unsafe_allow_html=True)

with s2:
    st.markdown(f"""
    <div class="kpi-card">
        <div class="kpi-title">Critical SLA (≤ 24 hrs)</div>
        <div class="kpi-value" style="color: {'#16A34A' if crit_compliance_rate >= 75 else '#DC2626'};">{crit_compliance_rate}%</div>
        <div class="kpi-sub">{crit_breach} Critical Breach(es)</div>
    </div>
    """, unsafe_allow_html=True)

with s3:
    st.markdown(f"""
    <div class="kpi-card">
        <div class="kpi-title">Mean MTTR (Average)</div>
        <div class="kpi-value">{overall_mean_mttr} hrs</div>
        <div class="kpi-sub">Mean Time to Resolve</div>
    </div>
    """, unsafe_allow_html=True)

with s4:
    st.markdown(f"""
    <div class="kpi-card">
        <div class="kpi-title">Median MTTR (Robust)</div>
        <div class="kpi-value">{overall_median_mttr} hrs</div>
        <div class="kpi-sub">50th Percentile Duration</div>
    </div>
    """, unsafe_allow_html=True)

st.markdown("<br>", unsafe_allow_html=True)

# Row 1: Box Plot & Distribution
r1_col1, r1_col2 = st.columns([1.2, 1.2])

with r1_col1:
    st.subheader("📦 Resolution Duration Dispersion (Box & Whisker)")
    fig_box = px.box(
        resolved_df,
        x="Severity",
        y="Resolution_Hours",
        color="Severity",
        color_discrete_map=SEVERITY_PALETTE,
        category_orders={"Severity": ["Critical", "High", "Medium", "Low"]},
        points="all"
    )
    fig_box.update_layout(
        xaxis_title="Severity Tier",
        yaxis_title="Resolution Duration (Hours)",
        showlegend=False,
        margin=dict(l=20, r=20, t=30, b=20)
    )
    st.plotly_chart(fig_box, width="stretch")

with r1_col2:
    st.subheader("📊 MTTR Density & Frequency Distribution")
    fig_hist = px.histogram(
        resolved_df,
        x="Resolution_Hours",
        nbins=25,
        color="Severity",
        color_discrete_map=SEVERITY_PALETTE,
        marginal="rug"
    )
    fig_hist.update_layout(
        xaxis_title="Resolution Hours",
        yaxis_title="Incident Count",
        margin=dict(l=20, r=20, t=30, b=20),
        legend=dict(orientation="h", yanchor="bottom", y=1.02, xanchor="right", x=1)
    )
    st.plotly_chart(fig_hist, width="stretch")

# Row 2: SLA Status Breakdown across Threat Vectors
st.subheader("🎯 SLA Compliance Breakdown by Threat Vector")
sla_type = pd.crosstab(resolved_df["Incident_Type"], resolved_df["SLA_Status"]).reset_index()
if "Breached" not in sla_type.columns:
    sla_type["Breached"] = 0
if "Compliant" not in sla_type.columns:
    sla_type["Compliant"] = 0

fig_sla_type = go.Figure()
fig_sla_type.add_trace(go.Bar(
    name="Compliant",
    x=sla_type["Incident_Type"],
    y=sla_type["Compliant"],
    marker_color="#22C55E"
))
fig_sla_type.add_trace(go.Bar(
    name="Breached",
    x=sla_type["Incident_Type"],
    y=sla_type["Breached"],
    marker_color="#EF4444"
))
fig_sla_type.update_layout(
    barmode="stack",
    yaxis_title="Resolved Incidents",
    xaxis_title="",
    margin=dict(l=20, r=20, t=30, b=20),
    legend=dict(orientation="h", yanchor="bottom", y=1.02, xanchor="right", x=1)
)
st.plotly_chart(fig_sla_type, width="stretch")

# Row 3: Outlier Cases Table
st.subheader("🚨 Incident Investigation: Longest Resolution Outliers")
st.markdown("Cases taking greater than 30 hours to remediate often reveal complex digital forensics, multi-team dependencies, or external contractor engagements:")

outliers = resolved_df.sort_values(by="Resolution_Hours", ascending=False).head(8)
st.dataframe(
    outliers[[
        "Incident_ID",
        "Incident_Date",
        "Incident_Type",
        "Severity",
        "Department",
        "Resolution_Hours",
        "SLA_Status",
        "Description"
    ]],
    width="stretch",
    hide_index=True
)
