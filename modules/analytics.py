"""
modules/analytics.py
====================
Plotly visualizations for Enterprise Hacker Matrix SOC Command Center.
Deep Black • Dark Emerald • Neon Green • Cyan Cybersecurity Analytics.
"""

import pandas as pd
import numpy as np
import plotly.express as px
import plotly.graph_objects as go
from modules.data_processing import SEVERITY_COLORS, STATUS_COLORS, PLOTLY_LAYOUT

# Matrix Green & Cyan Scales
MATRIX_SCALE_GREEN = ["#02120C", "#00A86B", "#00FF88"]
MATRIX_SCALE_CYAN = ["#021015", "#00838F", "#00E5FF"]
MATRIX_SCALE_PURPLE = ["#13091B", "#7C3AED", "#C084FC"]


# ==============================================================================
# SECTION: ATTACK & SEVERITY ANALYTICS
# ==============================================================================

def create_attack_type_chart(df: pd.DataFrame) -> go.Figure:
    """Horizontal bar chart ranking attack types by volume with percentage share."""
    counts = df["Attack_Type"].value_counts().reset_index()
    counts.columns = ["Attack_Type", "Count"]
    counts["Percentage"] = (counts["Count"] / counts["Count"].sum() * 100).round(1)
    counts = counts.sort_values(by="Count", ascending=True)

    fig = px.bar(
        counts,
        x="Count",
        y="Attack_Type",
        orientation="h",
        text=counts["Percentage"].apply(lambda x: f" {x}%"),
        color="Count",
        color_continuous_scale=MATRIX_SCALE_GREEN,
        title="<b>Attack Type Volume & Frequency Distribution</b>"
    )
    fig.update_layout(**PLOTLY_LAYOUT)
    fig.update_layout(
        coloraxis_showscale=False,
        xaxis_title="Number of Incidents",
        yaxis_title="Attack Type",
        height=380
    )
    fig.update_traces(textposition="outside", marker_line_color="#00FF88", marker_line_width=1)
    return fig


def create_severity_donut(df: pd.DataFrame) -> go.Figure:
    """Matrix Donut Chart showing incident severity breakdown."""
    sev_counts = df["Severity"].value_counts().reindex(["Critical", "High", "Medium", "Low"]).fillna(0).reset_index()
    sev_counts.columns = ["Severity", "Count"]

    fig = px.pie(
        sev_counts,
        values="Count",
        names="Severity",
        hole=0.64,
        color="Severity",
        color_discrete_map=SEVERITY_COLORS,
        title="<b>Incident Severity Distribution</b>"
    )
    fig.update_layout(**PLOTLY_LAYOUT)
    fig.update_layout(
        height=380,
        legend=dict(orientation="h", yanchor="bottom", y=-0.15, xanchor="center", x=0.5),
        annotations=[dict(text="<b>SEVERITY</b>", x=0.5, y=0.5, font_size=13, font_color="#00FF88", showarrow=False)]
    )
    fig.update_traces(textinfo="percent+label", hoverinfo="label+value+percent", marker=dict(line=dict(color="#020807", width=2)))
    return fig


def create_attack_vector_chart(df: pd.DataFrame) -> go.Figure:
    """Ranked bar chart of attack vectors colored by matrix cyan glow."""
    vec_counts = df["Attack_Vector"].value_counts().reset_index()
    vec_counts.columns = ["Attack_Vector", "Count"]
    vec_counts = vec_counts.sort_values(by="Count", ascending=True)

    fig = px.bar(
        vec_counts,
        x="Count",
        y="Attack_Vector",
        orientation="h",
        color="Count",
        color_continuous_scale=MATRIX_SCALE_CYAN,
        title="<b>Primary Infiltration Attack Vectors</b>"
    )
    fig.update_layout(**PLOTLY_LAYOUT)
    fig.update_layout(coloraxis_showscale=False, xaxis_title="Incident Count", yaxis_title="Infiltration Vector", height=380)
    fig.update_traces(marker_line_color="#00E5FF", marker_line_width=1)
    return fig


def create_root_cause_chart(df: pd.DataFrame) -> go.Figure:
    """Pareto-style analysis of root causes."""
    rc_counts = df["Root_Cause"].value_counts().reset_index()
    rc_counts.columns = ["Root_Cause", "Count"]
    rc_counts["Cumulative_Pct"] = (rc_counts["Count"].cumsum() / rc_counts["Count"].sum() * 100).round(1)

    fig = go.Figure()
    fig.add_trace(go.Bar(
        x=rc_counts["Root_Cause"],
        y=rc_counts["Count"],
        name="Incident Count",
        marker_color="#00A86B",
        marker_line=dict(color="#00FF88", width=1)
    ))
    fig.add_trace(go.Scatter(
        x=rc_counts["Root_Cause"],
        y=rc_counts["Cumulative_Pct"],
        name="Cumulative %",
        yaxis="y2",
        mode="lines+markers",
        line=dict(color="#FF1744", width=2.5),
        marker=dict(size=7, color="#FF1744")
    ))
    fig.update_layout(**PLOTLY_LAYOUT)
    fig.update_layout(
        title="<b>Root Cause Analysis & Cumulative Impact</b>",
        xaxis_title="Underlying Root Cause",
        yaxis=dict(title="Incidents", gridcolor="rgba(0, 255, 136, 0.08)"),
        yaxis2=dict(title="Cumulative %", overlaying="y", side="right", range=[0, 105], showgrid=False),
        legend=dict(orientation="h", yanchor="bottom", y=1.02, xanchor="right", x=1),
        height=380
    )
    return fig


def create_threat_actor_chart(df: pd.DataFrame) -> go.Figure:
    """Threat actor adversary matrix: incident volume vs average financial impact."""
    grouped = df.groupby("Threat_Actor").agg(
        Count=("Incident_ID", "count"),
        Avg_Loss=("Financial_Loss_USD", "mean"),
        Critical_Count=("Severity", lambda x: (x == "Critical").sum())
    ).reset_index().sort_values(by="Count", ascending=False)

    grouped["Avg_Loss_K"] = (grouped["Avg_Loss"] / 1000).round(1)

    fig = px.scatter(
        grouped,
        x="Count",
        y="Avg_Loss_K",
        size="Critical_Count",
        color="Critical_Count",
        text="Threat_Actor",
        color_continuous_scale="Viridis",
        title="<b>Adversary Matrix: Threat Actor Volume vs Avg Financial Impact ($K)</b>"
    )
    fig.update_layout(**PLOTLY_LAYOUT)
    fig.update_layout(
        xaxis_title="Incident Frequency",
        yaxis_title="Average Financial Loss ($K)",
        coloraxis_colorbar_title="Critical Threats",
        height=400
    )
    fig.update_traces(textposition="top center", marker=dict(line=dict(color="#00FF88", width=1.5)))
    return fig


def create_department_chart(df: pd.DataFrame) -> go.Figure:
    """Department incident count by severity breakdown."""
    dept_cross = df.groupby(["Department", "Severity"]).size().reset_index(name="Count")
    
    fig = px.bar(
        dept_cross,
        x="Department",
        y="Count",
        color="Severity",
        color_discrete_map=SEVERITY_COLORS,
        barmode="stack",
        title="<b>Departmental Compromise & Severity Exposure</b>"
    )
    fig.update_layout(**PLOTLY_LAYOUT)
    fig.update_layout(
        xaxis_title="Organizational Department",
        yaxis_title="Incident Count",
        legend=dict(orientation="h", yanchor="bottom", y=1.02, xanchor="right", x=1),
        height=380
    )
    return fig


def create_location_chart(df: pd.DataFrame) -> go.Figure:
    """Location-wise incidents across global SOC nodes."""
    loc_counts = df["Location"].value_counts().reset_index()
    loc_counts.columns = ["Location", "Count"]

    fig = px.bar(
        loc_counts,
        x="Location",
        y="Count",
        color="Count",
        color_continuous_scale=MATRIX_SCALE_GREEN,
        title="<b>Global SOC Node Incident Distribution</b>"
    )
    fig.update_layout(**PLOTLY_LAYOUT)
    fig.update_layout(coloraxis_showscale=False, xaxis_title="Global Region / Node", yaxis_title="Incidents", height=380)
    fig.update_traces(marker_line_color="#00FF88", marker_line_width=1)
    return fig


def create_asset_compromise_chart(df: pd.DataFrame) -> go.Figure:
    """Compromised asset breakdown by volume."""
    asset_counts = df["Affected_Asset"].value_counts().reset_index()
    asset_counts.columns = ["Affected_Asset", "Count"]
    asset_counts = asset_counts.sort_values(by="Count", ascending=True)

    fig = px.bar(
        asset_counts,
        x="Count",
        y="Affected_Asset",
        orientation="h",
        color="Count",
        color_continuous_scale=MATRIX_SCALE_CYAN,
        title="<b>Infrastructure Target & Asset Compromise Volume</b>"
    )
    fig.update_layout(**PLOTLY_LAYOUT)
    fig.update_layout(coloraxis_showscale=False, xaxis_title="Incidents Logged", yaxis_title="Asset Class", height=380)
    fig.update_traces(marker_line_color="#00E5FF", marker_line_width=1)
    return fig


def create_mfa_impact_chart(df: pd.DataFrame) -> go.Figure:
    """MFA configuration defense efficacy by severity."""
    col_name = "Multi_Factor_Auth" if "Multi_Factor_Auth" in df.columns else "Multi_Factor_Authentication"
    mfa_comp = df.groupby([col_name, "Severity"]).size().reset_index(name="Count")

    fig = px.bar(
        mfa_comp,
        x=col_name,
        y="Count",
        color="Severity",
        color_discrete_map=SEVERITY_COLORS,
        barmode="stack",
        title="<b>Multi-Factor Authentication (MFA) Defense Efficacy</b>"
    )
    fig.update_layout(**PLOTLY_LAYOUT)
    fig.update_layout(
        xaxis_title="MFA Configuration Status",
        yaxis_title="Incident Count",
        legend=dict(orientation="h", yanchor="bottom", y=1.02, xanchor="right", x=1),
        height=380
    )
    return fig


def create_exfiltration_bubble_chart(df: pd.DataFrame) -> go.Figure:
    """Data exfiltration impact: Financial Loss vs Records Affected."""
    col_exfil = "Data_Exfiltrated" if "Data_Exfiltrated" in df.columns else "Data_Exfiltration"
    sample = df.sample(min(800, len(df)), random_state=42)

    fig = px.scatter(
        sample,
        x="Records_Affected",
        y="Financial_Loss_USD",
        color=col_exfil,
        color_discrete_map={"Yes": "#FF1744", "No": "#00FF88"},
        opacity=0.75,
        hover_data=["Incident_ID", "Attack_Type", "Severity"],
        title="<b>Data Exfiltration Risk: Records Compromised vs Financial Loss ($)</b>"
    )
    fig.update_layout(**PLOTLY_LAYOUT)
    fig.update_layout(
        xaxis_title="Records Compromised",
        yaxis_title="Financial Loss ($ USD)",
        legend=dict(orientation="h", yanchor="bottom", y=1.02, xanchor="right", x=1),
        height=400
    )
    return fig


def create_matrix_heatmap(df: pd.DataFrame) -> go.Figure:
    """Attack Type vs Affected Asset cross-tabulation heatmap."""
    cross = pd.crosstab(df["Attack_Type"], df["Affected_Asset"])
    fig = px.imshow(
        cross,
        labels=dict(x="Affected Asset", y="Attack Type", color="Incidents"),
        color_continuous_scale="Greens",
        title="<b>Attack Type vs Affected Infrastructure Heatmap</b>"
    )
    fig.update_layout(**PLOTLY_LAYOUT)
    fig.update_layout(height=420)
    return fig


# ==============================================================================
# SECTION: FIVE-YEAR LONGITUDINAL COMPARISON (2021 - 2025)
# ==============================================================================

def create_year_incident_trend(comparison_df: pd.DataFrame) -> go.Figure:
    """Year-wise incident count with YoY trajectory overlay."""
    fig = go.Figure()
    fig.add_trace(go.Bar(
        x=comparison_df["Year"].astype(str),
        y=comparison_df["Total Incidents"],
        name="Total Incidents",
        marker_color="#00FF88",
        marker_line=dict(color="#00A86B", width=1.5)
    ))
    fig.add_trace(go.Scatter(
        x=comparison_df["Year"].astype(str),
        y=comparison_df["Total Incidents"],
        name="Trend Trajectory",
        mode="lines+markers+text",
        text=comparison_df["Incident YoY (%)"].apply(lambda x: f"{'+' if x>0 else ''}{x}% YoY" if x != 0 else "Base"),
        textposition="top center",
        line=dict(color="#00E5FF", width=3, dash="dot"),
        marker=dict(size=9, color="#00E5FF")
    ))
    fig.update_layout(**PLOTLY_LAYOUT)
    fig.update_layout(
        title="<b>Year-Wise Incident Count & YoY Growth (2021–2025)</b>",
        xaxis_title="Calendar Year",
        yaxis_title="Total Incidents",
        legend=dict(orientation="h", yanchor="bottom", y=1.02, xanchor="right", x=1),
        height=380
    )
    return fig


def create_year_financial_trend(comparison_df: pd.DataFrame) -> go.Figure:
    """Year-wise financial loss in millions of USD."""
    fig = px.bar(
        comparison_df,
        x=comparison_df["Year"].astype(str),
        y="Financial Loss ($M)",
        text=comparison_df["Financial Loss ($M)"].apply(lambda x: f"${x:.2f}M"),
        color="Financial Loss ($M)",
        color_continuous_scale=MATRIX_SCALE_GREEN,
        title="<b>Annual Financial Loss Impact (2021–2025)</b>"
    )
    fig.update_layout(**PLOTLY_LAYOUT)
    fig.update_layout(coloraxis_showscale=False, xaxis_title="Year", yaxis_title="Total Loss ($ Millions USD)", height=380)
    fig.update_traces(textposition="outside", marker_line_color="#00FF88", marker_line_width=1)
    return fig


def create_year_critical_trend(comparison_df: pd.DataFrame) -> go.Figure:
    """Year-wise critical incidents escalation line and area chart."""
    fig = px.area(
        comparison_df,
        x=comparison_df["Year"].astype(str),
        y="Critical Incidents",
        markers=True,
        title="<b>Annual Critical Severity Threat Escalation</b>"
    )
    fig.update_layout(**PLOTLY_LAYOUT)
    fig.update_layout(xaxis_title="Year", yaxis_title="Critical Incident Count", height=380)
    fig.update_traces(
        line_color="#FF1744",
        line_width=3,
        fillcolor="rgba(255, 23, 68, 0.2)",
        marker=dict(size=8, color="#FF1744", line=dict(color="#FFFFFF", width=1.5))
    )
    return fig


def create_attack_trends_multiline(df: pd.DataFrame) -> go.Figure:
    """Evolution of top attack types over the 5-year timeline."""
    top_attacks = df["Attack_Type"].value_counts().head(5).index.tolist()
    filtered = df[df["Attack_Type"].isin(top_attacks)]
    yearly_attack = filtered.groupby(["Year", "Attack_Type"]).size().reset_index(name="Count")

    fig = px.line(
        yearly_attack,
        x=yearly_attack["Year"].astype(str),
        y="Count",
        color="Attack_Type",
        markers=True,
        title="<b>Top 5 Attack Vector Evolution Over 5 Years (2021–2025)</b>",
        color_discrete_sequence=["#00FF88", "#00E5FF", "#FF1744", "#FF9100", "#C084FC"]
    )
    fig.update_layout(**PLOTLY_LAYOUT)
    fig.update_layout(
        xaxis_title="Year",
        yaxis_title="Annual Incidents",
        legend=dict(orientation="h", yanchor="bottom", y=1.02, xanchor="right", x=1),
        height=380
    )
    return fig


def create_sla_comparison_chart(comparison_df: pd.DataFrame) -> go.Figure:
    """Comparison of Average Response Time vs Resolution Time by Year."""
    fig = go.Figure()
    fig.add_trace(go.Bar(
        x=comparison_df["Year"].astype(str),
        y=comparison_df["Avg Response (hrs)"],
        name="Avg Response Time (hrs)",
        marker_color="#00A86B"
    ))
    fig.add_trace(go.Bar(
        x=comparison_df["Year"].astype(str),
        y=comparison_df["Avg Resolution (hrs)"],
        name="Avg Resolution Time (hrs)",
        marker_color="#00E5FF"
    ))
    fig.update_layout(**PLOTLY_LAYOUT)
    fig.update_layout(
        barmode="group",
        title="<b>SLA Performance: Mean Response vs Resolution Time (Hours)</b>",
        xaxis_title="Year",
        yaxis_title="Hours",
        legend=dict(orientation="h", yanchor="bottom", y=1.02, xanchor="right", x=1),
        height=380
    )
    return fig
