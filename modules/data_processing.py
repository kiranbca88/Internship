"""
modules/data_processing.py
==========================
Data loading, cleaning, validation, and metric calculation for
CYBERSHIELD – Enterprise Hacker Matrix SOC Command Center.
"""

import os
import pandas as pd
import numpy as np

# ==============================================================================
# HACKER MATRIX PALETTE & PLOTLY LAYOUT CONSTANTS
# ==============================================================================
SEVERITY_COLORS = {
    "Critical": "#FF1744",
    "High": "#FF9100",
    "Medium": "#FFEA00",
    "Low": "#00FF88"
}

STATUS_COLORS = {
    "Resolved": "#00FF88",
    "Closed": "#00A86B",
    "Under Investigation": "#FF9100",
    "Open": "#FF1744"
}

PLOTLY_LAYOUT = dict(
    template="plotly_dark",
    paper_bgcolor="rgba(6, 20, 16, 0.95)",
    plot_bgcolor="rgba(2, 8, 7, 0.95)",
    font=dict(color="#E8FFF4", family="'JetBrains Mono', 'Inter', monospace"),
    margin=dict(l=25, r=25, t=40, b=25),
    xaxis=dict(gridcolor="rgba(0, 255, 136, 0.08)", zerolinecolor="rgba(0, 255, 136, 0.15)"),
    yaxis=dict(gridcolor="rgba(0, 255, 136, 0.08)", zerolinecolor="rgba(0, 255, 136, 0.15)")
)


def load_dataset(filepath: str = None) -> pd.DataFrame:
    """
    Locates, loads, and normalizes the 5-year cybersecurity telemetry dataset.
    Ensures backwards and forwards compatibility for both naming conventions:
      - Response_Time_Hours <-> Response_Time
      - Resolution_Time_Hours <-> Resolution_Time
      - Financial_Loss_USD <-> Financial_Loss
      - Data_Exfiltrated <-> Data_Exfiltration
      - Multi_Factor_Auth <-> Multi_Factor_Authentication
    """
    search_paths = []
    if filepath:
        search_paths.append(filepath)

    search_paths.extend([
        "cyber_incidents_5_years.csv",
        os.path.join(os.path.dirname(__file__), "..", "cyber_incidents_5_years.csv"),
        os.path.join(os.path.dirname(__file__), "..", "cyber_security_incident_analytics", "cyber_incidents_5_years.csv"),
        os.path.join("cyber_security_incident_analytics", "cyber_incidents_5_years.csv")
    ])

    loaded_df = None
    for path in search_paths:
        if os.path.exists(path):
            try:
                loaded_df = pd.read_csv(path)
                break
            except Exception:
                continue

    if loaded_df is None:
        raise FileNotFoundError("Could not locate cyber_incidents_5_years.csv in workspace.")

    df = loaded_df.copy()

    # Column Normalization & Safe Aliasing
    alias_pairs = [
        ("Response_Time_Hours", "Response_Time"),
        ("Resolution_Time_Hours", "Resolution_Time"),
        ("Financial_Loss_USD", "Financial_Loss"),
        ("Data_Exfiltrated", "Data_Exfiltration"),
        ("Multi_Factor_Auth", "Multi_Factor_Authentication")
    ]

    for expected, alternate in alias_pairs:
        if expected in df.columns and alternate not in df.columns:
            df[alternate] = df[expected]
        elif alternate in df.columns and expected not in df.columns:
            df[expected] = df[alternate]

    # Convert timestamps and temporal columns
    df["Date"] = pd.to_datetime(df["Date"], errors="coerce")
    df["Date_Only"] = df["Date"].dt.date
    df["Year"] = df["Date"].dt.year
    df["Month"] = df["Date"].dt.month_name()
    df["Quarter"] = "Q" + df["Date"].dt.quarter.astype(str)
    df["Year_Month"] = df["Date"].dt.to_period("M").astype(str)

    # Safe handling of numeric fields
    numeric_cols = ["Response_Time_Hours", "Resolution_Time_Hours", "Financial_Loss_USD", "Records_Affected"]
    for col in numeric_cols:
        if col in df.columns:
            df[col] = pd.to_numeric(df[col], errors="coerce")

    return df


def calculate_kpis(df: pd.DataFrame) -> dict:
    """
    Computes all 8 Security Overview KPIs from the current dataset dynamically.
    No hardcoded values.
    """
    total_incidents = len(df)
    if total_incidents == 0:
        return {
            "total_incidents": 0,
            "critical_incidents": 0,
            "high_severity_incidents": 0,
            "resolved_incidents": 0,
            "open_incidents": 0,
            "total_financial_loss": "$0.00",
            "total_affected_records": "0",
            "avg_response_time": "0.0 hrs",
            "resolution_rate": "0.0%"
        }

    critical_count = int((df["Severity"] == "Critical").sum())
    high_count = int((df["Severity"] == "High").sum())
    resolved_count = int((df["Status"] == "Resolved").sum())
    open_count = int((df["Status"].isin(["Open", "Under Investigation"])).sum())
    
    financial_sum = float(df["Financial_Loss_USD"].sum()) if "Financial_Loss_USD" in df.columns else 0.0
    records_sum = int(df["Records_Affected"].sum()) if "Records_Affected" in df.columns else 0
    avg_resp = float(df["Response_Time_Hours"].mean()) if "Response_Time_Hours" in df.columns else 0.0

    resolution_pct = (resolved_count / total_incidents) * 100

    # Format nicely
    if financial_sum >= 1_000_000:
        fin_formatted = f"${financial_sum / 1_000_000:.2f}M"
    elif financial_sum >= 1_000:
        fin_formatted = f"${financial_sum / 1_000:.1f}K"
    else:
        fin_formatted = f"${financial_sum:,.2f}"

    if records_sum >= 1_000_000:
        rec_formatted = f"{records_sum / 1_000_000:.2f}M"
    elif records_sum >= 1_000:
        rec_formatted = f"{records_sum / 1_000:.1f}K"
    else:
        rec_formatted = f"{records_sum:,}"

    return {
        "total_incidents": f"{total_incidents:,}",
        "raw_total": total_incidents,
        "critical_incidents": f"{critical_count:,}",
        "critical_pct": f"{(critical_count / total_incidents * 100):.1f}%",
        "high_severity_incidents": f"{high_count:,}",
        "high_pct": f"{(high_count / total_incidents * 100):.1f}%",
        "resolved_incidents": f"{resolved_count:,}",
        "resolution_rate": f"{resolution_pct:.1f}%",
        "open_incidents": f"{open_count:,}",
        "total_financial_loss": fin_formatted,
        "raw_loss": financial_sum,
        "total_affected_records": rec_formatted,
        "raw_records": records_sum,
        "avg_response_time": f"{avg_resp:.1f} hrs"
    }


def compute_five_year_comparison(df: pd.DataFrame) -> pd.DataFrame:
    """
    Aggregates metrics for each year from 2021 to 2025, calculating
    Year-over-Year (YoY) growth rates and SLA performance.
    """
    yearly_records = []
    years = sorted(df["Year"].unique())

    prev_count = None
    prev_loss = None

    for y in years:
        sub = df[df["Year"] == y]
        count = len(sub)
        crit = int((sub["Severity"] == "Critical").sum())
        loss = float(sub["Financial_Loss_USD"].sum())
        records = int(sub["Records_Affected"].sum())
        avg_resp = float(sub["Response_Time_Hours"].mean())
        avg_resol = float(sub["Resolution_Time_Hours"].dropna().mean())

        # YoY Calculations
        if prev_count is not None and prev_count > 0:
            count_yoy = ((count - prev_count) / prev_count) * 100
        else:
            count_yoy = 0.0

        if prev_loss is not None and prev_loss > 0:
            loss_yoy = ((loss - prev_loss) / prev_loss) * 100
        else:
            loss_yoy = 0.0

        prev_count = count
        prev_loss = loss

        yearly_records.append({
            "Year": int(y),
            "Total Incidents": count,
            "Critical Incidents": crit,
            "Financial Loss ($M)": round(loss / 1_000_000, 2),
            "Total Loss ($)": round(loss, 2),
            "Affected Records": records,
            "Avg Response (hrs)": round(avg_resp, 1),
            "Avg Resolution (hrs)": round(avg_resol, 1),
            "Incident YoY (%)": round(count_yoy, 1),
            "Loss YoY (%)": round(loss_yoy, 1)
        })

    return pd.DataFrame(yearly_records)
