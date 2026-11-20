"""
analysis.py
-----------
Core analytics calculation module for cybersecurity incident datasets.

Designed with beginner-friendly, modular functions that compute standard
cybersecurity Key Performance Indicators (KPIs), operational distributions,
and time-to-resolve metrics.

ANALYTICAL CAUTION:
- Average Resolution Time is calculated strictly using Resolved incidents.
- Incident count / frequency alone does not reflect vulnerability exploitability,
  risk severity, or attack impact without considering asset criticality.
"""

import pandas as pd
import numpy as np
from typing import Dict, Any

def calculate_kpis(df: pd.DataFrame) -> Dict[str, Any]:
    """
    Calculate high-level cybersecurity incident KPIs.

    Parameters:
        df (pd.DataFrame): Cleaned incident dataframe.

    Returns:
        Dict[str, Any]: Dictionary containing key operational metrics.
    """
    if df.empty:
        return {
            "total_incidents": 0,
            "open_incidents": 0,
            "in_progress_incidents": 0,
            "unresolved_incidents": 0,
            "resolved_incidents": 0,
            "resolution_rate_pct": 0.0,
            "critical_incidents": 0,
            "high_incidents": 0,
            "high_critical_incidents": 0,
            "high_critical_pct": 0.0,
            "avg_resolution_hours": None,
            "median_resolution_hours": None,
        }

    total_incidents = len(df)
    open_incidents = int((df["Status"] == "Open").sum())
    in_progress = int((df["Status"] == "In Progress").sum())
    unresolved_incidents = open_incidents + in_progress
    resolved_incidents = int((df["Status"] == "Resolved").sum())

    resolution_rate_pct = round((resolved_incidents / total_incidents) * 100, 1) if total_incidents > 0 else 0.0

    critical_incidents = int((df["Severity"] == "Critical").sum())
    high_incidents = int((df["Severity"] == "High").sum())
    high_critical_incidents = critical_incidents + high_incidents
    high_critical_pct = round((high_critical_incidents / total_incidents) * 100, 1) if total_incidents > 0 else 0.0

    # CRITICAL: Filter exclusively for resolved records with non-null hours
    resolved_hours = df.loc[df["Status"] == "Resolved", "Resolution_Hours"].dropna()

    if len(resolved_hours) > 0:
        avg_res_hours = round(float(resolved_hours.mean()), 1)
        median_res_hours = round(float(resolved_hours.median()), 1)
    else:
        avg_res_hours = None
        median_res_hours = None

    return {
        "total_incidents": total_incidents,
        "open_incidents": open_incidents,
        "in_progress_incidents": in_progress,
        "unresolved_incidents": unresolved_incidents,
        "resolved_incidents": resolved_incidents,
        "resolution_rate_pct": resolution_rate_pct,
        "critical_incidents": critical_incidents,
        "high_incidents": high_incidents,
        "high_critical_incidents": high_critical_incidents,
        "high_critical_pct": high_critical_pct,
        "avg_resolution_hours": avg_res_hours,
        "median_resolution_hours": median_res_hours,
    }

def get_severity_distribution(df: pd.DataFrame) -> pd.DataFrame:
    """
    Calculate incident frequency and percentage by severity level.

    Parameters:
        df (pd.DataFrame): Incident dataframe.

    Returns:
        pd.DataFrame: Table with Severity, Count, and Percentage.
    """
    if df.empty:
        return pd.DataFrame(columns=["Severity", "Count", "Percentage"])

    # Ensure canonical severity ordering
    severity_order = ["Critical", "High", "Medium", "Low"]
    counts = df["Severity"].value_counts().reindex(severity_order, fill_value=0).reset_index()
    counts.columns = ["Severity", "Count"]
    counts["Percentage"] = round((counts["Count"] / len(df)) * 100, 1)
    return counts

def get_incident_types_summary(df: pd.DataFrame) -> pd.DataFrame:
    """
    Breakdown of incidents by category, including average resolution hours for resolved cases.

    Parameters:
        df (pd.DataFrame): Incident dataframe.

    Returns:
        pd.DataFrame: Summary table by Incident_Type.
    """
    if df.empty:
        return pd.DataFrame(columns=["Incident_Type", "Total_Incidents", "Percentage", "Avg_Resolution_Hours"])

    summary = []
    total = len(df)
    for inc_type, group in df.groupby("Incident_Type"):
        count = len(group)
        pct = round((count / total) * 100, 1)
        
        # Calculate resolution time only on resolved incidents
        resolved_group = group[group["Status"] == "Resolved"]["Resolution_Hours"].dropna()
        avg_hours = round(float(resolved_group.mean()), 1) if len(resolved_group) > 0 else np.nan

        summary.append({
            "Incident_Type": inc_type,
            "Total_Incidents": count,
            "Percentage": pct,
            "Avg_Resolution_Hours": avg_hours
        })

    result_df = pd.DataFrame(summary).sort_values(by="Total_Incidents", ascending=False).reset_index(drop=True)
    return result_df

def get_department_summary(df: pd.DataFrame) -> pd.DataFrame:
    """
    Breakdown of incidents by target department.

    Parameters:
        df (pd.DataFrame): Incident dataframe.

    Returns:
        pd.DataFrame: Summary table by Department.
    """
    if df.empty:
        return pd.DataFrame(columns=["Department", "Total_Incidents", "High_Critical_Count", "Resolved_Count", "Avg_Resolution_Hours"])

    summary = []
    for dept, group in df.groupby("Department"):
        total = len(group)
        high_crit = int(group["Severity"].isin(["High", "Critical"]).sum())
        resolved = int((group["Status"] == "Resolved").sum())
        
        resolved_hours = group[group["Status"] == "Resolved"]["Resolution_Hours"].dropna()
        avg_hours = round(float(resolved_hours.mean()), 1) if len(resolved_hours) > 0 else np.nan

        summary.append({
            "Department": dept,
            "Total_Incidents": total,
            "High_Critical_Count": high_crit,
            "Resolved_Count": resolved,
            "Avg_Resolution_Hours": avg_hours
        })

    result_df = pd.DataFrame(summary).sort_values(by="Total_Incidents", ascending=False).reset_index(drop=True)
    return result_df

def get_monthly_trend(df: pd.DataFrame) -> pd.DataFrame:
    """
    Compute monthly volume of reported incidents and resolution performance.

    Parameters:
        df (pd.DataFrame): Incident dataframe with datetime Incident_Date.

    Returns:
        pd.DataFrame: Monthly aggregated metrics.
    """
    if df.empty:
        return pd.DataFrame(columns=["Year_Month", "Total_Incidents", "Resolved_Incidents", "Avg_Resolution_Hours"])

    temp_df = df.copy()
    temp_df["Incident_Date"] = pd.to_datetime(temp_df["Incident_Date"])
    temp_df["Year_Month"] = temp_df["Incident_Date"].dt.to_period("M").astype(str)

    monthly_records = []
    for ym, group in temp_df.groupby("Year_Month"):
        total = len(group)
        resolved = int((group["Status"] == "Resolved").sum())
        resolved_hours = group[group["Status"] == "Resolved"]["Resolution_Hours"].dropna()
        avg_hours = round(float(resolved_hours.mean()), 1) if len(resolved_hours) > 0 else np.nan

        monthly_records.append({
            "Year_Month": ym,
            "Total_Incidents": total,
            "Resolved_Incidents": resolved,
            "Avg_Resolution_Hours": avg_hours
        })

    trend_df = pd.DataFrame(monthly_records).sort_values(by="Year_Month").reset_index(drop=True)
    return trend_df

def get_resolution_by_severity(df: pd.DataFrame) -> pd.DataFrame:
    """
    Calculates resolution time statistics grouped by incident severity.

    Parameters:
        df (pd.DataFrame): Incident dataframe.

    Returns:
        pd.DataFrame: Resolution stats per severity.
    """
    if df.empty:
        return pd.DataFrame(columns=["Severity", "Resolved_Count", "Mean_Hours", "Median_Hours", "Min_Hours", "Max_Hours"])

    resolved = df[df["Status"] == "Resolved"].dropna(subset=["Resolution_Hours"])
    if resolved.empty:
        return pd.DataFrame(columns=["Severity", "Resolved_Count", "Mean_Hours", "Median_Hours", "Min_Hours", "Max_Hours"])

    records = []
    severity_order = ["Critical", "High", "Medium", "Low"]
    for sev in severity_order:
        sub = resolved[resolved["Severity"] == sev]["Resolution_Hours"]
        if len(sub) > 0:
            records.append({
                "Severity": sev,
                "Resolved_Count": len(sub),
                "Mean_Hours": round(float(sub.mean()), 1),
                "Median_Hours": round(float(sub.median()), 1),
                "Min_Hours": round(float(sub.min()), 1),
                "Max_Hours": round(float(sub.max()), 1),
            })
        else:
            records.append({
                "Severity": sev,
                "Resolved_Count": 0,
                "Mean_Hours": np.nan,
                "Median_Hours": np.nan,
                "Min_Hours": np.nan,
                "Max_Hours": np.nan,
            })
    return pd.DataFrame(records)

def print_analytical_summary(df: pd.DataFrame) -> None:
    """Print an executive command-line summary of calculated metrics."""
    kpis = calculate_kpis(df)
    print("\n==================================================")
    print("      CYBER SECURITY INCIDENT KPI SUMMARY         ")
    print("==================================================")
    print(f"Total Incidents Logged        : {kpis['total_incidents']}")
    print(f"Resolved Incidents            : {kpis['resolved_incidents']} ({kpis['resolution_rate_pct']}%)")
    print(f"Unresolved (Open/In Progress) : {kpis['unresolved_incidents']}")
    print(f"High & Critical Incidents     : {kpis['high_critical_incidents']} ({kpis['high_critical_pct']}%)")
    print(f"Average Resolution Time (hrs) : {kpis['avg_resolution_hours']} hrs (Resolved only)")
    print(f"Median Resolution Time (hrs)  : {kpis['median_resolution_hours']} hrs (Resolved only)")
    print("==================================================\n")

if __name__ == "__main__":
    import os
    script_dir = os.path.dirname(os.path.abspath(__file__))
    project_root = os.path.dirname(script_dir)
    data_path = os.path.join(project_root, "data", "processed", "incidents_cleaned.csv")
    
    if os.path.exists(data_path):
        cleaned_df = pd.read_csv(data_path)
        print_analytical_summary(cleaned_df)
    else:
        print(f"[WARN] Processed dataset not found at {data_path}. Please run data_cleaning.py first.")

