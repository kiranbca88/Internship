"""
export_excel.py
---------------
Generates a multi-tab, professionally formatted Excel workbook
(outputs/incident_analysis.xlsx) with native Excel charts and styled tables.

Sheets included:
1. KPI Summary
2. Raw Data
3. Cleaned Data
4. Severity Analysis (with native Bar Chart)
5. Incident Types (with native Bar Chart)
6. Department Analysis (with native Bar Chart)
7. Monthly Trend (with native Line Chart)
8. Data Dictionary
"""

import os
import sys

# Ensure project root is in sys.path
SCRIPT_DIR = os.path.dirname(os.path.abspath(__file__))
PROJECT_ROOT = os.path.dirname(SCRIPT_DIR)
if PROJECT_ROOT not in sys.path:
    sys.path.insert(0, PROJECT_ROOT)

import pandas as pd
from openpyxl import Workbook
from openpyxl.styles import Font, PatternFill, Alignment, Border, Side
from openpyxl.utils import get_column_letter
from openpyxl.chart import BarChart, LineChart, Reference

try:
    from src.analysis import (
        calculate_kpis,
        get_severity_distribution,
        get_incident_types_summary,
        get_department_summary,
        get_monthly_trend,
        get_resolution_by_severity
    )
except ImportError:
    from analysis import (
        calculate_kpis,
        get_severity_distribution,
        get_incident_types_summary,
        get_department_summary,
        get_monthly_trend,
        get_resolution_by_severity
    )

# Styling Constants
NAVY_HEADER_FILL = PatternFill(start_color="1F4E78", end_color="1F4E78", fill_type="solid")
STEEL_SUB_FILL = PatternFill(start_color="D9E1F2", end_color="D9E1F2", fill_type="solid")
ZEBRA_FILL = PatternFill(start_color="F2F5F9", end_color="F2F5F9", fill_type="solid")
ALERT_FILL = PatternFill(start_color="FCE4D6", end_color="FCE4D6", fill_type="solid")

WHITE_BOLD_FONT = Font(name="Calibri", size=11, bold=True, color="FFFFFF")
DARK_BOLD_FONT = Font(name="Calibri", size=11, bold=True, color="1F4E78")
TITLE_FONT = Font(name="Calibri", size=16, bold=True, color="1F4E78")
SUBTITLE_FONT = Font(name="Calibri", size=10, italic=True, color="595959")
REGULAR_FONT = Font(name="Calibri", size=10, color="000000")

THIN_BORDER = Border(
    left=Side(style="thin", color="D3D3D3"),
    right=Side(style="thin", color="D3D3D3"),
    top=Side(style="thin", color="D3D3D3"),
    bottom=Side(style="thin", color="D3D3D3")
)

def auto_fit_columns(ws, min_width=12, max_width=45):
    """Adjust worksheet column widths to fit cell contents cleanly."""
    for col in ws.columns:
        max_len = 0
        col_letter = get_column_letter(col[0].column)
        for cell in col:
            # Skip title merged cells in row 1-2 to avoid wide columns
            if cell.row in [1, 2]:
                continue
            val_str = str(cell.value or "")
            if len(val_str) > max_len:
                max_len = len(val_str)
        ws.column_dimensions[col_letter].width = max(min_width, min(max_len + 3, max_width))

def style_table_range(ws, start_row, end_row, start_col, end_col):
    """Apply borders and alternating zebra shading to a table range."""
    for r in range(start_row, end_row + 1):
        for c in range(start_col, end_col + 1):
            cell = ws.cell(row=r, column=c)
            cell.font = REGULAR_FONT
            cell.border = THIN_BORDER
            if r % 2 == 0 and r > start_row:
                cell.fill = ZEBRA_FILL

def create_excel_report(raw_csv_path: str, cleaned_csv_path: str, output_xlsx_path: str) -> None:
    """
    Build the complete Excel workbook with all 8 sheets, formatting, and charts.
    """
    if not os.path.exists(raw_csv_path):
        raise FileNotFoundError(f"Raw CSV not found: {raw_csv_path}")
    if not os.path.exists(cleaned_csv_path):
        raise FileNotFoundError(f"Cleaned CSV not found: {cleaned_csv_path}")

    raw_df = pd.read_csv(raw_csv_path)
    cleaned_df = pd.read_csv(cleaned_csv_path)

    wb = Workbook()
    # Remove default sheet
    wb.remove(wb.active)

    # -------------------------------------------------------------
    # 1. KPI SUMMARY SHEET
    # -------------------------------------------------------------
    ws_kpi = wb.create_sheet(title="KPI Summary")
    ws_kpi.views.sheetView[0].showGridLines = True

    ws_kpi["A1"] = "Cyber Security Incident Analytics - Executive KPI Summary"
    ws_kpi["A1"].font = TITLE_FONT
    ws_kpi["A2"] = "Synthetic incident monitoring dataset for BCA Data Analyst Portfolio"
    ws_kpi["A2"].font = SUBTITLE_FONT

    kpis = calculate_kpis(cleaned_df)
    kpi_rows = [
        ["Key Performance Indicator", "Value", "Unit / Format", "Analytical Definition & Context"],
        ["Total Incidents Logged", kpis["total_incidents"], "Count", "Total unique cybersecurity incidents recorded across all business units"],
        ["Resolved Incidents", kpis["resolved_incidents"], "Count", "Incidents where containment, remediation, and root-cause analysis completed"],
        ["Open Incidents", kpis["open_incidents"], "Count", "Active incidents awaiting initial investigation or active remediation"],
        ["In Progress Incidents", kpis["in_progress_incidents"], "Count", "Incidents currently undergoing triage or digital forensics investigation"],
        ["Resolution Rate", f"{kpis['resolution_rate_pct']}%", "Percentage", "Proportion of total logged incidents successfully resolved to date"],
        ["Critical Incidents", kpis["critical_incidents"], "Count", "Tier-1 catastrophic incidents posing severe operational or compliance threat"],
        ["High Severity Incidents", kpis["high_incidents"], "Count", "Significant threats with elevated risk of data compromise or lateral spread"],
        ["High & Critical Incident Ratio", f"{kpis['high_critical_pct']}%", "Percentage", "Percentage of incident volume classified as High or Critical urgency"],
        ["Average Resolution Time", f"{kpis['avg_resolution_hours']} hrs", "Hours", "Mean Time to Resolve (MTTR) calculated strictly for Resolved incidents"],
        ["Median Resolution Time", f"{kpis['median_resolution_hours']} hrs", "Hours", "Median resolution duration, robust against extreme multi-day outliers"],
    ]

    start_r = 4
    for r_idx, row_data in enumerate(kpi_rows, start=start_r):
        for c_idx, val in enumerate(row_data, start=1):
            cell = ws_kpi.cell(row=r_idx, column=c_idx, value=val)
            if r_idx == start_r:
                cell.font = WHITE_BOLD_FONT
                cell.fill = NAVY_HEADER_FILL
                cell.alignment = Alignment(horizontal="center" if c_idx in [2, 3] else "left")
            else:
                cell.font = REGULAR_FONT
                cell.border = THIN_BORDER
                if c_idx in [2, 3]:
                    cell.alignment = Alignment(horizontal="center")
                if r_idx % 2 == 0:
                    cell.fill = ZEBRA_FILL

    # Additional mini table: Resolution by Severity on KPI Sheet
    res_sev_df = get_resolution_by_severity(cleaned_df)
    ws_kpi.cell(row=17, column=1, value="Resolution Performance by Severity Tier (Resolved Only)").font = DARK_BOLD_FONT
    for col_i, col_name in enumerate(res_sev_df.columns, start=1):
        c = ws_kpi.cell(row=18, column=col_i, value=col_name)
        c.font = WHITE_BOLD_FONT
        c.fill = NAVY_HEADER_FILL
        c.alignment = Alignment(horizontal="center")

    for row_i, r_data in enumerate(res_sev_df.values, start=19):
        for col_i, v in enumerate(r_data, start=1):
            c = ws_kpi.cell(row=row_i, column=col_i, value=v)
            c.font = REGULAR_FONT
            c.border = THIN_BORDER
            c.alignment = Alignment(horizontal="center")
            if row_i % 2 == 0:
                c.fill = ZEBRA_FILL

    auto_fit_columns(ws_kpi)

    # -------------------------------------------------------------
    # Helper to populate standard dataframe sheets
    # -------------------------------------------------------------
    def write_dataframe_sheet(sheet_title, df, subtitle=None):
        ws = wb.create_sheet(title=sheet_title)
        ws.views.sheetView[0].showGridLines = True
        ws["A1"] = f"Cyber Security Incident Analytics - {sheet_title}"
        ws["A1"].font = TITLE_FONT
        if subtitle:
            ws["A2"] = subtitle
            ws["A2"].font = SUBTITLE_FONT

        start_row = 4
        # Write headers
        for col_idx, col_name in enumerate(df.columns, start=1):
            cell = ws.cell(row=start_row, column=col_idx, value=col_name)
            cell.font = WHITE_BOLD_FONT
            cell.fill = NAVY_HEADER_FILL
            cell.alignment = Alignment(horizontal="center")

        # Write data rows
        for row_idx, row_values in enumerate(df.values, start=start_row + 1):
            for col_idx, val in enumerate(row_values, start=1):
                cell = ws.cell(row=row_idx, column=col_idx, value=val)
                cell.font = REGULAR_FONT
                cell.border = THIN_BORDER
                if row_idx % 2 == 0:
                    cell.fill = ZEBRA_FILL
                # Center align ID and Status columns
                if df.columns[col_idx - 1] in ["Incident_ID", "Status", "Severity", "Incident_Date", "Year_Month"]:
                    cell.alignment = Alignment(horizontal="center")

        auto_fit_columns(ws)
        return ws, start_row, start_row + len(df)

    # -------------------------------------------------------------
    # 2. RAW DATA SHEET
    # -------------------------------------------------------------
    write_dataframe_sheet("Raw Data", raw_df, "Uncleaned raw dataset directly exported from source logs")

    # -------------------------------------------------------------
    # 3. CLEANED DATA SHEET
    # -------------------------------------------------------------
    write_dataframe_sheet("Cleaned Data", cleaned_df, "Validated & deduplicated dataset; unresolved incident resolution hours kept as null")

    # -------------------------------------------------------------
    # 4. SEVERITY ANALYSIS SHEET (WITH BAR CHART)
    # -------------------------------------------------------------
    sev_df = get_severity_distribution(cleaned_df)
    ws_sev, s_start, s_end = write_dataframe_sheet("Severity Analysis", sev_df, "Incident counts and volume share grouped by severity tier")
    
    chart_sev = BarChart()
    chart_sev.type = "col"
    chart_sev.style = 10
    chart_sev.title = "Incident Volume by Severity Tier"
    chart_sev.y_axis.title = "Incident Count"
    chart_sev.x_axis.title = "Severity Level"
    chart_sev.height = 10
    chart_sev.width = 15
    data_ref = Reference(ws_sev, min_col=2, min_row=s_start, max_row=s_end)
    cats_ref = Reference(ws_sev, min_col=1, min_row=s_start + 1, max_row=s_end)
    chart_sev.add_data(data_ref, titles_from_data=True)
    chart_sev.set_categories(cats_ref)
    chart_sev.legend = None
    ws_sev.add_chart(chart_sev, "E4")

    # -------------------------------------------------------------
    # 5. INCIDENT TYPES SHEET (WITH BAR CHART)
    # -------------------------------------------------------------
    type_df = get_incident_types_summary(cleaned_df)
    ws_type, t_start, t_end = write_dataframe_sheet("Incident Types", type_df, "Threat distribution and average resolution duration by attack type")
    
    chart_type = BarChart()
    chart_type.type = "bar"
    chart_type.style = 11
    chart_type.title = "Incident Count by Threat Type"
    chart_type.x_axis.title = "Total Incidents"
    chart_type.y_axis.title = "Incident Type"
    chart_type.height = 10
    chart_type.width = 16
    data_ref_t = Reference(ws_type, min_col=2, min_row=t_start, max_row=t_end)
    cats_ref_t = Reference(ws_type, min_col=1, min_row=t_start + 1, max_row=t_end)
    chart_type.add_data(data_ref_t, titles_from_data=True)
    chart_type.set_categories(cats_ref_t)
    chart_type.legend = None
    ws_type.add_chart(chart_type, "F4")

    # -------------------------------------------------------------
    # 6. DEPARTMENT ANALYSIS SHEET (WITH BAR CHART)
    # -------------------------------------------------------------
    dept_df = get_department_summary(cleaned_df)
    ws_dept, d_start, d_end = write_dataframe_sheet("Department Analysis", dept_df, "Cross-departmental security workload and incident exposure")
    
    chart_dept = BarChart()
    chart_dept.type = "col"
    chart_dept.style = 12
    chart_dept.title = "Incident Volume by Department"
    chart_dept.y_axis.title = "Incident Count"
    chart_dept.x_axis.title = "Department"
    chart_dept.height = 10
    chart_dept.width = 16
    data_ref_d = Reference(ws_dept, min_col=2, min_row=d_start, max_row=d_end)
    cats_ref_d = Reference(ws_dept, min_col=1, min_row=d_start + 1, max_row=d_end)
    chart_dept.add_data(data_ref_d, titles_from_data=True)
    chart_dept.set_categories(cats_ref_d)
    chart_dept.legend = None
    ws_dept.add_chart(chart_dept, "G4")

    # -------------------------------------------------------------
    # 7. MONTHLY TREND SHEET (WITH LINE CHART)
    # -------------------------------------------------------------
    trend_df = get_monthly_trend(cleaned_df)
    ws_trend, tr_start, tr_end = write_dataframe_sheet("Monthly Trend", trend_df, "Chronological trend of monthly incident arrivals and resolutions")

    chart_trend = LineChart()
    chart_trend.title = "Monthly Cyber Security Incidents Trend"
    chart_trend.style = 13
    chart_trend.y_axis.title = "Incident Count"
    chart_trend.x_axis.title = "Reporting Month"
    chart_trend.height = 10
    chart_trend.width = 16
    data_ref_tr = Reference(ws_trend, min_col=2, min_row=tr_start, max_row=tr_end)
    cats_ref_tr = Reference(ws_trend, min_col=1, min_row=tr_start + 1, max_row=tr_end)
    chart_trend.add_data(data_ref_tr, titles_from_data=True)
    chart_trend.set_categories(cats_ref_tr)
    chart_trend.legend = None
    ws_trend.add_chart(chart_trend, "F4")

    # -------------------------------------------------------------
    # 8. DATA DICTIONARY SHEET
    # -------------------------------------------------------------
    dict_records = [
        ["Field Name", "Data Type", "Allowed Values / Format", "Nullable", "Description", "Analytical Note"],
        ["Incident_ID", "String", "INC-YYYY-XXXX (e.g. INC-2024-0001)", "No", "Unique primary key tracking each cybersecurity incident.", "Serves as distinct identifier; used to ensure no duplicates exist."],
        ["Incident_Date", "Datetime", "YYYY-MM-DD HH:MM:SS", "No", "Timestamp when the incident was detected and logged.", "Used for temporal aggregation and monthly trend calculations."],
        ["Incident_Type", "String", "Phishing, Malware, Ransomware, Suspicious Login, Data Leak, Unauthorized Access", "No", "Categorization of threat vector / security event mechanism.", "Reveals operational frequency; frequency alone does not equal exploit impact."],
        ["Severity", "String", "Low, Medium, High, Critical", "No", "Assigned risk urgency based on asset criticality and threat level.", "Primary triage factor; determines SLA and prioritization."],
        ["Department", "String", "IT, Finance, HR, Marketing, Operations, Sales, Legal, Engineering", "No", "Business unit experiencing or reporting the security event.", "Highlights organizational areas requiring security hygiene or phishing simulations."],
        ["Status", "String", "Open, In Progress, Resolved", "No", "Operational triage state of the incident response lifecycle.", "Used to segment completed cases from active backlogs."],
        ["Resolution_Hours", "Float", "Numeric >= 0.5 (or NULL)", "Yes", "Duration in hours from incident detection to complete resolution.", "CRITICAL: Must remain NULL for Open/In Progress cases; never fill with 0.0."],
        ["Description", "String", "Text description prefixed with [SYNTHETIC]", "No", "Contextual operational narrative of the detected security event.", "Provides realistic SOC triage detail for analysts and auditors."]
    ]
    dict_df = pd.DataFrame(dict_records[1:], columns=dict_records[0])
    write_dataframe_sheet("Data Dictionary", dict_df, "Comprehensive metadata, validation constraints, and analytical usage rules")

    # Save final workbook
    os.makedirs(os.path.dirname(output_xlsx_path), exist_ok=True)
    wb.save(output_xlsx_path)
    print(f"[SUCCESS] Multi-tab Excel workbook with charts generated at: {output_xlsx_path}")

if __name__ == "__main__":
    script_dir = os.path.dirname(os.path.abspath(__file__))
    project_root = os.path.dirname(script_dir)
    
    raw_path = os.path.join(project_root, "data", "raw", "incidents_sample.csv")
    cleaned_path = os.path.join(project_root, "data", "processed", "incidents_cleaned.csv")
    excel_path = os.path.join(project_root, "outputs", "incident_analysis.xlsx")
    
    create_excel_report(raw_path, cleaned_path, excel_path)
