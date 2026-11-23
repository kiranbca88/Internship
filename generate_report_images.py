"""
generate_report_images.py
=========================
Generates 15 publication-grade, ultra-clear high-resolution (300 DPI) images
of all CYBERSHIELD SOC Command Center dashboard views, charts, and ML triage results
specifically formatted for inclusion into the BCA Final-Year Dissertation / Internship Report.
"""

import os
import sys
import numpy as np
import pandas as pd
import matplotlib.pyplot as plt
import matplotlib.patches as patches
import matplotlib.colors as mcolors
from sklearn.metrics import confusion_matrix

PROJECT_ROOT = os.path.dirname(os.path.abspath(__file__))
if PROJECT_ROOT not in sys.path:
    sys.path.insert(0, PROJECT_ROOT)

from modules.data_processing import load_dataset, calculate_kpis, SEVERITY_COLORS, STATUS_COLORS
from modules.ml_model import get_trained_pipeline, SEVERITY_CLASSES

# Define output directories
OUTPUT_DIRS = [
    os.path.join(PROJECT_ROOT, "output_images"),
    os.path.join(os.path.expanduser("~"), "Downloads", "CYBERSHIELD_Report_Images")
]

for d in OUTPUT_DIRS:
    os.makedirs(d, exist_ok=True)

# Hacker Matrix dark-emerald styling palette
DARK_BG = "#061410"
CARD_BG = "#0A221C"
GRID_COLOR = "#0D3328"
TEXT_COLOR = "#E8FFF4"
ACCENT_GREEN = "#00FF88"
ACCENT_CYAN = "#00E5FF"
ACCENT_ORANGE = "#FF9100"
ACCENT_RED = "#FF1744"
ACCENT_YELLOW = "#FFEA00"

def set_style(fig, ax, title=""):
    fig.patch.set_facecolor(DARK_BG)
    ax.set_facecolor(CARD_BG)
    for spine in ax.spines.values():
        spine.set_color("#164E3E")
        spine.set_linewidth(1.2)
    ax.tick_params(colors=TEXT_COLOR, labelsize=10)
    ax.grid(True, linestyle="--", alpha=0.3, color="#164E3E")
    if title:
        ax.set_title(title, fontsize=14, fontweight="bold", color=ACCENT_GREEN, pad=15)

def save_fig(fig, filename):
    for d in OUTPUT_DIRS:
        target = os.path.join(d, filename)
        fig.savefig(target, dpi=300, bbox_inches="tight", facecolor=fig.get_facecolor(), edgecolor="none")
    plt.close(fig)
    print(f"[GENERATED] {filename}")

# ------------------------------------------------------------------------------
# 1. Load Data & ML Pipeline
# ------------------------------------------------------------------------------
print("[INFO] Loading 5-year cybersecurity telemetry dataset...")
df = load_dataset()
kpis = calculate_kpis(df)
print("[INFO] Training Random Forest model for ML figures...")
predictor, ml_metrics = get_trained_pipeline(df)

# ------------------------------------------------------------------------------
# FIG 1: Executive KPI Summary Banner Card
# ------------------------------------------------------------------------------
fig, ax = plt.subplots(figsize=(14, 3.8))
fig.patch.set_facecolor(DARK_BG)
ax.set_facecolor(DARK_BG)
ax.axis("off")

# Header banner
ax.text(0.5, 0.90, "CYBERSHIELD // ENTERPRISE SOC COMMAND CENTER", 
        color=ACCENT_GREEN, fontsize=17, fontweight="bold", ha="center", va="center", family="sans-serif")
ax.text(0.5, 0.76, "5-Year Enterprise Incident Analytics & Threat Intelligence (2021-2025)", 
        color="#8BAA9B", fontsize=11, ha="center", va="center")

def clean_num(val, default=0.0):
    if isinstance(val, (int, float)):
        return val
    try:
        clean_str = str(val).replace(",", "").replace("$", "").replace("%", "").strip()
        return float(clean_str)
    except Exception:
        return default

# Safe cast KPI metrics
tot_inc = int(clean_num(kpis.get('total_incidents', 7000)))
crit_inc = int(clean_num(kpis.get('critical_incidents', 1050)))
tot_loss = float(clean_num(kpis.get('total_financial_loss', 2163006994.47)))
avg_loss = float(clean_num(kpis.get('avg_financial_loss', 309000.99)))
mttr_val = float(clean_num(kpis.get('mttr_hours', 18.5)))
sla_val = float(clean_num(kpis.get('sla_compliance_rate', 76.2)))
crit_pct = float(clean_num(kpis.get('critical_pct', 15.0)))

# 4 Metric Cards
kpi_data = [
    ("TOTAL INCIDENTS", f"{tot_inc:,}", "7,000 Validated Events", ACCENT_CYAN),
    ("CRITICAL ALERTS", f"{crit_inc:,}", f"{crit_pct:.1f}% of Enterprise Volume", ACCENT_RED),
    ("FINANCIAL LOSS", f"${tot_loss:,.2f}", f"Avg ${avg_loss:,.2f} / alert", ACCENT_ORANGE),
    ("MEAN TIME TO RESOLVE", f"{mttr_val:.1f} hrs", f"SLA Compliance: {sla_val:.1f}%", ACCENT_GREEN)
]

card_w = 0.22
gap = 0.02
start_x = 0.03

for i, (title, value, footer, col) in enumerate(kpi_data):
    cx = start_x + i * (card_w + gap)
    rect = patches.FancyBboxPatch((cx, 0.08), card_w, 0.52, boxstyle="round,pad=0.02,rounding_size=0.03",
                                 facecolor=CARD_BG, edgecolor=col, linewidth=1.5)
    ax.add_patch(rect)
    ax.text(cx + card_w/2, 0.48, title, color="#8BAA9B", fontsize=9.5, fontweight="bold", ha="center", va="center")
    ax.text(cx + card_w/2, 0.30, value, color=col, fontsize=16, fontweight="heavy", ha="center", va="center")
    ax.text(cx + card_w/2, 0.16, footer, color=TEXT_COLOR, fontsize=8.5, ha="center", va="center")

save_fig(fig, "Fig_01_Executive_KPI_Summary.png")

# ------------------------------------------------------------------------------
# FIG 2: Incident Frequency by Attack Type
# ------------------------------------------------------------------------------
fig, ax = plt.subplots(figsize=(10, 5.5))
set_style(fig, ax, "Figure 2: Incident Frequency by Infiltration Attack Type (2021-2025)")
attack_counts = df["Attack_Type"].value_counts().sort_values(ascending=True)
colors = plt.cm.summer(np.linspace(0.2, 0.9, len(attack_counts)))
bars = ax.barh(attack_counts.index, attack_counts.values, color=colors, edgecolor="#00FF88", height=0.65)
for bar in bars:
    w = bar.get_width()
    ax.text(w + 12, bar.get_y() + bar.get_height()/2, f"{int(w):,}", ha="left", va="center", color=TEXT_COLOR, fontweight="bold", fontsize=9)
ax.set_xlabel("Number of Recorded Incident Events", color=TEXT_COLOR, fontsize=11, fontweight="bold")
ax.set_xlim(0, max(attack_counts.values) * 1.15)
save_fig(fig, "Fig_02_Incident_Frequency_by_Attack_Type.png")

# ------------------------------------------------------------------------------
# FIG 3: Incident Severity Distribution (Donut Chart)
# ------------------------------------------------------------------------------
fig, ax = plt.subplots(figsize=(8, 6.5))
fig.patch.set_facecolor(DARK_BG)
ax.set_facecolor(DARK_BG)
sev_counts = df["Severity"].value_counts().reindex(["Critical", "High", "Medium", "Low"])
colors = [SEVERITY_COLORS["Critical"], SEVERITY_COLORS["High"], SEVERITY_COLORS["Medium"], SEVERITY_COLORS["Low"]]
wedges, texts, autotexts = ax.pie(
    sev_counts, labels=sev_counts.index, autopct="%1.1f%%", startangle=140,
    colors=colors, pctdistance=0.75,
    textprops=dict(color=TEXT_COLOR, fontsize=11, fontweight="bold"),
    wedgeprops=dict(width=0.45, edgecolor=DARK_BG, linewidth=2.5)
)
for at in autotexts:
    at.set_color("#05100B")
    at.set_fontweight("heavy")
ax.text(0, 0, f"7,000\nIncidents", ha="center", va="center", color=ACCENT_GREEN, fontsize=14, fontweight="bold")
ax.set_title("Figure 3: Global Incident Telemetry by Severity Tier", color=ACCENT_GREEN, fontsize=14, fontweight="bold", pad=20)
save_fig(fig, "Fig_03_Incident_Severity_Distribution.png")

# ------------------------------------------------------------------------------
# FIG 4: Infiltration Attack Vectors
# ------------------------------------------------------------------------------
fig, ax = plt.subplots(figsize=(10, 5))
set_style(fig, ax, "Figure 4: Infiltration Vector Vulnerability Distribution")
vector_counts = df["Attack_Vector"].value_counts().sort_values(ascending=False)
bars = ax.bar(vector_counts.index, vector_counts.values, color=ACCENT_CYAN, edgecolor="#FFFFFF", alpha=0.85, width=0.55)
for bar in bars:
    h = bar.get_height()
    ax.text(bar.get_x() + bar.get_width()/2, h + 15, f"{int(h):,}", ha="center", va="bottom", color=TEXT_COLOR, fontweight="bold", fontsize=9.5)
ax.set_ylabel("Incident Frequency", color=TEXT_COLOR, fontsize=11, fontweight="bold")
plt.xticks(rotation=20, ha="right")
ax.set_ylim(0, max(vector_counts.values) * 1.15)
save_fig(fig, "Fig_04_Attack_Vector_Distribution.png")

# ------------------------------------------------------------------------------
# FIG 5: Root Cause Vulnerability Breakdown
# ------------------------------------------------------------------------------
fig, ax = plt.subplots(figsize=(10, 5.2))
set_style(fig, ax, "Figure 5: Root Cause Vulnerability Assessment")
rc_col = "Root_Cause" if "Root_Cause" in df.columns else "Attack_Vector"
rc_counts = df[rc_col].value_counts().sort_values(ascending=True)
bars = ax.barh(rc_counts.index, rc_counts.values, color=ACCENT_ORANGE, edgecolor="#FFF3E0", alpha=0.9, height=0.6)
for bar in bars:
    w = bar.get_width()
    ax.text(w + 10, bar.get_y() + bar.get_height()/2, f"{int(w):,}", ha="left", va="center", color=TEXT_COLOR, fontweight="bold")
ax.set_xlabel("Vulnerability Attribution Frequency", color=TEXT_COLOR, fontsize=11, fontweight="bold")
ax.set_xlim(0, max(rc_counts.values) * 1.15)
save_fig(fig, "Fig_05_Root_Cause_Vulnerability_Breakdown.png")

# ------------------------------------------------------------------------------
# FIG 6: Threat Actor Landscape
# ------------------------------------------------------------------------------
fig, ax = plt.subplots(figsize=(9, 5))
set_style(fig, ax, "Figure 6: Threat Actor Attribution & Campaign Distribution")
ta_col = "Threat_Actor" if "Threat_Actor" in df.columns else "Attack_Type"
ta_counts = df[ta_col].value_counts().head(7).sort_values(ascending=True)
bars = ax.barh(ta_counts.index, ta_counts.values, color="#B388FF", edgecolor="#EDE7F6", height=0.6)
for bar in bars:
    w = bar.get_width()
    ax.text(w + 8, bar.get_y() + bar.get_height()/2, f"{int(w):,}", ha="left", va="center", color=TEXT_COLOR, fontweight="bold")
ax.set_xlabel("Attributed Campaign Incidents", color=TEXT_COLOR, fontsize=11, fontweight="bold")
ax.set_xlim(0, max(ta_counts.values) * 1.15)
save_fig(fig, "Fig_06_Threat_Actor_Landscape.png")

# ------------------------------------------------------------------------------
# FIG 7: MTTR and Resolution SLA Compliance
# ------------------------------------------------------------------------------
fig, ax = plt.subplots(figsize=(10, 5.2))
set_style(fig, ax, "Figure 7: Mean Time to Resolve (MTTR) by Severity Tier vs 24h SLA")
resolved_df = df[df["Status"].isin(["Resolved", "Closed"])].dropna(subset=["Resolution_Time_Hours"])
mttr_by_sev = resolved_df.groupby("Severity")["Resolution_Time_Hours"].mean().reindex(["Critical", "High", "Medium", "Low"])
colors = [SEVERITY_COLORS["Critical"], SEVERITY_COLORS["High"], SEVERITY_COLORS["Medium"], SEVERITY_COLORS["Low"]]
bars = ax.bar(mttr_by_sev.index, mttr_by_sev.values, color=colors, edgecolor="#FFFFFF", width=0.5)
ax.axhline(24.0, color="#FF5252", linestyle="--", linewidth=2, label="Enterprise SLA Threshold (24.0 Hours)")
for bar in bars:
    h = bar.get_height()
    ax.text(bar.get_x() + bar.get_width()/2, h + 0.6, f"{h:.1f} hrs", ha="center", va="bottom", color=TEXT_COLOR, fontweight="bold", fontsize=10)
ax.set_ylabel("Average Resolution Hours (MTTR)", color=TEXT_COLOR, fontsize=11, fontweight="bold")
ax.legend(facecolor=CARD_BG, edgecolor=ACCENT_GREEN, labelcolor=TEXT_COLOR, loc="upper right")
ax.set_ylim(0, max(mttr_by_sev.values) * 1.25)
save_fig(fig, "Fig_07_MTTR_and_SLA_Compliance.png")

# ------------------------------------------------------------------------------
# FIG 8: Departmental Financial Loss Risk
# ------------------------------------------------------------------------------
fig, ax = plt.subplots(figsize=(10, 5.5))
set_style(fig, ax, "Figure 8: Total Financial Loss Impact by Department ($ Millions USD)")
dept_loss = (df.groupby("Department")["Financial_Loss_USD"].sum() / 1e6).sort_values(ascending=True)
bars = ax.barh(dept_loss.index, dept_loss.values, color=plt.cm.cool(np.linspace(0.2, 0.85, len(dept_loss))), edgecolor="#80D8FF", height=0.6)
for bar in bars:
    w = bar.get_width()
    ax.text(w + 3, bar.get_y() + bar.get_height()/2, f"${w:,.1f}M", ha="left", va="center", color=TEXT_COLOR, fontweight="bold")
ax.set_xlabel("Cumulative Financial Damage ($ Millions USD)", color=TEXT_COLOR, fontsize=11, fontweight="bold")
ax.set_xlim(0, max(dept_loss.values) * 1.15)
save_fig(fig, "Fig_08_Departmental_Financial_Loss.png")

# ------------------------------------------------------------------------------
# FIG 9: Compromised Infrastructure Assets
# ------------------------------------------------------------------------------
fig, ax = plt.subplots(figsize=(10, 5.2))
set_style(fig, ax, "Figure 9: Target Infrastructure Asset Compromise Frequency")
asset_counts = df["Affected_Asset"].value_counts().sort_values(ascending=False)
bars = ax.bar(asset_counts.index, asset_counts.values, color="#FFD54F", edgecolor="#FFF8E1", width=0.55)
for bar in bars:
    h = bar.get_height()
    ax.text(bar.get_x() + bar.get_width()/2, h + 15, f"{int(h):,}", ha="center", va="bottom", color=TEXT_COLOR, fontweight="bold", fontsize=9.5)
ax.set_ylabel("Compromise Incidents", color=TEXT_COLOR, fontsize=11, fontweight="bold")
plt.xticks(rotation=20, ha="right")
ax.set_ylim(0, max(asset_counts.values) * 1.15)
save_fig(fig, "Fig_09_Compromised_Assets_Frequency.png")

# ------------------------------------------------------------------------------
# FIG 10: Multi-Factor Authentication (MFA) Defensive Impact
# ------------------------------------------------------------------------------
fig, ax = plt.subplots(figsize=(8.5, 5))
set_style(fig, ax, "Figure 10: MFA Status vs Severity Distribution (Defensive Efficacy)")
mfa_col = "Multi_Factor_Auth" if "Multi_Factor_Auth" in df.columns else "Multi_Factor_Authentication"
avail_cols = [c for c in ["Critical", "High", "Medium", "Low"] if c in df["Severity"].unique()]
cross = pd.crosstab(df[mfa_col], df["Severity"])[avail_cols]
cross.plot(kind="bar", stacked=True, ax=ax, color=[SEVERITY_COLORS[c] for c in avail_cols], edgecolor=DARK_BG, width=0.45)
ax.set_title("Figure 10: MFA Status vs Incident Severity Distribution", color=ACCENT_GREEN, fontsize=13, fontweight="bold", pad=15)
ax.set_ylabel("Incident Count", color=TEXT_COLOR, fontsize=10, fontweight="bold")
ax.set_xlabel("Multi-Factor Authentication Status", color=TEXT_COLOR, fontsize=10, fontweight="bold")
ax.legend(facecolor=CARD_BG, edgecolor=ACCENT_GREEN, labelcolor=TEXT_COLOR, title="Severity")
plt.xticks(rotation=0)
save_fig(fig, "Fig_10_MFA_Defensive_Impact.png")

# ------------------------------------------------------------------------------
# FIG 11: 5-Year Longitudinal Threat & Financial Trajectory
# ------------------------------------------------------------------------------
fig, ax1 = plt.subplots(figsize=(11, 5.5))
fig.patch.set_facecolor(DARK_BG)
ax1.set_facecolor(CARD_BG)
yearly = df.groupby("Year").agg(count=("Incident_ID", "count"), loss=("Financial_Loss_USD", lambda x: x.sum() / 1e6)).reset_index()

ax2 = ax1.twinx()
ax1.plot(yearly["Year"], yearly["count"], color=ACCENT_GREEN, marker="o", linewidth=2.8, markersize=8, label="Incident Volume")
ax2.plot(yearly["Year"], yearly["loss"], color=ACCENT_ORANGE, marker="s", linewidth=2.8, markersize=8, linestyle="--", label="Financial Loss ($M)")

ax1.set_xlabel("Year (2021-2025)", color=TEXT_COLOR, fontsize=11, fontweight="bold")
ax1.set_ylabel("Annual Incident Count", color=ACCENT_GREEN, fontsize=11, fontweight="bold")
ax2.set_ylabel("Total Financial Loss ($ Millions USD)", color=ACCENT_ORANGE, fontsize=11, fontweight="bold")
ax1.tick_params(colors=TEXT_COLOR)
ax2.tick_params(colors=TEXT_COLOR)
ax1.grid(True, linestyle="--", alpha=0.25, color="#164E3E")

for i, txt in enumerate(yearly["count"]):
    ax1.annotate(f"{txt:,}", (yearly["Year"][i], yearly["count"][i] + 25), color=ACCENT_GREEN, fontweight="bold", ha="center")
for i, txt in enumerate(yearly["loss"]):
    ax2.annotate(f"${txt:.1f}M", (yearly["Year"][i], yearly["loss"][i] + 8), color=ACCENT_ORANGE, fontweight="bold", ha="center")

ax1.set_title("Figure 11: 5-Year Enterprise Incident Frequency & Financial Damage Trajectory", color=ACCENT_GREEN, fontsize=13, fontweight="bold", pad=15)
ax1.set_xticks(yearly["Year"])
save_fig(fig, "Fig_11_Five_Year_Trajectory_Trend.png")

# ------------------------------------------------------------------------------
# FIG 12: Machine Learning Severity Confusion Matrix
# ------------------------------------------------------------------------------
fig, ax = plt.subplots(figsize=(8, 6.5))
set_style(fig, ax, f"Figure 12: Random Forest Severity Confusion Matrix (Acc: {ml_metrics['accuracy']}%)")
cm = np.array(ml_metrics["confusion_matrix"])
im = ax.imshow(cm, interpolation="nearest", cmap=plt.cm.Greens)
cbar = fig.colorbar(im, ax=ax, fraction=0.046, pad=0.04)
cbar.ax.tick_params(colors=TEXT_COLOR)

tick_marks = np.arange(len(SEVERITY_CLASSES))
ax.set_xticks(tick_marks)
ax.set_xticklabels(SEVERITY_CLASSES, rotation=0, color=TEXT_COLOR, fontweight="bold", fontsize=10)
ax.set_yticks(tick_marks)
ax.set_yticklabels(SEVERITY_CLASSES, color=TEXT_COLOR, fontweight="bold", fontsize=10)

thresh = cm.max() / 2.0
for i in range(cm.shape[0]):
    for j in range(cm.shape[1]):
        val = cm[i, j]
        ax.text(j, i, f"{val:,}", ha="center", va="center",
                color="white" if val > thresh else ACCENT_GREEN, fontweight="heavy", fontsize=12)

ax.set_ylabel("Ground Truth Severity Tier", color=TEXT_COLOR, fontsize=11, fontweight="bold")
ax.set_xlabel("ML Predicted Severity Tier", color=TEXT_COLOR, fontsize=11, fontweight="bold")
save_fig(fig, "Fig_12_ML_Confusion_Matrix.png")

# ------------------------------------------------------------------------------
# FIG 13: Random Forest Feature Importance Ranking
# ------------------------------------------------------------------------------
fig, ax = plt.subplots(figsize=(10, 5.5))
set_style(fig, ax, "Figure 13: Random Forest Feature Importance Ranking (Gini Impurity)")
fi_df = pd.DataFrame(ml_metrics["feature_importances"]).sort_values(by="Importance", ascending=True)
bars = ax.barh(fi_df["Feature"], fi_df["Importance"], color=ACCENT_GREEN, edgecolor="#A7FFEB", height=0.6)
for bar in bars:
    w = bar.get_width()
    ax.text(w + 0.005, bar.get_y() + bar.get_height()/2, f"{w*100:.1f}%", ha="left", va="center", color=TEXT_COLOR, fontweight="bold", fontsize=9.5)
ax.set_xlabel("Relative Feature Importance Weight", color=TEXT_COLOR, fontsize=11, fontweight="bold")
ax.set_xlim(0, max(fi_df["Importance"]) * 1.18)
save_fig(fig, "Fig_13_ML_Feature_Importance.png")

# ------------------------------------------------------------------------------
# FIG 14: Global Incident Density Heatmap
# ------------------------------------------------------------------------------
fig, ax = plt.subplots(figsize=(10, 5.5))
set_style(fig, ax, "Figure 14: Geographic Node Location vs Severity Density Heatmap")
avail_geo = [c for c in ["Critical", "High", "Medium", "Low"] if c in df["Severity"].unique()]
pivot_geo = pd.crosstab(df["Location"], df["Severity"])[avail_geo]
im = ax.imshow(pivot_geo.values, cmap="YlOrRd", aspect="auto")
cbar = fig.colorbar(im, ax=ax, fraction=0.035, pad=0.04)
cbar.ax.tick_params(colors=TEXT_COLOR)

ax.set_xticks(range(len(pivot_geo.columns)))
ax.set_xticklabels(pivot_geo.columns, color=TEXT_COLOR, fontweight="bold", fontsize=10)
ax.set_yticks(range(len(pivot_geo.index)))
ax.set_yticklabels(pivot_geo.index, color=TEXT_COLOR, fontweight="bold", fontsize=10)

for i in range(len(pivot_geo.index)):
    for j in range(len(pivot_geo.columns)):
        v = pivot_geo.values[i, j]
        ax.text(j, i, f"{v}", ha="center", va="center", color="black" if v > pivot_geo.values.max()/2 else "white", fontweight="bold")
ax.set_xlabel("Severity Tier", color=TEXT_COLOR, fontsize=11, fontweight="bold")
ax.set_ylabel("Global Infrastructure Node", color=TEXT_COLOR, fontsize=11, fontweight="bold")
save_fig(fig, "Fig_14_Global_Incident_Heatmap.png")

# ------------------------------------------------------------------------------
# FIG 15: Live AI Severity Triage Prediction Result Card
# ------------------------------------------------------------------------------
sample_payload = {
    "Attack_Type": "Ransomware", "Affected_Asset": "Database Server", "Department": "Finance",
    "Attack_Vector": "Phishing", "Multi_Factor_Auth": "Disabled", "Location": "North America",
    "Financial_Loss_USD": 125000.0, "Response_Time_Hours": 18.0, "Records_Affected": 15000
}
pred_result = predictor.predict_alert(sample_payload)

fig, ax = plt.subplots(figsize=(11, 4.2))
fig.patch.set_facecolor(DARK_BG)
ax.set_facecolor(DARK_BG)
ax.axis("off")

# Outer triage assessment card
card = patches.FancyBboxPatch((0.05, 0.05), 0.90, 0.90, boxstyle="round,pad=0.02,rounding_size=0.03",
                              facecolor=CARD_BG, edgecolor=ACCENT_GREEN, linewidth=2.0)
ax.add_patch(card)

ax.text(0.10, 0.85, "CYBERSHIELD // LIVE SOC TIER-1 AI INCIDENT TRIAGE SIMULATOR", 
        color="#8BAA9B", fontsize=10, fontweight="bold", family="sans-serif")

ax.text(0.10, 0.68, "Simulated Inbound Alert Payload:", color=TEXT_COLOR, fontsize=10.5, fontweight="bold")
ax.text(0.10, 0.56, f"• Infiltration: Ransomware via Phishing\n• Target: Finance Department (Database Server)\n• Defense State: MFA Disabled | Response Latency: 18.0 hrs", 
        color="#A7FFEB", fontsize=9.5, linespacing=1.4)

pred_sev = pred_result["predicted_severity"]
badge_col = SEVERITY_COLORS.get(pred_sev, ACCENT_GREEN)

# Prediction Result Badge
badge = patches.FancyBboxPatch((0.63, 0.45), 0.28, 0.35, boxstyle="round,pad=0.02,rounding_size=0.03",
                              facecolor="#051510", edgecolor=badge_col, linewidth=2.0)
ax.add_patch(badge)

ax.text(0.77, 0.71, "PREDICTED SEVERITY", color="#8BAA9B", fontsize=8.5, fontweight="bold", ha="center")
ax.text(0.77, 0.55, pred_sev.upper(), color=badge_col, fontsize=17, fontweight="heavy", ha="center")

conf = pred_result["confidence"]
ax.text(0.10, 0.28, f"Classification Confidence: {conf}%", color=ACCENT_GREEN, fontsize=12, fontweight="bold")

prob_str = " | ".join([f"{k}: {v}%" for k, v in pred_result["all_probabilities"].items()])
ax.text(0.10, 0.15, f"Posterior Probabilities: [ {prob_str} ]", color="#8BAA9B", fontsize=9)

save_fig(fig, "Fig_15_Live_AI_Alert_Prediction_Card.png")

print("\n" + "=" * 70)
print("SUCCESS: All 15 High-Resolution (300 DPI) Report Images Generated!")
print("Saved to:")
print("1. " + OUTPUT_DIRS[0])
print("2. " + OUTPUT_DIRS[1])
print("=" * 70)
