# 🛡️ CYBERSHIELD – ENTERPRISE HACKER MATRIX SOC COMMAND CENTER
### SECURITY OPERATIONS CENTER | 2021–2025
**Enterprise Cyber Security Incident Analytics & Threat Intelligence Command Center**  
*BCA Final-Year Academic Capstone & Professional Portfolio Project*

---

## 📌 1. Project Overview & Concept
**CYBERSHIELD** is an enterprise-grade Security Operations Center (SOC) incident intelligence command platform combining two design philosophies:
- **Enterprise Design**: Clean, structured layout, modern typography, executive KPI panels, professional Plotly data visualisations, and intuitive vertical navigation.
- **Hacker Matrix Aesthetics**: Deep black canvas (`#020807`), dark emerald surfaces (`#061410`), neon green highlights (`#00FF88`), matrix digital rain elements, cyber gridlines, and animated threat-monitoring radar dots.

Analyzing **7,000 realistic incident records** across five complete calendar years (**2021–2025**), the platform provides operational visibility, adversary profiling, longitudinal trend forecasting, and AI-driven alert severity prediction.

---

## 🎨 2. Consistent Hacker Matrix Palette

| Role | Color Name | Hex Code | Purpose |
| :--- | :--- | :--- | :--- |
| **Main Background** | Deep Black | `#020807` | Global canvas background with digital grid |
| **Sidebar Background** | Matrix Black | `#010504` | Vertical fixed-feel left navigation panel |
| **Card Background** | Dark Emerald | `#061410` | KPI cards and panel containers |
| **Secondary Background**| Deep Forest | `#092019` | Hover states and elevated containers |
| **Primary Highlight** | Neon Green | `#00FF88` | Active navigation, glowing borders, KPIs |
| **Secondary Accent** | Matrix Green | `#00CC66` | Data markers, secondary metrics, borders |
| **Tertiary Accent** | Emerald | `#00A86B` | Plotly bars, category breakdowns |
| **Tech Highlight** | Cyan | `#00E5FF` | Financial loss, timeline trajectories |
| **Text Primary** | White-Green | `#E8FFF4` | High-contrast readable typography |
| **Text Muted** | Slate-Green | `#8BAA9B` | Metric labels, captions, metadata |
| **Critical Alerts** | Matrix Red | `#FF1744` | Critical severity, high-urgency threats |
| **High Alerts** | Matrix Orange | `#FF9100` | High severity, major operational alerts |
| **Medium Alerts** | Matrix Yellow | `#FFEA00` | Medium severity incidents |
| **Low Alerts** | Emerald Green | `#00FF88` | Low severity, contained incidents |

---

## 🗂️ 3. Project Directory Structure
```text
cyber_security_incident_project/
│
├── app.py                      # Main Streamlit SOC Dashboard (with auto-launcher hook)
├── requirements.txt            # Python Dependencies (Streamlit, Plotly, Scikit-learn, etc.)
├── README.md                   # Comprehensive Project Documentation & Viva Guide
├── cyber_incidents_5_years.csv # 5-Year Telemetry Dataset (7,000 records, 2021–2025)
├── run_dashboard.bat           # One-Click Windows Batch Launcher
├── run.py                      # Master Python Execution Runner
│
├── modules/                    # Reusable Python Engineering Modules
│   ├── __init__.py             # Package Initializer
│   ├── data_processing.py      # Telemetry ingestion, column normalization, KPI & YoY math
│   ├── analytics.py            # High-performance Plotly visual analytics figures
│   └── ml_model.py             # Scikit-learn Random Forest classifier & live inference
│
└── assets/                     # Visual Design & Styling
    └── styles.css              # Custom Hacker Matrix Cyber SOC CSS Stylesheet
```

---

## 🧭 4. Completely Redesigned Left Sidebar

The left navigation panel (280px wide) features:
1. **Header & Logo**:
   - Shield-style SOC icon (`🛡️`)
   - `CYBERSHIELD` (Neon green title)
   - `ENTERPRISE SOC` (Subtitle)
   - Pulsating status badge: `● SYSTEM ONLINE`
2. **9 Working Navigation Options**:
   - `🛡️ Command Center`: Executive overview, 8 glowing KPI cards, live-style dispatch feed, monthly influx trajectory.
   - `📡 Threat Intelligence`: Adversary matrix, threat actor volume vs loss, attack vectors, exfiltration risk bubble plot.
   - `📊 Incident Analytics`: Departmental compromise, global SOC nodes, MFA defense efficacy, asset vs attack heatmap.
   - `⚡ Attack Analysis`: Breakdown of 10 attack types, root cause Pareto chart, tactical response metrics.
   - `📈 Five-Year Comparison`: 2021–2025 longitudinal comparison, YoY growth rates, SLA MTTR performance.
   - `🤖 ML Predictions`: Scikit-learn Random Forest classifier, metrics, confusion matrix, feature importances, and live alert severity simulator.
   - `🔍 Incident Management`: Searchable telemetry table, forensic inspector dossier, CSV export.
   - `📑 Reports & Export`: Executive audit summary generator, SLA compliance review, text and CSV downloads.
   - `⚙️ System Settings`: 20-attribute schema data dictionary, runtime diagnostics, environment metadata.
3. **Sidebar System Status Card**:
   - Security Systems: `Online`
   - Database: `Connected`
   - Dataset Period: `2021–2025`
   - Application Version: `1.0.0`
   - Matrix SOC Node indicator: `[ MATRIX SOC NODE #01 ACTIVE ]`
   - Footer tagline: `STAY SECURE • STAY AHEAD`

---

## 📊 5. Dataset Specification (7,000 Records, 2021–2025)
All 20 required attributes are preserved with safe alias mappings:
`Incident_ID`, `Date`, `Year`, `Month`, `Quarter`, `Attack_Type`, `Severity`, `Status`, `Department`, `Location`, `Affected_Asset`, `Threat_Actor`, `Attack_Vector`, `Root_Cause`, `Response_Time_Hours`, `Resolution_Time_Hours`, `Records_Affected`, `Financial_Loss_USD`, `Data_Exfiltrated`, `Multi_Factor_Auth`.

---

## ⚡ 6. How to Run on Windows / VS Code

### Step 1: Open Terminal in VS Code
Press ``Ctrl + ` `` to open the terminal in the workspace directory.

### Step 2: Install Dependencies
```powershell
python -m pip install -r requirements.txt
```

### Step 3: Launch the Dashboard
```powershell
python -m streamlit run app.py
```

### Alternative: One-Click Execution
Double-click [`run_dashboard.bat`](run_dashboard.bat) from File Explorer to launch the dashboard and open your browser at:
👉 **`http://localhost:8501`**
