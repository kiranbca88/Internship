"""
run.py
------
Master execution runner for CYBERSHIELD – Cyber Security Incident Analytics
and Threat Intelligence Command Center.
"""

import os
import sys
import subprocess
import webbrowser

PROJECT_ROOT = os.path.dirname(os.path.abspath(__file__))
if PROJECT_ROOT not in sys.path:
    sys.path.insert(0, PROJECT_ROOT)

PYTHON_EXE = sys.executable

def print_banner():
    print("""
====================================================================
     🛡️  CYBERSHIELD // 5-YEAR CYBER INCIDENT ANALYTICS  🛡️
         SOC Command Center • Threat Intelligence • AI ML
====================================================================
    """)

def run_step(step_name: str, script_rel_path: str, is_module: bool = False, extra_args: list = None):
    print(f"\n[RUNNING] {step_name}...")
    cmd = [PYTHON_EXE]
    if is_module:
        cmd.extend(["-m", script_rel_path])
    else:
        full_path = os.path.join(PROJECT_ROOT, script_rel_path)
        cmd.append(full_path)
    if extra_args:
        cmd.extend(extra_args)

    env = os.environ.copy()
    scripts_dir = os.path.join(os.path.dirname(PYTHON_EXE), "Scripts")
    env["PATH"] = f"{os.path.dirname(PYTHON_EXE)};{scripts_dir};" + env.get("PATH", "")
    env["PYTHONIOENCODING"] = "utf-8"
    env["PYTHONUTF8"] = "1"

    result = subprocess.run(cmd, cwd=PROJECT_ROOT, env=env)
    if result.returncode == 0:
        print(f"[SUCCESS] {step_name} completed successfully.")
        return True
    else:
        print(f"[ERROR] {step_name} failed with exit code {result.returncode}.")
        return False

def generate_5y_data():
    return run_step("Step 1: 5-Year Telemetry Data Synthesis (7,000 Incidents)", "src/generate_5_years.py")

def train_ml():
    return run_step("Step 2: AI Incident Severity Classification (Random Forest ML)", "src/ml_model.py")

def export_excel():
    return run_step("Step 3: Styled Multi-Tab Excel Workbook Export", "src/export_excel.py")

def run_tests():
    return run_step("Step 4: Automated Unit Tests (pytest)", "pytest", is_module=True, extra_args=["-v", "tests/test_analysis.py"])

def launch_dashboard():
    print("\n[LAUNCHING] Starting CYBERSHIELD Streamlit SOC Dashboard...")
    print("Opening your browser to: http://localhost:8501")
    print("Press Ctrl + C in this terminal to stop the server.\n")
    webbrowser.open("http://localhost:8501")
    cmd = [PYTHON_EXE, "-m", "streamlit", "run", os.path.join(PROJECT_ROOT, "app.py")]
    env = os.environ.copy()
    scripts_dir = os.path.join(os.path.dirname(PYTHON_EXE), "Scripts")
    env["PATH"] = f"{os.path.dirname(PYTHON_EXE)};{scripts_dir};" + env.get("PATH", "")
    env["PYTHONIOENCODING"] = "utf-8"
    env["PYTHONUTF8"] = "1"
    try:
        subprocess.run(cmd, cwd=PROJECT_ROOT, env=env)
    except KeyboardInterrupt:
        print("\n[STOPPED] Dashboard server closed.")

def run_all_pipeline():
    print_banner()
    print("Executing full 5-year CYBERSHIELD data pipeline and ML training...")
    if not generate_5y_data(): return
    if not train_ml(): return
    if not export_excel(): return
    if not run_tests(): return

    print("\n" + "=" * 68)
    print("🎉 ALL DATASETS, ML MODELS, AND REPORTS GENERATED SUCCESSFULLY!")
    print("=" * 68)
    launch_dashboard()

def interactive_menu():
    while True:
        print_banner()
        print("Please choose an option to run:")
        print("  [1] Run All (Data Gen 5-Years -> Train ML Model -> Excel -> Tests -> Dashboard)")
        print("  [2] Launch CYBERSHIELD Dashboard Only (Browser)")
        print("  [3] Generate 5-Year Dataset (7,000 Incidents)")
        print("  [4] Train AI Severity Classifier (Random Forest ML)")
        print("  [5] Export Excel Report (outputs/incident_analysis.xlsx)")
        print("  [6] Run Automated Unit Tests (pytest)")
        print("  [0] Exit")
        print("=" * 68)
        choice = input("Enter your choice (1-6, or 0 to exit): ").strip()

        if choice == "1":
            run_all_pipeline()
            break
        elif choice == "2":
            launch_dashboard()
            break
        elif choice == "3":
            generate_5y_data()
            input("\nPress Enter to return to menu...")
        elif choice == "4":
            train_ml()
            input("\nPress Enter to return to menu...")
        elif choice == "5":
            export_excel()
            input("\nPress Enter to return to menu...")
        elif choice == "6":
            run_tests()
            input("\nPress Enter to return to menu...")
        elif choice == "0":
            print("\nExiting. Stay secure!")
            break
        else:
            print("\nInvalid selection. Please choose a valid number.")

if __name__ == "__main__":
    if len(sys.argv) > 1:
        arg = sys.argv[1].lower()
        if arg in ["--all", "-a"]:
            run_all_pipeline()
        elif arg in ["--dashboard", "-d"]:
            launch_dashboard()
        elif arg in ["--ml", "-m"]:
            train_ml()
        elif arg in ["--data"]:
            generate_5y_data()
        elif arg in ["--test", "-t"]:
            run_tests()
        else:
            interactive_menu()
    else:
        interactive_menu()
