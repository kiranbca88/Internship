"""
dashboard/app.py
----------------
Entrypoint to CYBERSHIELD – Cyber Security Incident Analytics & Threat Intelligence Dashboard.
Loads the complete enterprise SOC Command Center.
"""

import os
import sys

# Auto-launch via Streamlit if executed directly via `python dashboard/app.py` or VS Code "Run / Play" button
target_app = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "app.py"))
try:
    import streamlit.runtime as rt
    if not rt.exists():
        import subprocess
        # Free port 8501 if previously occupied by a stale process
        try:
            res = subprocess.run("netstat -ano | findstr :8501", shell=True, capture_output=True, text=True)
            for line in res.stdout.strip().split("\n"):
                if "LISTENING" in line:
                    pid = line.strip().split()[-1]
                    if pid and pid.isdigit() and int(pid) != os.getpid():
                        subprocess.run(f"taskkill /F /PID {pid}", shell=True, capture_output=True)
        except Exception:
            pass

        from streamlit.web import cli as stcli
        import webbrowser
        try:
            webbrowser.open("http://localhost:8501")
        except Exception:
            pass
        sys.argv = ["streamlit", "run", target_app, "--server.port=8501"]
        stcli.main()
        sys.exit(0)
except Exception:
    pass

# When running inside Streamlit runtime
if os.path.exists(target_app):
    sys.path.insert(0, os.path.dirname(target_app))
    with open(target_app, "r", encoding="utf-8") as f:
        code = f.read()
    exec(compile(code, target_app, 'exec'))
else:
    import streamlit as st
    st.error("app.py not found in parent directory.")
