"""
Master Launcher for CYBERSHIELD from Workspace Root.
Forwards to cyber_security_incident_analytics/run.py
"""
import os
import sys

target = os.path.join(os.path.dirname(__file__), "cyber_security_incident_analytics", "run.py")
if os.path.exists(target):
    sys.path.insert(0, os.path.dirname(target))
    with open(target, "r", encoding="utf-8") as f:
        code = f.read()
    exec(compile(code, target, 'exec'))
else:
    print(f"[ERROR] Could not find {target}")

