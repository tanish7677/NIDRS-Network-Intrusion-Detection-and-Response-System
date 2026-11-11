"""
NIDRS - retrain every model in the correct order
================================================
Run this ONCE after replacing the project files (and again whenever you
change the training data):

    python retrain_all.py

Order matters:
  1. multiclass_model.py   - trains the 5-class Random Forest with SMOTE and
                             saves the protocol/service/flag encoders
  2. train_model.py        - binary Random Forest, re-uses those encoders
  3. train_live_anomaly_model.py - Isolation Forest on data/live_flows.csv

Check the output of step 1 for the line:
    SMOTE applied using: ...
"""

import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent

STEPS = [
    (ROOT / "model", "multiclass_model.py"),
    (ROOT / "model", "train_model.py"),
    (ROOT / "data", "train_live_anomaly_model.py"),
]

for folder, script in STEPS:

    print("\n" + "=" * 60)
    print(f"Running {script}")
    print("=" * 60)

    result = subprocess.run([sys.executable, script], cwd=folder)

    if result.returncode != 0:
        print(f"\n{script} failed - stopping.")
        sys.exit(result.returncode)

print("\nAll models retrained successfully.")
