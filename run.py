
import subprocess
import sys
from pathlib import Path

# Get the project root directory
PROJECT_ROOT = Path(__file__).resolve().parent

# Locate the Streamlit dashboard
app_path = PROJECT_ROOT / "dashboard" / "app.py"

# Launch the dashboard
subprocess.run(
    [
        sys.executable,
        "-m",
        "streamlit",
        "run",
        str(app_path)
    ],
    cwd=PROJECT_ROOT
)
