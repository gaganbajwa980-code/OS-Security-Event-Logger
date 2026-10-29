
# OS Security Event Logger

## Overview
A Python-based Operating Systems project that analyzes log events, detects predefined suspicious activity, and displays alerts in a Streamlit dashboard.

## Features
- System log parsing
- Repeated failed-login detection
- Unauthorized-access detection
- Severity classification
- Interactive dashboard and charts
- Search and filtering
- CSV report export

## Technologies
Python, Streamlit, Pandas, Regular Expressions, Git and GitHub.

## Installation
```bash
python -m pip install -r requirements.txt
```

## Run
```bash
python -m streamlit run dashboard/app.py
```

## Test
```bash
python -m unittest discover -s tests -v
```

## Current Limitations
The current prototype analyzes simulated sample logs. Live operating-system log monitoring is planned as a future enhancement.
