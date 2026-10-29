
# OS Security Event Logger

## 1. Project Overview

The OS Security Event Logger is a Python-based Operating Systems project that analyzes system log entries, identifies predefined suspicious activities, and presents security alerts through a Streamlit dashboard.

The current prototype uses sample log data to demonstrate event parsing, security detection, reporting, and visualization.

## 2. Objectives

- Parse structured log entries.
- Detect repeated failed login attempts.
- Identify unauthorized-access and permission-denied events.
- Classify suspicious events as high severity.
- Display event statistics and security alerts.
- Export event data as CSV and JSON reports.

## 3. Features

- Log parsing using regular expressions.
- Configurable failed-login threshold.
- Detection of suspicious access activity.
- Command-line reporting.
- Interactive Streamlit dashboard.
- Severity filtering and message search.
- CSV and JSON report generation.
- Automated unit tests.

## 4. Technologies Used

- Python
- Streamlit
- Pandas
- Regular expressions
- JSON
- Git and GitHub
- Python unittest

## 5. Project Structure

OS-Security-Event-Logger/
- monitor/
  - log_monitor.py
- detection/
  - detector.py
- dashboard/
  - app.py
- data/
  - sample_logs.txt
- tests/
  - test_project.py
- main.py
- requirements.txt
- README.md
- .gitignore

## 6. Installation

Install Python, then install the project dependencies:

    python -m pip install -r requirements.txt

## 7. Running the Project

Run the command-line application:

    python main.py

Launch the interactive dashboard:

    python -m streamlit run dashboard/app.py

Run the automated tests:

    python -m unittest discover -s tests -v

## 8. Testing

The unit tests cover valid log parsing, invalid log handling, repeated failed-login detection, normal events, unauthorized access, permission-denied events, and failed logins below the configured threshold.

## 9. Current Limitations

The current prototype analyzes simulated sample logs. It does not automatically monitor live operating-system logs. Detection rules are predefined and may not identify every security threat.

## 10. Future Scope

- Integrate live operating-system log sources.
- Add date and time filters.
- Support additional security detection rules.
- Add alert notifications.
- Introduce user authentication and access controls.

## 11. Version Control

The project is maintained using Git and GitHub. Commit history documents the incremental development of the application.
