# SENTINEL — OS Security Event Logger

A Python-based Operating Systems security monitoring application that collects system events, detects suspicious activities, manages security incidents, and presents monitoring information through a modern interactive dashboard.

## 1. Project Overview

SENTINEL is designed to demonstrate how operating-system security events can be monitored and analyzed. It processes Windows Event Log data and sample log files, applies predefined detection rules, identifies potentially suspicious activities, and displays the results through a dashboard.

The application also supports incident tracking, configurable detection thresholds, system diagnostics, and report exports.

## 2. Objectives

- Monitor and analyze operating-system security events.
- Identify suspicious activities using predefined detection rules.
- Detect repeated failed login attempts.
- Identify important security events such as account creation and audit-log clearing.
- Generate and manage security incidents.
- Provide an interactive dashboard for monitoring and analysis.
- Export event and incident information in CSV and JSON formats.
- Maintain a modular and testable application structure.

## 3. Key Features

- Windows Event Log monitoring.
- Sample-file and simulated-event monitoring modes.
- Event parsing and normalization.
- Seven predefined security detection rules.
- Configurable failed-login detection threshold.
- Incident creation, correlation, status management, and persistence.
- Real-time monitoring controls, including start, pause, resume, and stop.
- Security alerts and severity classification.
- Event filtering and search.
- Dashboard analytics and system diagnostics.
- CSV and JSON report exports.
- Automated unit testing.

## 4. Technologies Used

- Python
- Streamlit
- Pandas
- Plotly
- Windows Event Log interfaces
- Regular Expressions
- XML Parsing
- JSON
- Git and GitHub
- Python unittest

## 5. Project Structure

```text
OS-Security-Event-Logger/
│
├── dashboard/
│   ├── app.py
│   ├── components.py
│   ├── theme.py
│   └── views/
│       ├── overview.py
│       ├── analytics.py
│       ├── events.py
│       ├── investigations.py
│       ├── system.py
│       └── threats.py
│
├── data/
│   └── sample_logs.txt
│
├── detection/
│   ├── detector.py
│   ├── rules.py
│   └── incident_manager.py
│
├── monitor/
│   ├── log_monitor.py
│   ├── event_models.py
│   ├── diagnostics.py
│   ├── windows_monitor.py
│   ├── app_state.py
│   └── controller.py
│
├── tests/
│   ├── test_project.py
│   ├── test_foundations.py
│   ├── test_windows_monitor.py
│   ├── test_detection.py
│   ├── test_controller.py
│   ├── test_app_state.py
│   ├── test_dashboard_interaction.py
│   └── test_redesigned_dashboard.py
│
├── main.py
├── run.py
├── requirements.txt
├── README.md
└── .gitignore
```

## 6. Monitoring and Detection

SENTINEL supports different event sources, including live Windows Event Logs, simulated replay, and static sample files.

The detection engine evaluates collected events against predefined rules. Examples include:

- Repeated failed login attempts.
- Audit log clearing.
- User account creation.
- Security group membership changes.
- New service installation.
- Unauthorized access and permission-denied activities.

Detection results can generate security alerts and incidents. Related detections can be correlated to avoid unnecessary duplicate incidents.

## 7. Dashboard

The Streamlit dashboard provides the following sections:

- Overview: Monitoring status, key metrics, and security activity.
- Analytics: Event statistics and visual analysis.
- Events: Event exploration, filtering, and exports.
- Investigations: Incident tracking and status management.
- System: Monitoring diagnostics and system information.
- Threats: Detection rules and security findings.

The dashboard also supports monitoring controls and dark/light theme presentation.

## 8. Installation and Execution

### Requirements

- Python 3.10 or later.
- Windows operating system for live Windows Event Log collection.
- Required Python packages listed in `requirements.txt`.

### Installation

Clone the repository:

```bash
git clone https://github.com/gaganbajwa980-code/OS-Security-Event-Logger.git
```

Move into the project directory:

```bash
cd OS-Security-Event-Logger
```

Install dependencies:

```bash
python -m pip install -r requirements.txt
```

### Run the application

Launch the dashboard:

```bash
python run.py
```

Alternatively:

```bash
python -m streamlit run dashboard/app.py
```

Note: Access to certain Windows Event Log channels may require appropriate Windows permissions. Sample-data mode can be used for demonstration and testing.

## 9. Testing

The project uses Python's built-in `unittest` framework to verify its functionality.

Run the complete test suite:

```bash
python -m unittest discover -s tests -v
```

Latest recorded test result:

- Total tests executed: 97
- Tests passed: 97
- Failed tests: 0

Testing covers event parsing, detection rules, incident management, monitoring lifecycle, application state, dashboard interactions, Windows Event Log handling, and data persistence.

## 10. Current Limitations

- Live Windows Event Log collection is platform-dependent.
- Access to protected event channels depends on system permissions.
- Detection is based on predefined rules rather than a trained machine-learning model.
- Detection accuracy depends on the quality and availability of collected event data.
- The application is currently designed as a local monitoring prototype rather than a centralized enterprise security platform.

## 11. Future Scope

- Introduce machine-learning-based anomaly detection.
- Extend monitoring to Linux and other operating systems.
- Add remote and centralized log collection.
- Introduce email or external notification integrations.
- Develop advanced threat correlation and investigation capabilities.
- Add user authentication and role-based access control.
- Improve scalability for large volumes of security events.

## 12. Version Control

The project is maintained using Git and GitHub. Development has been organized into 14 incremental revisions on the `feature/realtime-monitoring` branch.

The revisions document the development of the initial logger, event parsing, detection improvements, dashboard functionality, automated testing, Windows monitoring, incident management, application-state handling, dashboard redesign, and project configuration.

**GitHub Repository:**  
https://github.com/gaganbajwa980-code/OS-Security-Event-Logger

**Development Branch:** `feature/realtime-monitoring`

---

*Developed as an academic Operating Systems project.*