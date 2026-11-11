
# Sentinel — Five-Minute Project Demonstration

**Project:** Python Security Automation & Log Correlation Toolkit  
**Interface:** Sentinel Prism  
**Demonstration data:** Bundled synthetic authentication logs

This is the walkthrough I use to present my project during technical interviews.

## Preparation

From the repository root:

```powershell
.\.venv\Scripts\python.exe -m pip install -e ".[dev,web]"

.\.venv\Scripts\python.exe -m streamlit run dashboard\app.py --server.address 127.0.0.1 --server.port 8501
```

Open http://127.0.0.1:8501.

## 1. Introduction — 30 Seconds

"I built Sentinel as a Python-based security log analysis and incident investigation toolkit.

It processes supported Linux and Windows authentication events, applies configurable detection rules, and correlates related findings into incidents with traceable evidence.

I also developed a Streamlit dashboard to make the investigation process easier to explore."

## 2. Command Center — 60 Seconds

Open the Command Center.

"I designed this workspace to provide an overview of analyzed authentication activity.

The bundled synthetic dataset contains 29 events, producing six detection findings, four incidents, and 22 linked evidence records.

The charts summarize severity, detection rules, source IP addresses, and evidence activity."

Mention that the demonstration uses synthetic logs, not live system monitoring.

## 3. Incident Explorer — 90 Seconds

Open Incident Explorer and select a critical incident.

"This section allows me to investigate individual cases using source IP, host, platform, detection rule, and severity information.

Instead of showing only an alert, Sentinel preserves references to the events that contributed to each finding."

Open Evidence Timeline.

"The timeline shows the chronological sequence of linked evidence. A successful login after repeated failures is treated as an investigative signal, not proof of compromise."

## 4. Detection Lab — 45 Seconds

Open Detection Lab.

"I made the detection thresholds configurable so the analysis can be adjusted without changing the detection code.

The dashboard applies these settings for the current browser session, while the original YAML configuration remains unchanged."

Temporarily disable a rule, re-run the synthetic demo, then restore the committed defaults.

## 5. Validation and Reporting — 60 Seconds

Open Validation & Performance.

"I tested the detection engine using manually labeled synthetic scenarios and added tests for malformed inputs, unsafe XML declarations, file limits, and correlation edge cases.

The scenario-level detection results are reproducible, but I do not treat them as real-world accuracy estimates."

Open Report Center.

"Finally, I can export structured investigation records as CSV and JSON files with SHA-256 integrity metadata."

## 6. Closing — 15 Seconds

"The most important part of this project was maintaining evidence traceability while integrating multiple log formats, configurable detection rules, and two interfaces.

I built the dashboard on top of the existing Python services and maintained regression tests throughout development."

## Additional Technical Discussion

For longer interviews, I can demonstrate:

- The command-line workflow.
- YAML rule validation and overrides.
- Incident correlation boundaries.
- Evidence source references.
- Automated regression tests.
- CSV/JSON reporting.
- Defensive input validation.
- Local deployment limitations.

## Scope

All example incidents come from synthetic authentication logs.

Sentinel is a local prototype, not a production SIEM, live network monitor, or authenticated public application.
