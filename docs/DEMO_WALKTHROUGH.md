
# Sentinel — Five-Minute Interview Demonstration

This demonstration uses bundled synthetic data only.

## Preparation

Install the optional web dependencies and start Streamlit from the project root:

```powershell
.\.venv\Scripts\python.exe -m pip install -e ".[dev,web]"

.\.venv\Scripts\python.exe -m streamlit run dashboard\app.py --server.address 127.0.0.1 --server.port 8501
```

Open http://127.0.0.1:8501 in a browser.

## 1. Project Introduction — 30 seconds

"Sentinel is a Python-based security log analysis and incident investigation toolkit. It analyzes supported Linux and Windows authentication events, applies configurable detection rules, and correlates related findings into evidence-linked incidents."

Explain that the tool has both a command-line interface and a Streamlit dashboard using the same analysis engine.

## 2. Command Center — 60 seconds

Open the Command Center.

Using the bundled synthetic demo, show:

| Metric | Expected |
|---|---:|
| Events | 29 |
| Findings | 6 |
| Incidents | 4 |
| Linked evidence records | 22 |

Highlight the severity distribution, source-IP analysis and evidence activity chart.

Clarify that these values come from synthetic data rather than live network monitoring.

## 3. Incident Investigation — 90 seconds

Open Incident Explorer.

Filter to critical incidents and select one case.

Demonstrate:

- Incident severity and source IP
- Platform and affected host
- Detection rule identifiers
- Analyst summary
- Linked evidence references

Then open Evidence Timeline and show the chronological relationship between authentication events.

Explain that suspicious login sequences require further investigation before compromise can be established.

## 4. Detection Configuration — 45 seconds

Open Detection Lab.

Show the rule controls and explain that modifications are session-only.

Change one rule setting, apply it, and re-run the bundled synthetic data.

Restore the committed defaults before continuing.

## 5. Validation and Reports — 60 seconds

Open Validation & Performance.

Run the labeled synthetic scenario validation and explain its limited scope.

Then open Report Center and show the downloadable CSV/JSON investigation bundle.

Explain that the SHA-256 manifest supports comparison of exported file contents against their recorded hashes.

## 6. Closing — 15 seconds

"The main engineering focus was preserving evidence traceability while supporting two log formats and multiple investigation workflows. I separated the Python security backend from the interface, added defensive input validation, and maintained automated regression tests."

## Limitations

Sentinel is a local portfolio prototype, not a production SIEM.

It does not provide live network monitoring, authenticated multi-user deployment or native binary EVTX parsing.

All demonstration figures are derived from bundled synthetic fixtures.
