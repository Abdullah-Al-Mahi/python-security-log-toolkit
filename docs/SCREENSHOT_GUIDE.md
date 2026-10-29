# Screenshots and portfolio visuals: capture guide

**Screenshots are not included or fabricated in Phase 9.** Capture your actual
working application locally after running the instructions below. The images
should not show usernames, real private log paths or secrets that could harm
privacy. The synthetic test IPs are reserved examples.

| Suggested screenshot | How to obtain | What the caption should say |
|---|---|---|
| CLI ready | `security_log_toolkit status` and `doctor` | Tested local backend, v0.9.0 |
| Investigation summary | Open `reports/phase9_demo/analyst_summary.txt` | Synthetic evidence-driven investigation |
| Incidents table | Import `reports/phase9_demo/export/incidents.csv` | Four correlated/single-finding synthetic incidents |
| Linked timeline | Open `reports/phase9_demo/export/timelines.csv` | Chronological *linked* evidence, not whole-log history |
| Security test run | `python -m pytest -q` | Actual passing count on your own machine |
| Accuracy validation | Open `validation_summary.json` | Only four manually labeled synthetic scenarios |
| Architecture diagram | View `docs/ARCHITECTURE.md` on GitHub or Mermaid preview | Framework-neutral pipeline; UI planned for Phase 10 |

Windows 11 screenshot shortcut: **Win + Shift + S**, then save to a local
folder outside Git until you approve publication. Crop personal desktop details.
Do not remove the original evidence context from an image in a misleading way.

Recommended naming when later approved for publication:
`docs/images/01-cli-doctor.png`, `02-incidents.png`, `03-timeline.png`,
`04-tests.png`, `05-architecture.png`. Do not create links in the README before
those exact images exist. Add a caption saying "synthetic demonstration".

The **Phase 10 web dashboard** will be eligible for separate real screenshots
once installed and tested; do not label current CLI screenshots as dashboard UI.
