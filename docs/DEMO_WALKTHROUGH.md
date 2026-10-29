# Five-minute internship demonstration (offline)

This walkthrough uses **bundled synthetic data exclusively**. Nothing is
uploaded or published. Run all commands from the repository root in VS Code.

## Preparation (Windows 11 PowerShell)

```powershell
.\.venv\Scripts\python.exe -m pip install -e ".[dev]"
.\.venv\Scripts\python.exe -m security_log_toolkit doctor
.\.venv\Scripts\python.exe -m pytest -q
```

Expected on the Phase 9 baseline: doctor `READY`, **all 360 Phase 8 tests plus
Phase 9 tests passing** (see installed test output). The complete suite must be
run on your machine before citing a test count as your own result.

## Step 1 — Create presentation-ready artifacts (45–60 seconds of speech)

```powershell
.\.venv\Scripts\python.exe scripts/demo_portfolio.py --output-dir reports/phase9_demo
```

Expected synthetic summary: **29 normalized events, 6 findings, 4 incidents,
22 linked evidence records**. There are **4 manually labeled scenarios, 41 events,
6 TP, 0 FP, 0 FN** for the rule/IP scenario-label check. These metrics do not
measure field accuracy or production threat detection performance.

Outputs:

- `reports/phase9_demo/analyst_summary.txt` — talking points
- `reports/phase9_demo/investigation.json` — complete investigation record
- `reports/phase9_demo/export/` — five CSV files, JSON and SHA-256 manifest
- `reports/phase9_demo/validation_summary.json` — synthetic validation summary
- `reports/phase9_demo/portfolio_manifest.json` — SHA-256 verification index

The script **refuses to overwrite** an existing output directory. To repeat,
choose `--output-dir reports/phase9_demo_2` rather than deleting earlier reports.
Do not commit files from `reports/` to Git.

## Step 2 — Show the detection and response workflow (90 seconds)

1. Open `analyst_summary.txt`. Explain that the toolkit parses Linux OpenSSH
   and Windows Security 4624/4625 XML into a shared UTC event model.
2. Open `export/incidents.csv`. Point to two critical and two high severity
   synthetic incidents, grouped by host/platform/source IP.
3. Open `export/findings.csv`. Explain brute force, password spray and failed
   attempts followed by a successful authentication.
4. Open `export/timelines.csv`. Identify the failed-to-successful authentication
   pattern. Explicitly state **it is an investigative lead, not proof of compromise**.
5. Open `export/export_manifest.json`. Explain SHA-256 detects content changes
   when compared with a trusted manifest; the file is not a signed chain of custody.

## Step 3 — Show defensive testing (60 seconds)

```powershell
.\.venv\Scripts\python.exe -m security_log_toolkit validate --output reports/phase9_validation.json
.\.venv\Scripts\python.exe -m security_log_toolkit benchmark --events 1000 --runs 3 --output reports/phase9_benchmark.json
```

Describe malicious-input cases: invalid IPs, oversized logs, XML DTD/entities,
misleading cross-host activity, and path traversal in scenario manifests.
Benchmark timing is **hardware-dependent in-memory analysis**, excluding raw
parsing, file writing and UI overhead.

## Step 4 — Explain architecture and upcoming UI (60 seconds)

Open [`ARCHITECTURE.md`](ARCHITECTURE.md). Explain that parsing, detection,
correlation, timeline generation, validation and export functions are independent
of the CLI. Phase 10 will be a **free local Streamlit dashboard** on the same
backend; **it is not implemented in Phase 9**.

## Step 5 — Show development evidence and close (30 seconds)

```powershell
git --no-pager log -6 --oneline
.\.venv\Scripts\python.exe -m pytest -q
```

Suggested closing: "I built this to demonstrate an end-to-end SOC investigation
workflow, with repeatable synthetic experiments and evidence-linked exports. My
next milestone is a local dashboard calling the same tested Python services."

## Suggested screenshots (capture manually)

See [`SCREENSHOT_GUIDE.md`](SCREENSHOT_GUIDE.md). Capture **real application
screenshots from your local computer**. Do not present example image mockups as
working UI. Phase 10 dashboard screenshots can be added only when built.
