# Phase 10 — Sentinel Local SOC Dashboard

**Status:** implemented in project source; must pass the owner's Windows 11
browser acceptance test before the project is declared complete.

## Safety and intended deployment

- The interface is a **local single-user developer tool**, not a hardened,
  authenticated, multi-user application. It has **no login system**.
- `.streamlit/config.toml` binds the server to `127.0.0.1`. Never change this to
  `0.0.0.0`, deploy it to the public internet, port-forward it, or put it behind
  a public proxy when viewing real authentication data.
- `browser.gatherUsageStats=false` disables Streamlit's usage-statistics setting.
- Uploaded raw files are processed in a temporary directory, which is deleted
  whether analysis succeeds or fails. **Streamlit's uploader and session state
  may still retain data in server memory until cleared or the process exits**;
  do not treat this as an audited data-erasure guarantee.
- The UI never writes uploads or reports under `reports/` automatically. Downloads
  are created in memory; the browser saves files only when you click Download.
- The UI is offline from an analysis perspective. Installing dependencies via
  pip requires an internet connection once; runtime uses no paid API or cloud.
- Linux authentication logs require an explicit **year and original timezone
  offset**. Windows input is *Security Event XML* (4624/4625), not `.evtx`.
- Maximum uploads: **4** files, **16 MiB each**, **32 MiB combined**. Existing
  investigation JSON imports are at most **50 MiB**. These are resource limits,
  not a defense against every potentially malicious input.
- Analyze only logs you are authorized to access. Review private data before
  downloading or forwarding incident reports.

## Install on Windows 11 / VS Code

From the root of your existing repository:

```powershell
Set-Location "$HOME\CyberSecurity-Projects\python-security-log-toolkit"
.\.venv\Scripts\python.exe -m pip install -e ".[dev,web]"
.\.venv\Scripts\python.exe -m security_log_toolkit --version
.\.venv\Scripts\python.exe -m streamlit --version
.\.venv\Scripts\python.exe -m pytest -q
```

If the installation cannot find Streamlit, first confirm Windows has internet
access and that pip can contact PyPI; do not install unofficial wheels. The web
extra is optional: **the command-line toolkit remains runnable without it**.

Start the browser interface with an explicit loopback bind:

```powershell
.\.venv\Scripts\python.exe -m streamlit run dashboard\app.py --server.address 127.0.0.1 --server.port 8501
```

Open **http://127.0.0.1:8501** in your local browser if it doesn't open
itself. Keep this terminal open while using the dashboard. To stop the server,
click inside the terminal and press **Ctrl+C**. No remote URL is generated.

## Sidebar sections / usage

1. **Command center:** immediately loads checked-in **synthetic** samples. The
   baseline shows 29 normalized events, six findings, four incidents (two
   critical, two high), and 22 linked evidence events. Use charts to compare
   severity, rules, source IPs and timeline activity.
2. **Log intake:** upload `.log`/`.txt` Linux syslog or Windows `.xml`. Enter
   Linux year and UTC offset before clicking **Analyze uploaded logs**.
   You may also import an existing toolkit investigation `.json` for review.
   The UI does not automatically run processing when simply selecting a file.
3. **Incident explorer:** filter by severity, platform, rule, host, IP, or
   account. Select an incident to view analyst interpretation and linked
   evidence. A login success after failures is **not** proof of compromise.
4. **Evidence timeline:** inspect event stages, timestamps, source-file labels,
   and linked evidence IDs. Timelines represent **linked detection evidence
   only**, not every raw log record.
5. **Detection lab:** modify rule enabled/severity/windows/thresholds and
   correlation time limits **for this browser session**. Click **Apply**,
   then re-run the synthetic demo or analyze another upload. The tracked YAML
   files remain untouched. Download the adjusted YAML if you want to save it
   for future manual review. **Reload synthetic demonstration** in the sidebar
   always uses the committed default config instead.
6. **Validation & performance:** run the existing manually labeled synthetic
   accuracy exercise and bounded, in-memory performance benchmark. These do
   **not** establish production detection accuracy or total ingest speed.
7. **Report center:** download JSON, five related CSVs, the manifest, or one
   ZIP containing all seven files. SHA-256 values protect integrity relative
   to the manifest, **not authorship**.

Use **Clear investigation session** to remove the current report and config
settings from app session state, reset the uploader widgets, and return to a
blank investigation view. Stopping Streamlit closes the application process.

## Backend contract

`src/security_log_toolkit/dashboard/service.py` contains no Streamlit import.
It uses `analyze_raw_logs()`, `inspect_configuration()`, `evaluate_scenarios()`,
`run_benchmark()`, and Phase 7 `build_export_artifacts()` for the same behavior
as CLI. The Streamlit presentation lives only in `dashboard/app.py`.

Use the download ZIP function directly in a Python script if needed:

```python
from pathlib import Path
from security_log_toolkit.dashboard import load_synthetic_demo, build_dashboard_zip
report = load_synthetic_demo(Path('.'))
zip_bytes = build_dashboard_zip(report)
```

## Testing and acceptance

```powershell
.\.venv\Scripts\python.exe -m pytest -q
.\.venv\Scripts\python.exe -m security_log_toolkit doctor
.\.venv\Scripts\python.exe scripts/audit_portfolio.py
```

With `.[dev,web]` installed, the suite also runs a genuine Streamlit AppTest
smoke test. When Streamlit is not installed, that optional test is skipped.

Manual acceptance on Windows 11:

- [ ] Dashboard opens at `http://127.0.0.1:8501` with no traceback.
- [ ] Synthetic overview cards show 29 / 6 / 4 / 22.
- [ ] Incident filters and timeline selection operate.
- [ ] Upload sample Linux+Windows files from `samples/` and analyze.
- [ ] Alter one detection setting, apply, re-run the demo; restore defaults.
- [ ] Validation shows 4 scenarios and 6 TP / 0 FP / 0 FN.
- [ ] Benchmark runs (e.g., 1000 events, 3 repetitions).
- [ ] ZIP contains exactly 7 expected export files and the manifest matches.
- [ ] CLI `status`, `doctor`, `analyze`, `report`, `export` still work.
- [ ] Git remains clean after final commit and sensitive data was not published.

**Do not call the project finished until the owner verifies browser behavior.**
