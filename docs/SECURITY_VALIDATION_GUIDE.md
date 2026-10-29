# Phase 8 — Security, accuracy and performance validation

Introduced in **0.8.0** and retained in **0.9.0**. All examples are offline and free. Use Windows PowerShell from
`C:\Users\abmah\CyberSecurity-Projects\python-security-log-toolkit`.

## Scope and explicit limitations

The toolkit supports UTF-8 Linux OpenSSH syslog and Windows Security **XML exports**
containing event IDs 4624 and 4625; **not binary .evtx**, general Windows events,
or live SIEM streaming. Indicators are investigation leads, not proven compromise.
Raw logs may contain usernames/IP addresses; never publish real personal/security
logs in a GitHub portfolio or upload them to untrusted websites.

Phase 8 adds conservative file-size limits at the **shared backend entry points**:

| Data | Limit | Behavior |
| --- | --- | --- |
| Raw Linux `.log` and Windows `.xml` (via `ingest_file`) | 16 MiB each | Rejected before parsing |
| Phase 2 normalized JSON (`load_normalized_events`) | 32 MiB per file | Rejected before decoding |
| Existing incident JSON used with `timeline --incident-report` | 50 MiB | Rejected before decoding |
| Individual Linux syslog line | 65,536 characters | Rejected with filename and line |

Windows XML DTD and entity declarations are explicitly rejected, including UTF-16
markup. XML parser still accepts valid UTF-8 and UTF-16 Windows event exports.
These conservative safeguards do **not** prove immunity to all resource-exhaustion,
CPU, path, race-condition or XML parser attacks. Do not expose the local parser as
an unauthenticated public API. Large production logs would need streaming parsing,
resource quotas and additional review.

The earlier 50 MiB limit for the `report`/`export` commands remains in place.

## Reproduce synthetic detection accuracy

The ground truth at `samples/validation/ground_truth.json` was **manually labeled
before evaluation**, listing expected `(rule_id, source_ip)` pairs in four synthetic
source scenarios. Two sources contain attack-pattern fixtures; two are below
configured thresholds. The evaluator checks whether a rule/IP pair is present in
each scenario, *not* number of individual alerts, exact onset time or account compromise.

```powershell
.\.venv\Scripts\python.exe -m security_log_toolkit validate --output reports/phase8_validation.json
```

Expected default-config counts: **4 scenarios, 41 normalized events, 6 TP, 0 FP,
0 FN, synthetic precision 1.0000, recall 1.0000, F1 1.0000**.

- True positive: expected rule/IP pair is detected in the relevant scenario.
- False positive: rule/IP pair is observed but not in its manually labeled list.
- False negative: expected pair isn't observed.
- No true-negative **count** is defined: it requires enumerating a bounded set of
  negative rule/IP opportunities. Consequently **accuracy and real-world FPR are
  not reported**.
- This tiny synthetic set is *not* representative of real-world activity and does
  not establish production precision/recall. It will miss many real-world evasion
  patterns, noisy environments, distributed attacks and unusual timestamps.
- Changing detection YAML may change scores, as expected.

To inspect the report:

```powershell
$validation = Get-Content 'reports\phase8_validation.json' -Raw | ConvertFrom-Json
$validation.summary | Format-List
$validation.scenarios | Select-Object name,events,true_positives,false_positives,false_negatives | Format-Table
```

The evaluator rejects malformed ground-truth JSON, duplicate labels, invalid IPs,
unknown rules, absolute/traversal paths and escapes from the permitted samples root.

## Reproduce bounded performance benchmark

```powershell
.\.venv\Scripts\python.exe -m security_log_toolkit benchmark --events 1000 --runs 3 --output reports/phase8_benchmark.json
```

For an optional scaling comparison (run **without an output**):

```powershell
.\.venv\Scripts\python.exe -m security_log_toolkit benchmark --events 3000 --runs 3
```

The benchmark creates deterministic **synthetic normalized Python events** and
times shared **detection + correlation + incident serialization** services in
memory, after creating events and loading configuration. It does not read raw
files, run export, measure the full web UI, or estimate continuous live ingestion
capacity. Hardware load, CPU architecture and Python version affect measured
milliseconds and events/second; do not claim a fixed expected speed. It returns
median latency, nearest-rank p95, min/max, median events/second, and result counts.
`--events` accepts **100–5000**; `--runs` accepts **2–10** to bound accidental
resource consumption. A benchmark is not a security or availability guarantee.

## Adversarial sample fixtures

These are entirely synthetic; do not use them as production security evidence.

- `samples/validation/reject_external_entity.xml` — forbidden external entity
  declaration. Must be **rejected**, not expanded or fetched.
- `samples/validation/reject_malformed.xml` — malformed XML that fails parsing.
- `samples/validation/reject_bad_ip.log` — recognized SSH event with malformed IP;
  must raise a contextual validation error rather than invent an IP.

Tests generate sparse oversized files, overlong lines, UTF-16 entity declarations,
path traversal attempts, disabled rules and malformed label manifests. No web
requests or paid services are required.

## Verification and Git

```powershell
.\.venv\Scripts\python.exe -m security_log_toolkit status
.\.venv\Scripts\python.exe -m security_log_toolkit doctor
.\.venv\Scripts\python.exe -m pytest -q
.\.venv\Scripts\python.exe -m security_log_toolkit validate --output reports/phase8_validation.json
.\.venv\Scripts\python.exe -m security_log_toolkit benchmark --events 1000 --runs 3 --output reports/phase8_benchmark.json
```

Both report outputs are intentionally **overwrite-protected**: repeat with
`--force` only if you explicitly want to replace those generated reports.
Keep `reports/` ignored by Git. Commit updated source code, synthetic fixture files,
tests and documentation—not sensitive live logs.

## Preparing Phase 10

`security_log_toolkit.quality.evaluate_scenarios()` and
`security_log_toolkit.quality.run_benchmark()` accept ordinary Python arguments
and return JSON-safe dictionaries. The future private Streamlit UI can call these
services without shelling out or duplicating validation logic. Treat benchmarks
as diagnostics and display synthetic-only labels visibly in the dashboard.
- `samples/validation/edge_linux_auth.log` — interleaved failures from two
  distinct source IPs below rule thresholds, plus an IPv6 success and benign
  non-SSH entry. Must not merge failures across IPs.
- `samples/validation/edge_windows_security.xml` — same source IP spread across
  two Windows hosts, a local service login missing IP, and a 4634 unsupported
  event. Must not merge failures across host boundaries.
