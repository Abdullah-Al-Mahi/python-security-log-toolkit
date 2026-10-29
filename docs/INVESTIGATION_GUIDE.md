# Phase 5 — Reading an evidence-linked incident timeline

## Purpose

An incident is a group of one or more detection findings created in Phase 4.
Phase 5 adds a **chronological timeline based on unique evidence records already
linked to those findings**. This supports analyst review, reproducible demonstrations
and a future local dashboard without asserting that an attack succeeded.

## What counts as evidence?

Each timeline entry represents an original **normalized authentication record** used
by one or more detection findings. Look for:

- `evidence_id`: stable reference that matches the incident's `evidence` list
- `linked_finding_ids`: which Phase 3 rule findings used this evidence
- `timestamp`: UTC event time (not ingestion or computer clock time)
- `stage`: authentication failure or observed authentication success
- `account`, `hostname`, `source_ip`: source identity context
- `source.file`, `source.line`, `source.record_id`: best available log locator
- `seconds_from_start`: relative position in this incident's evidence timeline

Two overlapping findings may reference the same failed login: it appears **once**
in the incident timeline, with **both** finding IDs attached.

## Sample synthetic investigation

Using the bundled Linux and Windows attack datasets, the expected result is:

| Measure | Expected |
|---|---:|
| Normalized authentication records analyzed | 29 |
| Detection findings | 6 |
| Incidents | 4 |
| Correlated incidents | 2 |
| Single-finding incidents | 2 |
| Unique evidence timeline records | 22 |
| Incidents with observed successful logins | 2 |

Two incidents have linked failures followed by successful logins for the same account.
Two are multi-account failure cases without observed success in their supporting
evidence. **This is a synthetic exercise, not proof of compromised accounts.**

## Suggested analyst workflow

1. Start with the incident's platform, hostname, source IP, severity and rule IDs.
2. Read `timeline.observed_pattern` and the conservative `analyst_summary`.
3. Inspect `timeline.events` in UTC order and note affected accounts.
4. Trace any important entry back to its `source.file` and line/record ID.
5. Look at `linked_finding_ids` to see why the record contributed to an alert.
6. Corroborate observations using other authorized telemetry, such as endpoint events,
   user activity, and authentication-provider logs, before concluding an incident.

## Limitations

Timelines omit unrelated or unflagged log entries. Source records may be incomplete or
lack IP/port context. Correlation does not prove a source IP is one person or attacker.
No automatic containment, external API calls, or real-time collection is performed.
Only synthetic or properly authorized real-world log data should be analyzed.
