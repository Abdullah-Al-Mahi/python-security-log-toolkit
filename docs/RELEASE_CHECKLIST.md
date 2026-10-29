# Publication safety checklist (manual approval required)

**Default: KEEP THE REPOSITORY PRIVATE / LOCAL.** Phase 9 does not create a
GitHub repository or push anything online. GitHub publication is a separate,
explicit user action after inspection and approval.

## Before creating or changing any remote

- [ ] The working tree is clean: `git status --short`
- [ ] Tests pass locally: `python -m pytest -q`
- [ ] Offline audit reports no flagged tracked files:
  `python scripts/audit_portfolio.py`
- [ ] `git ls-files` does not show `reports/`, `.venv/`, `.env`, binary `.evtx`,
  private files, secrets, database files or real customer/employee log data
- [ ] Review **all tracked samples**, Git history and documentation for
  identifying information. The offline audit is only a heuristic and cannot
  guarantee secret-free source code or Git history
- [ ] Review existing `.gitignore` rather than overwriting it; generated
  `reports/`, `.venv/`, cache folders and private logs should be ignored
- [ ] Review existing LICENSE text and compare with `pyproject.toml` (`MIT`).
  Do not change its author or ownership information without permission
- [ ] Confirm screenshots use synthetic data, have no credentials, and reflect
  real working functionality; current Phase 9 has **no deployed web dashboard**
- [ ] Review GitHub visibility settings. Set **private** initially if a remote
  repository is ever explicitly approved
- [ ] GitHub Actions are optional and network-dependent: workflow is **manual
  dispatch only**, uses standard hosted runners and no project secrets. Minute
  allowances vary by account/repository; run only after reviewing usage limits
- [ ] Decide separately whether to publish publicly; don't interpret a
  documentation update or local Git commit as permission to publish

## Safe offline inspection (PowerShell)

```powershell
.\.venv\Scripts\python.exe scripts/audit_portfolio.py
git status --short
git ls-files
git --no-pager log -8 --oneline
```

**Never run `git push` or create a public repo as an automatic part of Phase 9.**
If a credential was ever committed previously, merely deleting it from the
working tree is insufficient. Revoke the credential and separately assess Git
history cleanup before any sharing.

## After user approves publication in a separate step

Review privacy and license again, choose repository visibility and only then
configure a remote. Update the portfolio with actual captured evidence and
links to the correct repository. No URL is promised at this stage.
