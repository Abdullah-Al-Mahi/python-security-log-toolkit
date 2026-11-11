
# Sentinel — Screenshot and Portfolio Visuals Guide

## Purpose

I use genuine application screenshots to demonstrate the completed Sentinel Prism interface and its security investigation capabilities.

The screenshots in this repository show my locally running application using bundled synthetic demonstration data.

I do not use unrelated UI mockups as evidence of implemented features.

## Published Dashboard Screenshots

| File | Content |
|---|---|
| `docs/screenshots/sentinel-dark.png` | Command Center in dark mode |
| `docs/screenshots/sentinel-light.png` | Command Center in light mode |
| `docs/screenshots/incident-explorer.png` | Incident investigation interface |

These images are referenced in the main repository README.

## Capturing Updated Screenshots

Start the dashboard locally:

```powershell
.\.venv\Scripts\python.exe -m streamlit run dashboard\app.py --server.address 127.0.0.1 --server.port 8501
```

Open http://127.0.0.1:8501.

Load the bundled synthetic demonstration and confirm that the interface displays the expected investigation metrics.

Use **Win + Shift + S** on Windows to capture the relevant area.

For a professional presentation:

1. Keep the application window clean and readable.
2. Capture the actual running interface.
3. Use consistent browser dimensions.
4. Exclude unrelated applications and notifications.
5. Avoid exposing private usernames, credentials, local file paths, or real logs.
6. Keep the synthetic-data label visible where practical.
7. Use appropriate image resolution without unnecessarily large files.

## Recommended Screenshot Coverage

### Command Center — Dark Mode

Show the project branding, navigation, event metrics, charts, and priority investigations.

### Command Center — Light Mode

Show the same workspace using the alternate theme.

### Incident Explorer

Show filtering controls, selected incident details, and evidence relationships.

### Optional Additional Images

- Evidence Timeline.
- Detection Lab.
- Validation & Performance.
- Report Center.
- Automated regression test output.
- Architecture diagrams.

## Image Organization

```text
docs/
└── screenshots/
    ├── sentinel-dark.png
    ├── sentinel-light.png
    └── incident-explorer.png
```

The existing README uses these filenames. If an image is renamed, its README reference must also be updated.

## Privacy and Accuracy

I use synthetic data for publicly shared demonstration images.

I do not publish screenshots containing real authentication logs, customer information, credentials, or confidential infrastructure details.

Image editing should improve readability without misrepresenting analysis results or fabricating capabilities.

The publication-audit script may flag tracked files larger than 2 MiB for manual review. Screenshots should be optimized where practical.

## Updating the Portfolio

When I make significant UI changes, I capture new screenshots from the running application and replace the outdated images.

The README should always reflect the current implemented interface rather than an earlier design or unrelated reference image.
