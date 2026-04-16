# AWS Security Risk Analyzer

A lightweight Streamlit-based dashboard for analyzing AWS security findings with contextual risk scoring, executive summaries, and remediation guidance.

## Features

- Context-aware risk scoring
- Executive summary for leadership
- Top risky resources and service concentration
- Filter by service and priority
- CSV export
- Optional AI-generated executive summary

## Project structure

- `app/streamlit_app.py` — dashboard UI
- `data/alerts.json` — sample findings dataset
- `src/parser.py` — alert loader and normalizer
- `src/score_engine.py` — contextual scoring model
- `src/risk_engine.py` — unified decision engine
- `src/summarizer.py` — compatibility shim
- `src/remediation.py` — compatibility shim
- `.streamlit/config.toml` — Streamlit watcher settings

## Run locally

```bash
python -m venv venv
source venv/bin/activate
pip install -r requirements.txt
streamlit run app/streamlit_app.py
```

## Optional AI summary

If you want to enable the AI executive summary feature, install:

```bash
pip install transformers torch torchvision
```

The app uses lazy import for the AI summary so the dashboard still works without those packages.
