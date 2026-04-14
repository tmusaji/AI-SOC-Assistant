# AI SOC Assistant

## Project Overview

AI SOC Assistant is a production-oriented Security Operations Center alert triage application built with FastAPI, SQLite, Server-Sent Events, and OpenRouter. It accepts raw Splunk alert payloads from n8n, suppresses obvious false positives with deterministic rules, enriches the remaining alerts with AI-driven analyst output, stores the results persistently, and presents everything in a live web dashboard.

## Architecture Diagram

```text
+------------------+        +--------------------+        +----------------------+
| Splunk Detection | -----> | n8n HTTP Request   | -----> | POST /ingest         |
| / Saved Search   |        | Workflow           |        | FastAPI Ingestion    |
+------------------+        +--------------------+        +----------+-----------+
                                                                  |
                                                                  v
                                                   +-----------------------------+
                                                   | Rule-Based FP Filter        |
                                                   | false_positive.py           |
                                                   +-------------+---------------+
                                                                 |
                                       +-------------------------+------------------------+
                                       |                                                  |
                                       v                                                  v
                         +-----------------------------+                    +-----------------------------+
                         | Suppressed Alert            |                    | OpenRouter AI Analyst       |
                         | Stored in SQLite            |                    | ai_analyst.py               |
                         | Hidden from main feed       |                    +-------------+---------------+
                         +-------------+---------------+                                  |
                                       |                                                  v
                                       |                                +-----------------------------+
                                       |                                | Structured JSON Triage      |
                                       |                                | Severity / Summary / MITRE |
                                       |                                +-------------+---------------+
                                       |                                              |
                                       +--------------------------+-------------------+
                                                                  |
                                                                  v
                                                   +-----------------------------+
                                                   | SQLite alerts table         |
                                                   | SQLAlchemy ORM              |
                                                   +-------------+---------------+
                                                                 |
                                                                 v
                                                   +-----------------------------+
                                                   | FastAPI API + SSE Stream    |
                                                   | /alerts /stats /stream      |
                                                   +-------------+---------------+
                                                                 |
                                                                 v
                                                   +-----------------------------+
                                                   | Browser Dashboard           |
                                                   | Jinja2 + HTML/CSS/JS        |
                                                   +-----------------------------+
```

## Features

- Two-stage alert triage with zero-cost suppression before AI enrichment
- OpenRouter integration using `meta-llama/llama-3.3-70b-instruct:free`
- Persistent SQLite storage for active, suppressed, and resolved alerts
- Live dashboard updates over SSE with no page refresh
- Analyst actions to resolve alerts or mark them false positive manually
- Dark-theme SOC dashboard with severity styling, counters, badges, and expandable evidence
- Simple deployment model with a single FastAPI service and no frontend build step

## Requirements

- Ubuntu server
- Python 3.10+
- OpenRouter API key
- Network access from the server to OpenRouter
- Splunk alert payloads forwarded through n8n or another HTTP sender

## Installation

1. Clone the repository:

   ```bash
   git clone https://github.com/<your-user>/ai-soc-assistant.git
   cd ai-soc-assistant
   ```

2. Create a virtual environment:

   ```bash
   python3.10 -m venv venv
   source venv/bin/activate
   ```

3. Install dependencies:

   ```bash
   pip install --upgrade pip
   pip install -r requirements.txt
   ```

## Configuration

1. Copy the example environment file:

   ```bash
   cp .env.example .env
   ```

2. Set the required variables:

   ```env
   OPENROUTER_API_KEY=your_key_here
   OPENROUTER_MODEL=meta-llama/llama-3.3-70b-instruct:free
   HOST=0.0.0.0
   PORT=8000
   DATABASE_URL=sqlite:///./soc_assistant.db
   ```

## Running the App

Start the service with:

```bash
uvicorn main:app --host 0.0.0.0 --port 8000
```

Open the dashboard at:

```text
http://<server-ip>:8000
```

## n8n Setup

1. In n8n, create a workflow that receives or transforms Splunk alert data.
2. Add an HTTP Request node targeting:

   ```text
   POST http://<server-ip>:8000/ingest
   ```

3. Send the raw JSON body from Splunk with fields such as:
   - `alert_name`
   - `src_ip`
   - `dest_ip`
   - `user`
   - `host`
   - `sourcetype`
   - `event_count`
   - `_raw`

4. Example payload:

   ```json
   {
     "alert_name": "Multiple failed login attempts from external IP",
     "src_ip": "185.220.101.10",
     "dest_ip": "10.20.30.15",
     "user": "jsmith",
     "host": "vpn-gateway-01",
     "sourcetype": "linux_secure",
     "event_count": 8,
     "_raw": "Failed password for jsmith from 185.220.101.10 port 54532 ssh2"
   }
   ```

## API Endpoints

- `POST /ingest` ingests a Splunk alert, applies suppression/AI analysis, stores the result, and emits SSE updates
- `GET /alerts` returns all active non-suppressed alerts
- `GET /alerts/suppressed` returns suppressed alerts
- `PATCH /alerts/{id}/resolve` marks an alert as resolved
- `PATCH /alerts/{id}/false-positive` marks an alert as false positive
- `GET /stats` returns live alert counters
- `GET /stream` streams live dashboard events over SSE
- `GET /` serves the SOC dashboard

## Screenshots placeholder

- Dashboard overview screenshot: `docs/screenshots/dashboard-overview.png`
- Expanded alert card screenshot: `docs/screenshots/alert-details.png`
- Suppressed alerts view screenshot: `docs/screenshots/suppressed-feed.png`
