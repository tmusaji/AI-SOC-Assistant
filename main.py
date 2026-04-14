from __future__ import annotations

import asyncio
import json
import logging
import uuid
from contextlib import asynccontextmanager
from datetime import datetime, timezone
from typing import Any, AsyncGenerator

from dotenv import load_dotenv
from fastapi import Depends, FastAPI, HTTPException, Request
from fastapi.responses import HTMLResponse, StreamingResponse
from fastapi.templating import Jinja2Templates
from sqlalchemy import desc, func, select
from sqlalchemy.orm import Session

from ai_analyst import analyze_alert
from false_positive import evaluate_false_positive_rule
from models import Alert, get_db, init_db


load_dotenv()

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s %(levelname)s %(name)s %(message)s",
)
logger = logging.getLogger("ai-soc-assistant")

SEVERITIES = ("CRITICAL", "HIGH", "MEDIUM", "LOW", "INFORMATIONAL")
templates = Jinja2Templates(directory="templates")


@asynccontextmanager
async def lifespan(_: FastAPI) -> AsyncGenerator[None, None]:
    init_db()
    logger.info("SQLite database initialized.")
    yield


app = FastAPI(title="AI SOC Assistant", lifespan=lifespan)


class EventBroker:
    def __init__(self) -> None:
        self._subscribers: set[asyncio.Queue[str]] = set()
        self._lock = asyncio.Lock()

    async def subscribe(self) -> asyncio.Queue[str]:
        queue: asyncio.Queue[str] = asyncio.Queue(maxsize=100)
        async with self._lock:
            self._subscribers.add(queue)
        return queue

    async def unsubscribe(self, queue: asyncio.Queue[str]) -> None:
        async with self._lock:
            self._subscribers.discard(queue)

    async def publish(self, event: str, payload: dict[str, Any]) -> None:
        message = _format_sse(event, payload)
        stale_queues: list[asyncio.Queue[str]] = []
        async with self._lock:
            for queue in list(self._subscribers):
                try:
                    queue.put_nowait(message)
                except asyncio.QueueFull:
                    stale_queues.append(queue)
            for queue in stale_queues:
                self._subscribers.discard(queue)


broker = EventBroker()


@app.get("/", response_class=HTMLResponse)
async def dashboard(request: Request) -> HTMLResponse:
    return templates.TemplateResponse("dashboard.html", {"request": request})


@app.post("/ingest", status_code=201)
async def ingest_alert(payload: dict[str, Any], db: Session = Depends(get_db)) -> dict[str, Any]:
    if not isinstance(payload, dict):
        raise HTTPException(status_code=400, detail="Payload must be a JSON object.")

    normalized_alert = normalize_payload(payload)
    suppression = evaluate_false_positive_rule(normalized_alert)

    if suppression.is_suppressed:
        record = build_alert_record(
            normalized_alert,
            {
                "is_false_positive": True,
                "suppression_reason": suppression.reason,
                "severity": "INFORMATIONAL",
                "summary": "Alert suppressed by the rule-based false positive filter before AI analysis.",
                "malicious_indicators": [],
                "recommended_action": "No analyst action required unless suppression rules need tuning.",
                "attack_technique": None,
                "confidence_score": 1.0,
                "affected_assets": collect_default_assets(normalized_alert),
                "priority": 100,
            },
            analysis_source="rule_based",
        )
        db.add(record)
        db.commit()
        db.refresh(record)
        await broadcast_suppressed(record, db)
        return {
            "id": record.id,
            "status": "suppressed",
            "analysis_source": "rule_based",
            "suppression_reason": suppression.reason,
        }

    analysis = await analyze_alert(normalized_alert)
    record = build_alert_record(normalized_alert, analysis, analysis_source="ai")
    db.add(record)
    db.commit()
    db.refresh(record)

    if record.is_false_positive:
        await broadcast_suppressed(record, db)
        return {
            "id": record.id,
            "status": "suppressed",
            "analysis_source": "ai",
            "suppression_reason": record.suppression_reason,
        }

    await broker.publish("alert_created", serialize_alert(record))
    await broadcast_stats(db)
    return {
        "id": record.id,
        "status": "active",
        "analysis_source": "ai",
        "priority": record.priority,
        "severity": record.severity,
    }


@app.get("/alerts")
async def get_alerts(db: Session = Depends(get_db)) -> list[dict[str, Any]]:
    statement = (
        select(Alert)
        .where(Alert.is_false_positive.is_(False), Alert.is_resolved.is_(False))
        .order_by(Alert.priority.asc(), desc(Alert.created_at))
    )
    alerts = db.scalars(statement).all()
    return [serialize_alert(alert) for alert in alerts]


@app.get("/alerts/suppressed")
async def get_suppressed_alerts(db: Session = Depends(get_db)) -> list[dict[str, Any]]:
    statement = (
        select(Alert)
        .where(Alert.is_false_positive.is_(True))
        .order_by(desc(Alert.created_at))
    )
    alerts = db.scalars(statement).all()
    return [serialize_alert(alert) for alert in alerts]


@app.patch("/alerts/{alert_id}/resolve")
async def resolve_alert(alert_id: str, db: Session = Depends(get_db)) -> dict[str, Any]:
    alert = db.get(Alert, alert_id)
    if alert is None:
        raise HTTPException(status_code=404, detail="Alert not found.")

    alert.is_resolved = True
    db.commit()
    db.refresh(alert)

    await broker.publish("alert_resolved", serialize_alert(alert))
    await broadcast_stats(db)
    return serialize_alert(alert)


@app.patch("/alerts/{alert_id}/false-positive")
async def mark_false_positive(alert_id: str, db: Session = Depends(get_db)) -> dict[str, Any]:
    alert = db.get(Alert, alert_id)
    if alert is None:
        raise HTTPException(status_code=404, detail="Alert not found.")

    alert.is_false_positive = True
    alert.is_resolved = False
    alert.suppression_reason = alert.suppression_reason or "Marked as false positive by an analyst."
    db.commit()
    db.refresh(alert)

    await broadcast_suppressed(alert, db)
    return serialize_alert(alert)


@app.get("/stats")
async def get_stats(db: Session = Depends(get_db)) -> dict[str, Any]:
    return build_stats_payload(db)


@app.get("/stream")
async def stream_events() -> StreamingResponse:
    async def event_generator() -> AsyncGenerator[str, None]:
        queue = await broker.subscribe()
        try:
            yield _format_sse("connected", {"status": "ready"})
            while True:
                try:
                    message = await asyncio.wait_for(queue.get(), timeout=15)
                    yield message
                except asyncio.TimeoutError:
                    yield ": keepalive\n\n"
        finally:
            await broker.unsubscribe(queue)

    return StreamingResponse(
        event_generator(),
        media_type="text/event-stream",
        headers={
            "Cache-Control": "no-cache",
            "Connection": "keep-alive",
            "X-Accel-Buffering": "no",
        },
    )


def normalize_payload(payload: dict[str, Any]) -> dict[str, Any]:
    merged: dict[str, Any] = {}
    for key in ("result", "data", "event"):
        nested = payload.get(key)
        if isinstance(nested, dict):
            merged.update(nested)
    merged.update(payload)

    alert_name = first_non_empty(
        merged.get("alert_name"),
        merged.get("search_name"),
        merged.get("savedsearch_name"),
        merged.get("rule_name"),
        "Splunk Alert",
    )
    src_ip = first_non_empty(
        merged.get("src_ip"),
        merged.get("src"),
        merged.get("source_ip"),
        merged.get("client_ip"),
    )
    dest_ip = first_non_empty(
        merged.get("dest_ip"),
        merged.get("dest"),
        merged.get("destination_ip"),
        merged.get("dvc_ip"),
    )
    user = first_non_empty(
        merged.get("user"),
        merged.get("username"),
        merged.get("src_user"),
        merged.get("account"),
    )
    host = first_non_empty(
        merged.get("host"),
        merged.get("dest_host"),
        merged.get("device_host"),
        merged.get("computer_name"),
    )
    sourcetype = first_non_empty(
        merged.get("sourcetype"),
        merged.get("source_type"),
    )
    event_count = safe_int(
        merged.get("event_count"),
        merged.get("count"),
        merged.get("eventcount"),
        default=0,
    )

    raw_event = merged.get("_raw") or merged.get("raw_event") or payload
    if isinstance(raw_event, str):
        raw_event_text = raw_event
    else:
        raw_event_text = json.dumps(raw_event, indent=2, default=str, ensure_ascii=False)

    return {
        "alert_name": alert_name,
        "src_ip": src_ip,
        "dest_ip": dest_ip,
        "user": user,
        "host": host,
        "raw_event": raw_event_text,
        "sourcetype": sourcetype,
        "event_count": event_count,
    }


def build_alert_record(
    normalized_alert: dict[str, Any],
    analysis: dict[str, Any],
    analysis_source: str,
) -> Alert:
    malicious_indicators = ensure_string_list(analysis.get("malicious_indicators"))
    affected_assets = ensure_string_list(analysis.get("affected_assets")) or collect_default_assets(normalized_alert)

    return Alert(
        id=str(uuid.uuid4()),
        alert_name=normalized_alert["alert_name"],
        src_ip=normalized_alert.get("src_ip"),
        dest_ip=normalized_alert.get("dest_ip"),
        user=normalized_alert.get("user"),
        host=normalized_alert.get("host"),
        raw_event=normalized_alert.get("raw_event", ""),
        sourcetype=normalized_alert.get("sourcetype"),
        severity=str(analysis.get("severity", "MEDIUM")).upper(),
        priority=max(1, min(100, safe_int(analysis.get("priority"), default=100))),
        summary=str(analysis.get("summary") or "No summary available.").strip(),
        malicious_indicators=malicious_indicators,
        recommended_action=str(analysis.get("recommended_action") or "Investigate the alert.").strip(),
        attack_technique=str(analysis.get("attack_technique")).strip() if analysis.get("attack_technique") else None,
        confidence_score=max(0.0, min(1.0, safe_float(analysis.get("confidence_score"), 0.0))),
        affected_assets=affected_assets,
        is_false_positive=bool(analysis.get("is_false_positive", False)),
        suppression_reason=str(analysis.get("suppression_reason")).strip() if analysis.get("suppression_reason") else None,
        is_resolved=False,
        analysis_source=analysis_source,
        created_at=datetime.now(timezone.utc),
    )


def serialize_alert(alert: Alert) -> dict[str, Any]:
    created_at = alert.created_at
    if created_at is not None and created_at.tzinfo is None:
        created_at = created_at.replace(tzinfo=timezone.utc)

    return {
        "id": alert.id,
        "alert_name": alert.alert_name,
        "src_ip": alert.src_ip,
        "dest_ip": alert.dest_ip,
        "user": alert.user,
        "host": alert.host,
        "raw_event": alert.raw_event,
        "sourcetype": alert.sourcetype,
        "severity": alert.severity,
        "priority": alert.priority,
        "summary": alert.summary,
        "malicious_indicators": alert.malicious_indicators or [],
        "recommended_action": alert.recommended_action,
        "attack_technique": alert.attack_technique,
        "confidence_score": alert.confidence_score,
        "affected_assets": alert.affected_assets or [],
        "is_false_positive": alert.is_false_positive,
        "suppression_reason": alert.suppression_reason,
        "is_resolved": alert.is_resolved,
        "analysis_source": alert.analysis_source,
        "created_at": created_at.isoformat() if created_at else None,
    }


def build_stats_payload(db: Session) -> dict[str, Any]:
    active_filter = [Alert.is_false_positive.is_(False), Alert.is_resolved.is_(False)]
    by_severity = {}
    for severity in SEVERITIES:
        count_statement = select(func.count(Alert.id)).where(*active_filter, Alert.severity == severity)
        by_severity[severity] = db.scalar(count_statement) or 0

    total_alerts = db.scalar(select(func.count(Alert.id)).where(*active_filter)) or 0
    suppressed = db.scalar(select(func.count(Alert.id)).where(Alert.is_false_positive.is_(True))) or 0
    false_positive_caught = db.scalar(select(func.count(Alert.id)).where(Alert.is_false_positive.is_(True))) or 0
    today_start = datetime.now(timezone.utc).replace(hour=0, minute=0, second=0, microsecond=0)
    alerts_today = db.scalar(select(func.count(Alert.id)).where(Alert.created_at >= today_start)) or 0

    return {
        "total_alerts": total_alerts,
        "by_severity": by_severity,
        "suppressed": suppressed,
        "false_positive_caught": false_positive_caught,
        "alerts_today": alerts_today,
        "active_critical": by_severity["CRITICAL"],
    }


async def broadcast_suppressed(alert: Alert, db: Session) -> None:
    await broker.publish("alert_suppressed", serialize_alert(alert))
    await broadcast_stats(db)


async def broadcast_stats(db: Session) -> None:
    await broker.publish("stats", build_stats_payload(db))


def collect_default_assets(alert: dict[str, Any]) -> list[str]:
    assets = []
    for field in ("host", "src_ip", "dest_ip", "user"):
        value = str(alert.get(field, "") or "").strip()
        if value and value not in assets:
            assets.append(value)
    return assets


def ensure_string_list(value: Any) -> list[str]:
    if not isinstance(value, list):
        return []
    items = []
    for item in value:
        text = str(item or "").strip()
        if text and text not in items:
            items.append(text)
    return items


def safe_int(*values: Any, default: int = 0) -> int:
    for value in values:
        try:
            if value is None or value == "":
                continue
            return int(value)
        except (TypeError, ValueError):
            continue
    return default


def safe_float(value: Any, default: float = 0.0) -> float:
    try:
        return float(value)
    except (TypeError, ValueError):
        return default


def first_non_empty(*values: Any) -> str | None:
    for value in values:
        text = str(value or "").strip()
        if text:
            return text
    return None


def _format_sse(event: str, payload: dict[str, Any]) -> str:
    return f"event: {event}\ndata: {json.dumps(payload, default=str, ensure_ascii=False)}\n\n"
