from __future__ import annotations

import json
import os
from typing import Any

import httpx


OPENROUTER_URL = "https://openrouter.ai/api/v1/chat/completions"
DEFAULT_MODEL = "meta-llama/llama-3.3-70b-instruct:free"
VALID_SEVERITIES = ("CRITICAL", "HIGH", "MEDIUM", "LOW", "INFORMATIONAL")
SEVERITY_BASE_PRIORITY = {
    "CRITICAL": 12,
    "HIGH": 28,
    "MEDIUM": 52,
    "LOW": 76,
    "INFORMATIONAL": 92,
}

SOC_ANALYST_SYSTEM_PROMPT = """You are an elite Tier-3 SOC analyst with 15 years of experience. Analyze the incoming Splunk alert and return ONLY a JSON object with no markdown, no explanation.

Required JSON keys:
{
  "is_false_positive": boolean,
  "suppression_reason": string or null,
  "severity": "CRITICAL" | "HIGH" | "MEDIUM" | "LOW" | "INFORMATIONAL",
  "summary": "2-3 sentence plain English briefing of what is happening, who is involved, and the risk level",
  "malicious_indicators": ["specific indicator 1", "specific indicator 2"],
  "recommended_action": "Specific actionable steps for the SOC analyst",
  "attack_technique": "MITRE ATT&CK ID and name or null",
  "confidence_score": 0.0 to 1.0,
  "affected_assets": ["host", "ip", "user"],
  "priority": 1 to 100
}

Severity rules: CRITICAL=active breach/ransomware/C2/exfiltration, HIGH=credential theft/lateral movement/persistence, MEDIUM=suspicious unconfirmed/recon/policy violation, LOW=minor anomaly/single failure, INFORMATIONAL=context only.
Set is_false_positive=true for: known scanner IPs, service accounts doing normal tasks, heartbeat/keepalive traffic, single failed login with no pattern, internal monitoring tools.
Priority 1 = most urgent. Calculate priority based on severity, confidence, and number of affected assets."""


async def analyze_alert(alert: dict[str, Any]) -> dict[str, Any]:
    api_key = os.getenv("OPENROUTER_API_KEY", "").strip()
    model = os.getenv("OPENROUTER_MODEL", DEFAULT_MODEL).strip() or DEFAULT_MODEL

    if not api_key:
        return _fallback_analysis(alert, "OPENROUTER_API_KEY is not configured.")

    request_payload = {
        "model": model,
        "messages": [
            {"role": "system", "content": SOC_ANALYST_SYSTEM_PROMPT},
            {
                "role": "user",
                "content": json.dumps(alert, indent=2, default=str, ensure_ascii=False),
            },
        ],
        "temperature": 0.1,
    }
    headers = {
        "Authorization": f"Bearer {api_key}",
        "HTTP-Referer": "http://localhost:8000",
        "X-Title": "AI SOC Assistant",
        "Content-Type": "application/json",
    }

    try:
        async with httpx.AsyncClient(timeout=httpx.Timeout(35.0, connect=10.0)) as client:
            response = await client.post(OPENROUTER_URL, headers=headers, json=request_payload)
            response.raise_for_status()

        content = _extract_message_content(response.json())
        parsed = _extract_json_object(content)
        return _normalize_ai_result(parsed, alert)
    except (httpx.HTTPError, KeyError, TypeError, ValueError, json.JSONDecodeError) as exc:
        return _fallback_analysis(alert, str(exc))


def calculate_priority(severity: str, confidence_score: float, asset_count: int) -> int:
    normalized_severity = severity if severity in VALID_SEVERITIES else "MEDIUM"
    base_priority = SEVERITY_BASE_PRIORITY[normalized_severity]
    confidence_bonus = round(_clamp_float(confidence_score) * 24)
    asset_bonus = min(max(asset_count, 0), 8) * 3
    return max(1, min(100, base_priority - confidence_bonus - asset_bonus))


def _extract_message_content(payload: dict[str, Any]) -> str:
    message = payload["choices"][0]["message"]["content"]
    if isinstance(message, str):
        return message
    if isinstance(message, list):
        text_fragments = []
        for item in message:
            if isinstance(item, dict) and item.get("type") == "text":
                text_fragments.append(str(item.get("text", "")))
        return "".join(text_fragments)
    raise ValueError("OpenRouter returned an unsupported content format.")


def _extract_json_object(content: str) -> dict[str, Any]:
    cleaned = content.strip()
    if cleaned.startswith("```"):
        cleaned = cleaned.strip("`")
        if cleaned.lower().startswith("json"):
            cleaned = cleaned[4:].strip()

    try:
        return json.loads(cleaned)
    except json.JSONDecodeError:
        start = cleaned.find("{")
        end = cleaned.rfind("}")
        if start == -1 or end == -1 or end <= start:
            raise
        return json.loads(cleaned[start : end + 1])


def _normalize_ai_result(result: dict[str, Any], alert: dict[str, Any]) -> dict[str, Any]:
    severity = str(result.get("severity", "")).upper().strip()
    if severity not in VALID_SEVERITIES:
        severity = _infer_severity(alert)

    confidence_score = _clamp_float(result.get("confidence_score", 0.45))
    affected_assets = _sanitize_list(result.get("affected_assets")) or _collect_affected_assets(alert)
    priority = _safe_priority(result.get("priority"), severity, confidence_score, len(affected_assets))
    malicious_indicators = _sanitize_list(result.get("malicious_indicators"))

    normalized = {
        "is_false_positive": bool(result.get("is_false_positive", False)),
        "suppression_reason": _nullable_text(result.get("suppression_reason")),
        "severity": severity,
        "summary": _required_text(
            result.get("summary"),
            _build_fallback_summary(alert, severity),
        ),
        "malicious_indicators": malicious_indicators,
        "recommended_action": _required_text(
            result.get("recommended_action"),
            "Validate the alert context, pivot on related telemetry, and escalate if corroborating evidence appears.",
        ),
        "attack_technique": _nullable_text(result.get("attack_technique")),
        "confidence_score": confidence_score,
        "affected_assets": affected_assets,
        "priority": priority,
    }

    if normalized["is_false_positive"] and not normalized["suppression_reason"]:
        normalized["suppression_reason"] = "AI analyst classified the activity as benign or expected."

    return normalized


def _fallback_analysis(alert: dict[str, Any], error_context: str) -> dict[str, Any]:
    severity = _infer_severity(alert)
    confidence_score = 0.42 if severity in {"CRITICAL", "HIGH"} else 0.34
    affected_assets = _collect_affected_assets(alert)
    priority = calculate_priority(severity, confidence_score, len(affected_assets))
    summary = (
        f"Automated fallback triage was used because the AI provider was unavailable or returned invalid data. "
        f"The alert remains queued for analyst review with a provisional {severity.lower()} severity assessment."
    )
    recommended_action = (
        "Review the raw event, validate whether the entities are expected in your environment, "
        "and re-run enrichment if the OpenRouter service becomes available."
    )
    return {
        "is_false_positive": False,
        "suppression_reason": None,
        "severity": severity,
        "summary": summary,
        "malicious_indicators": _collect_indicator_candidates(alert),
        "recommended_action": f"{recommended_action} Fallback context: {error_context[:180]}",
        "attack_technique": None,
        "confidence_score": confidence_score,
        "affected_assets": affected_assets,
        "priority": priority,
    }


def _infer_severity(alert: dict[str, Any]) -> str:
    text = " ".join(
        str(alert.get(field, "") or "")
        for field in ("alert_name", "raw_event", "sourcetype")
    ).lower()

    if any(keyword in text for keyword in ("ransomware", "exfil", "c2", "command and control", "beacon", "breach")):
        return "CRITICAL"
    if any(keyword in text for keyword in ("credential", "lateral", "persistence", "mimikatz", "privilege", "powershell")):
        return "HIGH"
    if any(keyword in text for keyword in ("recon", "scan", "suspicious", "policy", "anomaly", "phishing")):
        return "MEDIUM"
    if any(keyword in text for keyword in ("failed login", "minor", "single failure", "warning")):
        return "LOW"
    return "MEDIUM"


def _collect_affected_assets(alert: dict[str, Any]) -> list[str]:
    ordered_assets = []
    for key in ("host", "src_ip", "dest_ip", "user"):
        value = str(alert.get(key, "") or "").strip()
        if value and value not in ordered_assets:
            ordered_assets.append(value)
    return ordered_assets


def _collect_indicator_candidates(alert: dict[str, Any]) -> list[str]:
    indicators = []
    for label, key in (
        ("Source IP", "src_ip"),
        ("Destination IP", "dest_ip"),
        ("User", "user"),
        ("Host", "host"),
        ("Sourcetype", "sourcetype"),
    ):
        value = str(alert.get(key, "") or "").strip()
        if value:
            indicators.append(f"{label}: {value}")
    return indicators


def _sanitize_list(value: Any) -> list[str]:
    if not isinstance(value, list):
        return []
    sanitized = []
    for item in value:
        text = str(item or "").strip()
        if text and text not in sanitized:
            sanitized.append(text)
    return sanitized


def _nullable_text(value: Any) -> str | None:
    text = str(value).strip() if value is not None else ""
    return text or None


def _required_text(value: Any, fallback: str) -> str:
    text = str(value).strip() if value is not None else ""
    return text or fallback


def _clamp_float(value: Any) -> float:
    try:
        number = float(value)
    except (TypeError, ValueError):
        number = 0.0
    return max(0.0, min(1.0, number))


def _safe_priority(value: Any, severity: str, confidence_score: float, asset_count: int) -> int:
    try:
        parsed = int(value)
    except (TypeError, ValueError):
        parsed = calculate_priority(severity, confidence_score, asset_count)
    return max(1, min(100, parsed))


def _build_fallback_summary(alert: dict[str, Any], severity: str) -> str:
    alert_name = str(alert.get("alert_name") or "Unnamed alert").strip()
    host = str(alert.get("host") or "unknown host").strip()
    user = str(alert.get("user") or "no identified user").strip()
    return (
        f"{alert_name} requires review on {host}. "
        f"The activity involves {user} and is currently assessed as {severity.lower()} pending analyst validation."
    )
