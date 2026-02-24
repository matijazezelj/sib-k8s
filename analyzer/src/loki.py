"""Loki client for pushing analysis results."""

import json
import re
import time
from typing import Any, Dict, Optional

import httpx
import structlog

from .config import settings

logger = structlog.get_logger()

# Global HTTP client
_client: Optional[httpx.AsyncClient] = None


def get_client() -> httpx.AsyncClient:
    """Get or create the HTTP client."""
    global _client
    if _client is None:
        _client = httpx.AsyncClient(timeout=30.0)
    return _client


async def push_to_loki(analysis_result: Dict[str, Any]) -> bool:
    """
    Push analysis result to Loki.
    
    Args:
        analysis_result: The analysis result to push
        
    Returns:
        True if successful, False otherwise
    """
    if not settings.loki_url:
        logger.debug("Loki URL not configured, skipping push")
        return False
    
    try:
        # Build Loki push payload
        # Loki expects nanosecond timestamps
        timestamp_ns = str(int(time.time() * 1_000_000_000))
        
        alert_info = analysis_result.get("alert", {})
        
        # Create log entry with analysis
        log_entry = json.dumps({
            "rule": alert_info.get("rule"),
            "priority": alert_info.get("priority"),
            "source": alert_info.get("source"),
            "analysis": analysis_result.get("analysis"),
            "mitre_techniques": analysis_result.get("mitre_techniques", []),
            "risk_score": extract_risk_score(analysis_result.get("analysis", "")),
            "analysis_time_ms": analysis_result.get("analysis_time_ms"),
            "cached": analysis_result.get("cached"),
            "obfuscation_level": analysis_result.get("obfuscation_level"),
        })
        
        # Build labels
        labels = {
            "job": "sib-k8s-analysis",
            "source": "ai_analysis",
            "rule": sanitize_label(alert_info.get("rule", "unknown")),
            "priority": sanitize_label(alert_info.get("priority", "unknown")),
            "alert_source": sanitize_label(alert_info.get("source", "unknown")),
        }
        
        # Loki push format
        payload = {
            "streams": [
                {
                    "stream": labels,
                    "values": [
                        [timestamp_ns, log_entry]
                    ]
                }
            ]
        }
        
        client = get_client()
        response = await client.post(
            f"{settings.loki_url}/loki/api/v1/push",
            json=payload,
            headers={"Content-Type": "application/json"}
        )
        
        if response.status_code == 204:
            logger.info(
                "Analysis pushed to Loki",
                rule=alert_info.get("rule"),
                status=response.status_code
            )
            return True
        else:
            logger.warning(
                "Failed to push to Loki",
                status=response.status_code,
                response=response.text
            )
            return False
            
    except Exception as e:
        logger.error("Error pushing to Loki", error=str(e))
        return False


def sanitize_label(value: str) -> str:
    """Sanitize a string to be a valid Loki label value."""
    if not value:
        return "unknown"
    # Replace spaces and special characters
    sanitized = value.replace(" ", "_").replace("/", "_").replace(":", "_")
    # Limit length
    return sanitized[:128]


def extract_risk_score(analysis: str) -> Optional[int]:
    """Extract risk score from analysis text."""
    # Look for patterns like "Risk Score: 7/10" or "risk: 4/10" or "7 out of 10"
    patterns = [
        r'[Rr]isk\s*[Ss]core[:\s]+(\d+)/10',
        r'[Rr]isk[:\s]+(\d+)/10',
        r'(\d+)\s*(?:out of|/)\s*10',
        r'[Ss]everity[:\s]+(\d+)/10',
    ]
    
    for pattern in patterns:
        match = re.search(pattern, analysis)
        if match:
            try:
                score = int(match.group(1))
                if 1 <= score <= 10:
                    return score
            except ValueError:
                continue
    
    return None
