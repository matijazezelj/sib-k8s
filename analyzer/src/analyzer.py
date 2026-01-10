"""Core alert analysis logic."""

import hashlib
import json
from datetime import datetime
from typing import Any, Dict, List, Optional

import structlog
from cachetools import TTLCache

from .config import settings
from .llm import get_provider
from .loki import push_to_loki
from .mitre import get_mitre_techniques, format_mitre_info
from .obfuscator import obfuscator

logger = structlog.get_logger()

# Response cache
_cache: Optional[TTLCache] = None


def get_cache() -> TTLCache:
    """Get or create the response cache."""
    global _cache
    if _cache is None:
        _cache = TTLCache(
            maxsize=settings.cache_max_size,
            ttl=settings.cache_ttl
        )
    return _cache


def generate_cache_key(alert: Dict[str, Any]) -> str:
    """Generate a cache key for an alert."""
    # Use rule and key output fields for caching
    key_data = {
        "rule": alert.get("rule", ""),
        "priority": alert.get("priority", ""),
        "output_fields": {
            k: v for k, v in alert.get("output_fields", {}).items()
            if k in ("evt.type", "syscall.type", "ka.verb", "ka.target.resource")
        }
    }
    key_str = json.dumps(key_data, sort_keys=True)
    return hashlib.sha256(key_str.encode()).hexdigest()


def build_analysis_prompt(alert: Dict[str, Any], obfuscated: Dict[str, Any]) -> str:
    """Build the analysis prompt for the LLM."""
    rule_name = alert.get("rule", "Unknown Rule")
    priority = alert.get("priority", "Unknown")
    output = obfuscated.get("output", alert.get("output", "No output"))
    output_fields = obfuscated.get("output_fields", {})
    
    # Get MITRE mapping
    mitre_techniques = get_mitre_techniques(rule_name)
    mitre_info = format_mitre_info(mitre_techniques)
    
    prompt = f"""Analyze this Kubernetes security alert and provide actionable insights.

## Alert Details
- **Rule**: {rule_name}
- **Priority**: {priority}
- **Output**: {output}

## Context Fields
```json
{json.dumps(output_fields, indent=2)}
```

{mitre_info}

## Analysis Request
Please provide:

1. **Threat Assessment**: What is the severity and potential impact of this alert?

2. **Attack Vector Analysis**: How might an attacker be leveraging this behavior?

3. **Recommended Actions**: What immediate steps should be taken?
   - Containment measures
   - Investigation steps
   - Remediation actions

4. **Detection Improvements**: How can we improve detection for similar threats?

5. **Risk Score**: Rate the risk from 1-10 with justification.

Keep the response concise and actionable for a security operations team.
"""
    return prompt


async def analyze_alert(alert: Dict[str, Any]) -> Dict[str, Any]:
    """
    Analyze a Falco alert using LLM with obfuscation.
    
    Args:
        alert: Raw Falco alert from Falcosidekick
        
    Returns:
        Analysis result with recommendations
    """
    start_time = datetime.utcnow()
    
    # Check cache first
    if settings.cache_enabled:
        cache = get_cache()
        cache_key = generate_cache_key(alert)
        
        if cache_key in cache:
            logger.info("Cache hit for alert analysis", rule=alert.get("rule"))
            cached = cache[cache_key]
            cached["cached"] = True
            cached["analysis_time_ms"] = 0
            return cached
    
    # Obfuscate the alert
    obfuscated_alert = obfuscator.obfuscate_alert(alert)
    
    # Build prompt
    prompt = build_analysis_prompt(alert, obfuscated_alert)
    
    # Get analysis from LLM
    try:
        provider = get_provider()
        llm_response = await provider.analyze(prompt)
    except Exception as e:
        logger.error("LLM analysis failed", error=str(e), rule=alert.get("rule"))
        llm_response = f"Analysis unavailable: {str(e)}"
    
    # Get MITRE techniques
    mitre_techniques = get_mitre_techniques(alert.get("rule", ""))
    
    # Calculate analysis time
    analysis_time = (datetime.utcnow() - start_time).total_seconds() * 1000
    
    result = {
        "alert": {
            "rule": alert.get("rule"),
            "priority": alert.get("priority"),
            "time": alert.get("time"),
            "source": alert.get("source"),
        },
        "analysis": llm_response,
        "mitre_techniques": [
            {
                "id": t.id,
                "name": t.name,
                "tactic": t.tactic,
                "url": t.url
            }
            for t in mitre_techniques
        ],
        "obfuscation_level": settings.obfuscation_level.value,
        "analysis_time_ms": round(analysis_time, 2),
        "cached": False,
        "timestamp": datetime.utcnow().isoformat(),
    }
    
    # Store in cache
    if settings.cache_enabled:
        cache[cache_key] = result
    
    # Push to Loki for Grafana visibility
    await push_to_loki(result)
    
    logger.info(
        "Alert analyzed",
        rule=alert.get("rule"),
        priority=alert.get("priority"),
        mitre_count=len(mitre_techniques),
        analysis_time_ms=analysis_time
    )
    
    return result


async def batch_analyze(alerts: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
    """Analyze multiple alerts."""
    results = []
    for alert in alerts:
        result = await analyze_alert(alert)
        results.append(result)
    return results
