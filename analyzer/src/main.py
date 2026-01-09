"""FastAPI application for the SIB-K8s Analyzer service."""

import json
from contextlib import asynccontextmanager
from typing import Any, Dict, List

import structlog
from fastapi import FastAPI, HTTPException, Request, Response
from fastapi.responses import JSONResponse
from prometheus_client import Counter, Histogram, generate_latest, CONTENT_TYPE_LATEST
from pydantic import BaseModel

from .analyzer import analyze_alert, batch_analyze
from .config import settings
from .llm import get_provider

# Configure structured logging
structlog.configure(
    processors=[
        structlog.stdlib.filter_by_level,
        structlog.stdlib.add_logger_name,
        structlog.stdlib.add_log_level,
        structlog.processors.TimeStamper(fmt="iso"),
        structlog.processors.JSONRenderer()
    ],
    wrapper_class=structlog.stdlib.BoundLogger,
    context_class=dict,
    logger_factory=structlog.stdlib.LoggerFactory(),
)

logger = structlog.get_logger()

# Prometheus metrics
ALERTS_RECEIVED = Counter(
    "sib_alerts_received_total",
    "Total number of alerts received",
    ["rule", "priority"]
)
ALERTS_ANALYZED = Counter(
    "sib_alerts_analyzed_total",
    "Total number of alerts analyzed",
    ["rule", "priority", "cached"]
)
ANALYSIS_DURATION = Histogram(
    "sib_analysis_duration_seconds",
    "Time spent analyzing alerts",
    buckets=[0.1, 0.5, 1.0, 2.0, 5.0, 10.0, 30.0, 60.0]
)


class FalcoAlert(BaseModel):
    """Falco alert model from Falcosidekick."""
    rule: str
    priority: str
    output: str
    source: str = "syscalls"
    time: str
    output_fields: Dict[str, Any] = {}
    hostname: str = ""
    tags: List[str] = []


class AnalysisResponse(BaseModel):
    """Response model for alert analysis."""
    alert: Dict[str, Any]
    analysis: str
    mitre_techniques: List[Dict[str, str]]
    obfuscation_level: str
    analysis_time_ms: float
    cached: bool
    timestamp: str


class HealthResponse(BaseModel):
    """Health check response."""
    status: str
    llm_provider: str
    llm_available: bool
    obfuscation_level: str
    cache_enabled: bool


@asynccontextmanager
async def lifespan(app: FastAPI):
    """Application lifespan handler."""
    logger.info(
        "Starting SIB-K8s Analyzer",
        llm_provider=settings.llm_provider.value,
        obfuscation_level=settings.obfuscation_level.value,
    )
    yield
    logger.info("Shutting down SIB-K8s Analyzer")


app = FastAPI(
    title="SIB-K8s Analyzer",
    description="AI-powered Kubernetes security alert analyzer with privacy-preserving obfuscation",
    version="1.0.0",
    lifespan=lifespan,
)


@app.get("/health", response_model=HealthResponse)
async def health_check():
    """Health check endpoint."""
    provider = get_provider()
    llm_available = await provider.health_check()
    
    return HealthResponse(
        status="healthy" if llm_available else "degraded",
        llm_provider=settings.llm_provider.value,
        llm_available=llm_available,
        obfuscation_level=settings.obfuscation_level.value,
        cache_enabled=settings.cache_enabled,
    )


@app.get("/ready")
async def readiness_check():
    """Kubernetes readiness probe."""
    return {"status": "ready"}


@app.get("/live")
async def liveness_check():
    """Kubernetes liveness probe."""
    return {"status": "alive"}


@app.get("/metrics")
async def metrics():
    """Prometheus metrics endpoint."""
    return Response(
        content=generate_latest(),
        media_type=CONTENT_TYPE_LATEST
    )


@app.post("/analyze", response_model=AnalysisResponse)
async def analyze_endpoint(alert: FalcoAlert):
    """
    Analyze a single Falco alert.
    
    This endpoint receives alerts from Falcosidekick and returns
    AI-powered analysis with MITRE ATT&CK mapping.
    """
    ALERTS_RECEIVED.labels(
        rule=alert.rule,
        priority=alert.priority
    ).inc()
    
    try:
        with ANALYSIS_DURATION.time():
            result = await analyze_alert(alert.model_dump())
        
        ALERTS_ANALYZED.labels(
            rule=alert.rule,
            priority=alert.priority,
            cached=str(result.get("cached", False))
        ).inc()
        
        return AnalysisResponse(**result)
    
    except Exception as e:
        logger.error("Analysis failed", error=str(e), rule=alert.rule)
        raise HTTPException(status_code=500, detail=str(e))


@app.post("/analyze/batch", response_model=List[AnalysisResponse])
async def batch_analyze_endpoint(alerts: List[FalcoAlert]):
    """
    Analyze multiple Falco alerts in batch.
    """
    for alert in alerts:
        ALERTS_RECEIVED.labels(
            rule=alert.rule,
            priority=alert.priority
        ).inc()
    
    try:
        results = await batch_analyze([a.model_dump() for a in alerts])
        
        for result in results:
            ALERTS_ANALYZED.labels(
                rule=result["alert"]["rule"],
                priority=result["alert"]["priority"],
                cached=str(result.get("cached", False))
            ).inc()
        
        return [AnalysisResponse(**r) for r in results]
    
    except Exception as e:
        logger.error("Batch analysis failed", error=str(e))
        raise HTTPException(status_code=500, detail=str(e))


@app.post("/webhook")
async def falcosidekick_webhook(request: Request):
    """
    Webhook endpoint for Falcosidekick.
    
    This endpoint is compatible with Falcosidekick's webhook output format.
    """
    try:
        body = await request.json()
        
        # Handle both single alert and array
        if isinstance(body, list):
            alerts = [FalcoAlert(**a) for a in body]
            results = await batch_analyze([a.model_dump() for a in alerts])
        else:
            alert = FalcoAlert(**body)
            results = [await analyze_alert(alert.model_dump())]
        
        return JSONResponse(
            content={"status": "processed", "count": len(results)},
            status_code=200
        )
    
    except Exception as e:
        logger.error("Webhook processing failed", error=str(e))
        return JSONResponse(
            content={"status": "error", "message": str(e)},
            status_code=500
        )


def main():
    """Run the application."""
    import uvicorn
    
    uvicorn.run(
        "src.main:app",
        host=settings.host,
        port=settings.port,
        reload=settings.debug,
    )


if __name__ == "__main__":
    main()
