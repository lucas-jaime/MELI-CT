"""
API REST para deteccion de anomalias en logs de acceso.
Orquesta el flujo: Agente Ingestor -> Modelo IA -> Agente Decision
"""

from fastapi import FastAPI, HTTPException
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel
import time

from app.agents.ingestion import IngestionAgent
from app.agents.decision import DecisionAgent
from app.model.detector import get_detector
from app.config import DATASET_MODE

app = FastAPI(
    title="Anomaly Detection API",
    description="Deteccion inteligente de comportamientos anomalos en registros de acceso. Challenge Mercado Libre.",
    version="1.0.0",
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_methods=["*"],
    allow_headers=["*"],
)

ingestion_agent = IngestionAgent()
decision_agent = DecisionAgent()


class AnalyzeRequest(BaseModel):
    logs: list[dict]

    class Config:
        json_schema_extra = {
            "example": {
                "logs": [
                    {
                        "ip": "192.168.1.100",
                        "method": "GET",
                        "endpoint": "/api/products",
                        "status_code": 200,
                        "response_size": 1024,
                        "response_time_ms": 120,
                        "user_agent": "Mozilla/5.0",
                        "requests_per_minute": 5
                    },
                    {
                        "ip": "10.0.0.1",
                        "method": "GET",
                        "endpoint": "/.env",
                        "status_code": 404,
                        "response_size": 0,
                        "response_time_ms": 50,
                        "user_agent": "Nikto/2.1.6",
                        "requests_per_minute": 250
                    }
                ]
            }
        }


@app.get("/", tags=["Health"])
def root():
    return {
        "service": "Anomaly Detection API",
        "version": "1.0.0",
        "status": "running",
        "dataset_mode": DATASET_MODE,
        "endpoints": {
            "analyze": "POST /analyze",
            "health": "GET /health",
            "docs": "GET /docs"
        }
    }


@app.get("/health", tags=["Health"])
def health():
    """Verifica que el servicio y los modelos esten disponibles."""
    try:
        detector = get_detector()
        return {
            "status": "healthy",
            "dataset_mode": detector.dataset_mode,
            "models_loaded": detector.iso_model is not None and detector.rf_model is not None,
            "isolation_forest": "loaded",
            "random_forest": "loaded"
        }
    except Exception as e:
        raise HTTPException(status_code=503, detail=f"Servicio no disponible: {str(e)}")


@app.post("/analyze", tags=["Analysis"])
def analyze(request: AnalyzeRequest):
    """
    Analiza un lote de logs en busca de comportamientos anomalos.

    Modos soportados:
    - synthetic: logs HTTP con campos ip, method, endpoint, status_code, etc.
    - kaggle: logs de red con campos Flow Duration, Flow Packets/s, etc.
    """
    if not request.logs:
        raise HTTPException(status_code=400, detail="Se requiere al menos un log.")

    if len(request.logs) > 10000:
        raise HTTPException(status_code=400, detail="Maximo 10.000 logs por request.")

    start_time = time.time()

    try:
        # PASO 1: Agente de Ingesion
        ingestion_result = ingestion_agent.process(request.logs)

        if ingestion_result.total_valid == 0:
            raise HTTPException(
                status_code=422,
                detail={
                    "message": "Ningun log valido para analizar.",
                    "errors": ingestion_result.invalid_reasons
                }
            )

        # PASO 2: Modelo de IA
        detector = get_detector()
        model_results = detector.predict(ingestion_result.processed_logs)

        # PASO 3: Agente de Decision
        summary = decision_agent.decide(model_results)

        elapsed_ms = round((time.time() - start_time) * 1000, 2)

        return {
            "status": "success",
            "processing_time_ms": elapsed_ms,
            "dataset_mode": detector.dataset_mode,
            "ingestion": {
                "total_received": ingestion_result.total_received,
                "total_valid": ingestion_result.total_valid,
                "total_invalid": ingestion_result.total_invalid,
                "invalid_reasons": ingestion_result.invalid_reasons
            },
            "analysis": {
                "total_analyzed": summary.total_analyzed,
                "threats_detected": summary.threats_detected,
                "threat_rate": summary.threat_rate,
                "threat_percentage": f"{summary.threat_rate * 100:.1f}%",
                "actions_summary": summary.actions,
                "threat_levels_summary": summary.threat_levels,
                "most_suspicious_ips": summary.most_suspicious_ips,
                "recommendations": summary.recommendations,
            },
            "decisions": [d.model_dump() for d in summary.decisions]
        }

    except HTTPException:
        raise
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Error interno: {str(e)}")