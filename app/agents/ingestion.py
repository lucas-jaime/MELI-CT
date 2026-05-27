"""
Agente 1: Ingestor de logs.
Soporta dos modos:
  - synthetic: logs HTTP con campos ip, method, endpoint, etc.
  - kaggle: logs de red con features del dataset CICIDS2017
"""

from pydantic import BaseModel, field_validator
from typing import Optional
from datetime import datetime
from app.config import DATASET_MODE


class LogEntry(BaseModel):
    """Schema de un log. Campos HTTP opcionales en modo kaggle."""
    ip: str

    # Campos HTTP — obligatorios en modo synthetic, opcionales en kaggle
    method: Optional[str] = "GET"
    endpoint: Optional[str] = "/"
    status_code: Optional[int] = 200
    response_size: Optional[int] = 0
    response_time_ms: Optional[int] = 0
    user_agent: Optional[str] = ""
    requests_per_minute: Optional[int] = 0
    timestamp: Optional[str] = None

    @field_validator("method")
    @classmethod
    def method_must_be_valid(cls, v):
        if v is None:
            return "GET"
        valid = ["GET", "POST", "PUT", "DELETE", "OPTIONS", "PATCH", "HEAD", "TRACE"]
        if v.upper() not in valid:
            raise ValueError(f"Metodo HTTP invalido: {v}")
        return v.upper()

    @field_validator("status_code")
    @classmethod
    def status_code_must_be_valid(cls, v):
        if v is None:
            return 200
        if not (100 <= v <= 599):
            raise ValueError(f"Status code invalido: {v}")
        return v

    @field_validator("response_time_ms", "response_size", "requests_per_minute")
    @classmethod
    def must_be_non_negative(cls, v):
        if v is None:
            return 0
        if v < 0:
            raise ValueError("El valor no puede ser negativo")
        return v


class SyntheticLogEntry(LogEntry):
    """Schema estricto para modo synthetic — campos HTTP obligatorios."""
    method: str
    endpoint: str
    status_code: int
    response_size: int
    response_time_ms: int
    user_agent: str
    requests_per_minute: int


class IngestionResult(BaseModel):
    """Resultado del agente de ingesion."""
    total_received: int
    total_valid: int
    total_invalid: int
    invalid_reasons: list[str]
    processed_logs: list[dict]


class IngestionAgent:
    """
    Agente 1 — Ingestor de logs.
    Valida, normaliza y enriquece los logs antes de enviarlos al modelo.
    """

    def process(self, raw_logs: list[dict]) -> IngestionResult:
        """Procesa un lote de logs crudos."""
        valid_logs = []
        invalid_reasons = []

        for i, raw in enumerate(raw_logs):
            try:
                # En modo synthetic validamos campos HTTP estrictamente
                if DATASET_MODE == "synthetic":
                    entry = SyntheticLogEntry(**raw)
                else:
                    # En modo kaggle solo requerimos ip
                    if "ip" not in raw:
                        raw["ip"] = "0.0.0.0"
                    entry = LogEntry(**raw)

                processed = {**raw}
                processed["timestamp"] = processed.get("timestamp") or datetime.now().strftime("%Y-%m-%d %H:%M:%S")
                processed["ip"] = entry.ip
                processed["method"] = entry.method or "GET"
                processed["endpoint"] = entry.endpoint or "/"
                processed["status_code"] = entry.status_code or 200
                processed["response_size"] = entry.response_size or 0
                processed["response_time_ms"] = entry.response_time_ms or 0
                processed["user_agent"] = entry.user_agent or ""
                processed["requests_per_minute"] = entry.requests_per_minute or 0
                processed["endpoint_depth"] = len(str(processed["endpoint"]).split("/"))
                processed["has_query_params"] = "?" in str(processed["endpoint"])

                valid_logs.append(processed)

            except Exception as e:
                invalid_reasons.append(f"Log {i}: {str(e)}")

        return IngestionResult(
            total_received=len(raw_logs),
            total_valid=len(valid_logs),
            total_invalid=len(raw_logs) - len(valid_logs),
            invalid_reasons=invalid_reasons,
            processed_logs=valid_logs
        )

    def _extract_ip_features(self, ip: str) -> dict:
        try:
            parts = ip.split(".")
            return {
                "first_octet": int(parts[0]),
                "is_private": ip.startswith(("192.168.", "10.", "172.16."))
            }
        except Exception:
            return {"first_octet": 0, "is_private": False}