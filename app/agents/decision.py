"""
Agente 2: Agente de Decision.
Responsabilidad: recibir los resultados del modelo de IA
y decidir que accion tomar: BLOCK, ALERT, MONITOR o ALLOW.
Soporta modo synthetic y kaggle.
"""

from pydantic import BaseModel
from enum import Enum
from app.config import DATASET_MODE


class Action(str, Enum):
    BLOCK = "BLOCK"
    ALERT = "ALERT"
    MONITOR = "MONITOR"
    ALLOW = "ALLOW"


class ThreatLevel(str, Enum):
    CRITICAL = "CRITICAL"
    HIGH = "HIGH"
    MEDIUM = "MEDIUM"
    LOW = "LOW"
    NONE = "NONE"


class LogDecision(BaseModel):
    ip: str
    endpoint: str
    method: str
    is_anomaly: bool
    threat_level: ThreatLevel
    action: Action
    confidence: float
    reasons: list[str]
    suggested_rule: str


class DecisionSummary(BaseModel):
    total_analyzed: int
    threats_detected: int
    threat_rate: float
    actions: dict
    threat_levels: dict
    most_suspicious_ips: list[str]
    recommendations: list[str]
    decisions: list[LogDecision]


class DecisionAgent:
    """
    Agente 2 — Decision.
    Aplica reglas de negocio segun el modo activo.
    """

    # Solo aplican en modo synthetic
    CRITICAL_ENDPOINTS = [
        "/wp-config.php", "/.env", "/etc/passwd", "/etc/shadow",
        "/backup.sql", "/shell.php", "/cmd.php", "/.git/config"
    ]

    ATTACK_PATTERNS = [
        "OR '1'='1", "UNION SELECT", "../", "..%2F",
        "<script>", "javascript:", "eval(", "exec("
    ]

    # Endpoints sospechosos — comparacion exacta de prefijo
    SUSPICIOUS_ENDPOINT_PREFIXES = [
        "/wp-admin", "/wp-login", "/admin", "/phpinfo",
        "/shell", "/cmd", "/backup", "/config"
    ]

    def decide(self, model_results: list[dict]) -> DecisionSummary:
        decisions = []
        ip_anomaly_count = {}

        for result in model_results:
            log = result["log"]
            ip = log.get("ip", "unknown")
            endpoint = log.get("endpoint", "/")
            method = log.get("method", "GET")

            reasons = []
            threat_level = ThreatLevel.NONE
            action = Action.ALLOW

            if result["is_anomaly"]:
                ip_anomaly_count[ip] = ip_anomaly_count.get(ip, 0) + 1

                if DATASET_MODE == "synthetic":
                    reasons = self._get_synthetic_reasons(result, log, endpoint)
                else:
                    reasons = self._get_kaggle_reasons(result, log)

                # Determinar nivel y accion
                threat_level, action = self._classify_threat(
                    result, endpoint, DATASET_MODE
                )

            suggested_rule = self._generate_firewall_rule(ip, endpoint, action)

            decisions.append(LogDecision(
                ip=ip,
                endpoint=endpoint,
                method=method,
                is_anomaly=result["is_anomaly"],
                threat_level=threat_level,
                action=action,
                confidence=result["confidence"],
                reasons=reasons,
                suggested_rule=suggested_rule
            ))

        return self._build_summary(decisions, ip_anomaly_count)

    def _get_synthetic_reasons(self, result: dict, log: dict, endpoint: str) -> list[str]:
        """Razones para modo synthetic basadas en HTTP."""
        reasons = []

        # Verificar endpoint sospechoso con prefijo exacto
        is_suspicious_endpoint = any(
            endpoint.startswith(prefix)
            for prefix in self.SUSPICIOUS_ENDPOINT_PREFIXES
        )
        if is_suspicious_endpoint:
            reasons.append(f"Endpoint sospechoso: {endpoint}")

        if result.get("user_agent_suspicious"):
            reasons.append("User-Agent sospechoso detectado")

        if log.get("requests_per_minute", 0) > 100:
            reasons.append(f"Tasa de requests elevada: {log.get('requests_per_minute')} req/min")

        if log.get("response_time_ms", 0) > 3000:
            reasons.append("Tiempo de respuesta anomalo (posible DoS)")

        if any(p in endpoint for p in self.ATTACK_PATTERNS):
            reasons.append("Patron de ataque conocido detectado en endpoint")

        if log.get("status_code") in [401, 403] and log.get("requests_per_minute", 0) > 30:
            reasons.append("Posible ataque de fuerza bruta (errores de autenticacion)")

        if not reasons:
            reasons.append("Comportamiento anomalo detectado por el modelo de IA")

        return reasons

    def _get_kaggle_reasons(self, result: dict, log: dict) -> list[str]:
        """
        Razones para modo kaggle.
        Confia en el modelo de IA para la deteccion y agrega
        contexto basado en puertos y scores del modelo.
        """
        reasons = []

        dst_port = log.get("Destination Port", 0)
        fin_flags = log.get("FIN Flag Count", 0)
        iso_score = result.get("isolation_forest_score", 0)
        rf_proba = result.get("random_forest_proba", 0)

        # Contexto del modelo
        if rf_proba >= 0.85:
            reasons.append(f"Random Forest: alta probabilidad de ataque ({rf_proba:.0%})")
        elif rf_proba >= 0.50:
            reasons.append(f"Random Forest: probabilidad de ataque moderada ({rf_proba:.0%})")

        if iso_score < -0.2:
            reasons.append(f"Isolation Forest: patron estadisticamente anomalo (score: {iso_score:.3f})")

        # Puerto sensible como contexto adicional
        SENSITIVE_PORTS = {
            21: "FTP", 22: "SSH", 23: "Telnet",
            3389: "RDP", 445: "SMB", 1433: "MSSQL",
            3306: "MySQL", 5432: "PostgreSQL"
        }
        if dst_port in SENSITIVE_PORTS:
            reasons.append(f"Trafico anomalo hacia puerto sensible: {dst_port} ({SENSITIVE_PORTS[dst_port]})")

        if fin_flags > 0 and rf_proba >= 0.5:
            reasons.append("Flags TCP inusuales en trafico anomalo")

        if not reasons:
            reasons.append("Patron de trafico de red anomalo detectado por el modelo de IA")

        return reasons

    def _classify_threat(self, result: dict, endpoint: str, mode: str) -> tuple:
        """Determina nivel de amenaza y accion segun el modo."""
        if mode == "synthetic":
            # En synthetic usamos reglas de endpoint y patrones HTTP
            is_critical = any(ce in endpoint for ce in self.CRITICAL_ENDPOINTS)
            has_pattern = any(p in endpoint for p in self.ATTACK_PATTERNS)

            if is_critical or has_pattern:
                return ThreatLevel.CRITICAL, Action.BLOCK
            elif result["confidence"] >= 0.8:
                return ThreatLevel.HIGH, Action.BLOCK
            elif result["confidence"] >= 0.5:
                return ThreatLevel.MEDIUM, Action.ALERT
            else:
                return ThreatLevel.LOW, Action.MONITOR

        else:
            # En kaggle usamos solo el confidence del modelo
            if result["confidence"] >= 0.85:
                return ThreatLevel.CRITICAL, Action.BLOCK
            elif result["confidence"] >= 0.70:
                return ThreatLevel.HIGH, Action.BLOCK
            elif result["confidence"] >= 0.50:
                return ThreatLevel.MEDIUM, Action.ALERT
            else:
                return ThreatLevel.LOW, Action.MONITOR

    def _generate_firewall_rule(self, ip: str, endpoint: str, action: Action) -> str:
        if action == Action.BLOCK:
            return f"iptables -A INPUT -s {ip} -j DROP"
        elif action == Action.ALERT:
            return f"iptables -A INPUT -s {ip} -j LOG --log-prefix 'ALERT: '"
        elif action == Action.MONITOR:
            return f"# Monitorear IP {ip} - aumentar logging para esta fuente"
        return f"# IP {ip} permitida - trafico normal"

    def _build_summary(self, decisions: list, ip_anomaly_count: dict) -> DecisionSummary:
        threats = [d for d in decisions if d.is_anomaly]
        actions_count = {}
        threat_levels_count = {}

        for d in decisions:
            actions_count[d.action.value] = actions_count.get(d.action.value, 0) + 1
            threat_levels_count[d.threat_level.value] = threat_levels_count.get(d.threat_level.value, 0) + 1

        suspicious_ips = sorted(ip_anomaly_count.items(), key=lambda x: x[1], reverse=True)
        top_ips = [ip for ip, _ in suspicious_ips[:5]]
        recommendations = self._generate_recommendations(decisions, ip_anomaly_count)

        return DecisionSummary(
            total_analyzed=len(decisions),
            threats_detected=len(threats),
            threat_rate=round(len(threats) / len(decisions), 3) if decisions else 0,
            actions=actions_count,
            threat_levels=threat_levels_count,
            most_suspicious_ips=top_ips,
            recommendations=recommendations,
            decisions=decisions
        )

    def _generate_recommendations(self, decisions: list, ip_anomaly_count: dict) -> list[str]:
        recs = []
        threats = [d for d in decisions if d.is_anomaly]

        if not threats:
            return ["No se detectaron amenazas. El trafico parece normal."]

        threat_rate = len(threats) / len(decisions) if decisions else 0
        if threat_rate > 0.3:
            recs.append(f"CRITICO: Tasa de amenazas elevada ({threat_rate*100:.1f}%). Revisar configuracion de firewall inmediatamente.")

        blocks = [d for d in decisions if d.action == Action.BLOCK]
        if blocks:
            recs.append(f"Bloquear {len(set(d.ip for d in blocks))} IPs identificadas como amenaza critica.")

        high_freq_ips = [ip for ip, count in ip_anomaly_count.items() if count > 5]
        if high_freq_ips:
            recs.append(f"Implementar rate limiting para {len(high_freq_ips)} IPs con actividad sospechosa repetida.")

        if DATASET_MODE == "synthetic":
            brute_force = [d for d in threats if any("fuerza bruta" in r for r in d.reasons)]
            if brute_force:
                recs.append("Habilitar CAPTCHA o 2FA en endpoints de autenticacion para prevenir fuerza bruta.")
            scanners = [d for d in threats if any("User-Agent sospechoso" in r for r in d.reasons)]
            if scanners:
                recs.append("Detectados posibles escaneos automatizados. Considerar Web Application Firewall (WAF).")
        else:
            ddos = [d for d in threats if any("DDoS" in r or "paquetes" in r.lower() for r in d.reasons)]
            if ddos:
                recs.append("Detectado posible ataque DDoS. Activar rate limiting y filtros de trafico.")
            scanners = [d for d in threats if any("escaneo" in r.lower() for r in d.reasons)]
            if scanners:
                recs.append("Detectado posible escaneo de puertos. Revisar reglas de firewall perimetral.")
            bots = [d for d in threats if any("bot" in r.lower() for r in d.reasons)]
            if bots:
                recs.append("Detectado posible trafico de botnet. Considerar bloqueo de rangos IP sospechosos.")

        return recs