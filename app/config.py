"""
Configuracion central del sistema.
Permite elegir entre dataset ficticio o Kaggle CICIDS2017.
"""

import os

# --- Seleccion de dataset ---
# Opciones: "synthetic" o "kaggle"
DATASET_MODE = os.getenv("DATASET_MODE", "synthetic")

# --- Rutas ---
SYNTHETIC_CSV_PATH = "app/data/access_logs.csv"
KAGGLE_CSV_PATH = "app/data/cicids2017.csv"

# --- Rutas de modelos ---
MODEL_PATH = "app/model/isolation_forest.pkl"
SUPERVISED_MODEL_PATH = "app/model/random_forest.pkl"
SCALER_PATH = "app/model/scaler.pkl"
DATASET_MODE_PATH = "app/model/dataset_mode.txt"

# --- Features por dataset ---
SYNTHETIC_FEATURES = [
    "method", "status_code", "response_size",
    "response_time_ms", "requests_per_minute",
    "endpoint_suspicious", "user_agent_suspicious"
]

KAGGLE_FEATURES = [
    "Destination Port", "Flow Duration",
    "Total Fwd Packets", "Total Length of Fwd Packets",
    "Fwd Packet Length Mean", "Fwd Packet Length Std",
    "Bwd Packet Length Mean", "Bwd Packet Length Std",
    "Flow Bytes/s", "Flow Packets/s",
    "Flow IAT Mean", "Flow IAT Std",
    "FIN Flag Count", "PSH Flag Count", "ACK Flag Count",
    "Average Packet Size", "Init_Win_bytes_forward",
    "Init_Win_bytes_backward", "Active Mean", "Idle Mean"
]

# Endpoints y User-Agents sospechosos para dataset sintetico
SUSPICIOUS_ENDPOINTS = [
    "/wp-admin", "/admin", "/wp-login.php", "/.env", "/config.php",
    "/backup.sql", "/phpinfo.php", "/etc/passwd", "/shell.php",
    "/.git", "/actuator", "/cmd.php", "passwd", "shadow", "OR '1'='1"
]

SUSPICIOUS_UAS = [
    "sqlmap", "nikto", "nmap", "masscan", "curl", "python-requests", "-", ""
]