"""
Generador de dataset ficticio de logs de acceso HTTP.
Simula trafico normal y anomalo (ataques, escaneos, fuerza bruta).
"""

import pandas as pd
import numpy as np
import random
from datetime import datetime, timedelta

TOTAL_LOGS = 5000
ANOMALY_RATIO = 0.15

NORMAL_IPS = [f"192.168.{random.randint(1,10)}.{random.randint(1,254)}" for _ in range(100)]
ATTACK_IPS = [f"10.{random.randint(0,255)}.{random.randint(0,255)}.{random.randint(1,254)}" for _ in range(20)]

NORMAL_ENDPOINTS = [
    "/", "/home", "/products", "/cart", "/checkout",
    "/api/products", "/api/cart", "/api/user/profile",
    "/static/css/main.css", "/static/js/app.js",
    "/images/product1.jpg", "/favicon.ico"
]

SUSPICIOUS_ENDPOINTS = [
    "/wp-admin", "/admin", "/wp-login.php", "/.env",
    "/config.php", "/backup.sql", "/phpinfo.php",
    "/etc/passwd", "/api/users", "/../../../etc/passwd",
    "/wp-config.php", "/shell.php", "/cmd.php",
    "/.git/config", "/api/admin/users", "/actuator/env"
]

NORMAL_USER_AGENTS = [
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36",
    "Mozilla/5.0 (iPhone; CPU iPhone OS 14_0 like Mac OS X)",
    "Mozilla/5.0 (Linux; Android 11; Pixel 5)",
]

SUSPICIOUS_USER_AGENTS = [
    "sqlmap/1.7.8", "Nikto/2.1.6", "python-requests/2.28.0",
    "curl/7.68.0", "Nmap Scripting Engine", "masscan/1.0", "-", "",
]


def generate_normal_log(timestamp):
    return {
        "timestamp": timestamp.strftime("%Y-%m-%d %H:%M:%S"),
        "ip": random.choice(NORMAL_IPS),
        "method": random.choice(["GET", "POST"]),
        "endpoint": random.choice(NORMAL_ENDPOINTS),
        "status_code": random.choice([200, 200, 200, 301, 302, 304, 404]),
        "response_size": random.randint(500, 50000),
        "response_time_ms": random.randint(50, 500),
        "user_agent": random.choice(NORMAL_USER_AGENTS),
        "requests_per_minute": random.randint(1, 20),
        "is_anomaly": 0
    }


def generate_anomaly_log(timestamp, attack_type=None):
    if attack_type is None:
        attack_type = random.choice(["brute_force", "scanner", "sql_injection", "path_traversal", "dos"])

    base = {
        "timestamp": timestamp.strftime("%Y-%m-%d %H:%M:%S"),
        "ip": random.choice(ATTACK_IPS),
        "is_anomaly": 1
    }

    if attack_type == "brute_force":
        base.update({
            "method": "POST",
            "endpoint": random.choice(["/wp-login.php", "/admin/login", "/api/auth"]),
            "status_code": random.choice([401, 403, 200]),
            "response_size": random.randint(100, 1000),
            "response_time_ms": random.randint(100, 300),
            "user_agent": random.choice(NORMAL_USER_AGENTS),
            "requests_per_minute": random.randint(60, 300),
        })
    elif attack_type == "scanner":
        base.update({
            "method": random.choice(["GET", "OPTIONS"]),
            "endpoint": random.choice(SUSPICIOUS_ENDPOINTS),
            "status_code": random.choice([404, 403, 200]),
            "response_size": random.randint(0, 500),
            "response_time_ms": random.randint(10, 100),
            "user_agent": random.choice(SUSPICIOUS_USER_AGENTS),
            "requests_per_minute": random.randint(100, 500),
        })
    elif attack_type == "sql_injection":
        base.update({
            "method": "GET",
            "endpoint": "/api/products?id=1' OR '1'='1",
            "status_code": random.choice([500, 200, 400]),
            "response_size": random.randint(0, 2000),
            "response_time_ms": random.randint(500, 5000),
            "user_agent": random.choice(SUSPICIOUS_USER_AGENTS + NORMAL_USER_AGENTS),
            "requests_per_minute": random.randint(5, 50),
        })
    elif attack_type == "path_traversal":
        base.update({
            "method": "GET",
            "endpoint": random.choice(["/../../../etc/passwd", "/.env", "/.git/config"]),
            "status_code": random.choice([400, 403, 404, 200]),
            "response_size": random.randint(0, 1000),
            "response_time_ms": random.randint(50, 200),
            "user_agent": random.choice(SUSPICIOUS_USER_AGENTS),
            "requests_per_minute": random.randint(1, 30),
        })
    elif attack_type == "dos":
        base.update({
            "method": "GET",
            "endpoint": random.choice(NORMAL_ENDPOINTS),
            "status_code": random.choice([200, 503, 429]),
            "response_size": random.randint(500, 5000),
            "response_time_ms": random.randint(1000, 10000),
            "user_agent": random.choice(NORMAL_USER_AGENTS + SUSPICIOUS_USER_AGENTS),
            "requests_per_minute": random.randint(500, 2000),
        })

    return base


def generate_dataset(total=TOTAL_LOGS, anomaly_ratio=ANOMALY_RATIO):
    logs = []
    start_time = datetime.now() - timedelta(days=7)
    n_anomalies = int(total * anomaly_ratio)
    n_normal = total - n_anomalies

    for i in range(n_normal):
        ts = start_time + timedelta(seconds=random.randint(0, 7 * 24 * 3600))
        logs.append(generate_normal_log(ts))

    attack_types = ["brute_force", "scanner", "sql_injection", "path_traversal", "dos"]
    for i in range(n_anomalies):
        ts = start_time + timedelta(seconds=random.randint(0, 7 * 24 * 3600))
        logs.append(generate_anomaly_log(ts, attack_types[i % len(attack_types)]))

    df = pd.DataFrame(logs)
    df = df.sample(frac=1).reset_index(drop=True)
    return df


if __name__ == "__main__":
    df = generate_dataset()
    df.to_csv("app/data/access_logs.csv", index=False)
    print(f"Dataset generado: {len(df)} registros")
    print(f"Anomalias: {df['is_anomaly'].sum()} ({df['is_anomaly'].mean()*100:.1f}%)")
    print(df.head())