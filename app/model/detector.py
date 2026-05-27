"""
Inferencia del modelo de deteccion de anomalias.
Soporta dos modos: synthetic y kaggle.
Entrena automaticamente si los modelos no existen o si cambio el modo.
"""

import pickle
import pandas as pd
import numpy as np
import os

from app.config import (
    DATASET_MODE, MODEL_PATH, SUPERVISED_MODEL_PATH,
    SCALER_PATH, DATASET_MODE_PATH,
    SYNTHETIC_FEATURES, KAGGLE_FEATURES,
    SUSPICIOUS_ENDPOINTS, SUSPICIOUS_UAS
)


class AnomalyDetector:
    def __init__(self):
        self.iso_model = None
        self.rf_model = None
        self.scaler = None
        self.dataset_mode = "synthetic"
        self._load_models()

    def _needs_training(self) -> bool:
        """Verifica si hay que entrenar o reentrenar los modelos."""
        # Si no existen los modelos
        if not os.path.exists(MODEL_PATH):
            print("Modelos no encontrados. Entrenando...")
            return True

        # Si cambio el modo respecto al entrenamiento anterior
        if os.path.exists(DATASET_MODE_PATH):
            with open(DATASET_MODE_PATH, "r") as f:
                trained_mode = f.read().strip()
            if trained_mode != DATASET_MODE:
                print(f"Modo cambio de '{trained_mode}' a '{DATASET_MODE}'. Reentrenando...")
                return True

        return False

    def _load_models(self):
        """Carga los modelos desde disco. Entrena si es necesario."""
        if self._needs_training():
            from app.model.train import main as train_main
            train_main(mode=DATASET_MODE)

        with open(MODEL_PATH, "rb") as f:
            self.iso_model = pickle.load(f)
        with open(SUPERVISED_MODEL_PATH, "rb") as f:
            self.rf_model = pickle.load(f)
        with open(SCALER_PATH, "rb") as f:
            self.scaler = pickle.load(f)

        # Leer el modo con que fueron entrenados
        if os.path.exists(DATASET_MODE_PATH):
            with open(DATASET_MODE_PATH, "r") as f:
                self.dataset_mode = f.read().strip()

        print(f"Modelos cargados correctamente. Modo: {self.dataset_mode}")

    def _engineer_features_synthetic(self, logs: list[dict]) -> pd.DataFrame:
        """Feature engineering para logs HTTP del dataset sintetico."""
        df = pd.DataFrame(logs)

        method_map = {"GET": 0, "POST": 1, "PUT": 2, "DELETE": 3, "OPTIONS": 4, "TRACE": 5}
        df["method"] = df.get("method", pd.Series(["GET"] * len(df))).map(method_map).fillna(0)

        df["endpoint_suspicious"] = df["endpoint"].apply(
            lambda e: 1 if any(s in str(e) for s in SUSPICIOUS_ENDPOINTS) else 0
        )
        df["user_agent_suspicious"] = df["user_agent"].apply(
            lambda ua: 1 if any(s in str(ua).lower() for s in SUSPICIOUS_UAS) else 0
        )

        for col in ["status_code", "response_size", "response_time_ms", "requests_per_minute"]:
            if col not in df.columns:
                df[col] = 0

        return df[SYNTHETIC_FEATURES]

    def _engineer_features_kaggle(self, logs: list[dict]) -> pd.DataFrame:
        """Feature engineering para logs de red del dataset CICIDS2017."""
        df = pd.DataFrame(logs)
        df = df.replace([float('inf'), float('-inf')], 0)
        df = df.fillna(0)

        for col in KAGGLE_FEATURES:
            if col not in df.columns:
                df[col] = 0

        return df[KAGGLE_FEATURES]

    def _engineer_features(self, logs: list[dict]) -> pd.DataFrame:
        """Selecciona el feature engineering segun el modo."""
        if self.dataset_mode == "kaggle":
            return self._engineer_features_kaggle(logs)
        return self._engineer_features_synthetic(logs)

    def predict(self, logs: list[dict]) -> list[dict]:
        """Predice anomalias combinando Isolation Forest + Random Forest."""
        X = self._engineer_features(logs)
        X_scaled = pd.DataFrame(self.scaler.transform(X), columns=X.columns)

        iso_preds = self.iso_model.predict(X_scaled)
        iso_scores = self.iso_model.score_samples(X_scaled)
        rf_proba = self.rf_model.predict_proba(X_scaled)[:, 1]

        results = []
        for i, log in enumerate(logs):
            iso_anomaly = iso_preds[i] == -1
            rf_anomaly = rf_proba[i] > 0.5
            is_anomaly = iso_anomaly or rf_anomaly
            confidence = float((rf_proba[i] + (1 if iso_anomaly else 0)) / 2)

            if self.dataset_mode == "synthetic":
                endpoint_suspicious = bool(X["endpoint_suspicious"].iloc[i])
                user_agent_suspicious = bool(X["user_agent_suspicious"].iloc[i])
            else:
                endpoint_suspicious = bool(X["Flow Packets/s"].iloc[i] > 10000)
                user_agent_suspicious = bool(X["FIN Flag Count"].iloc[i] > 5)

            results.append({
                "log": log,
                "is_anomaly": is_anomaly,
                "confidence": round(confidence, 3),
                "isolation_forest_score": round(float(iso_scores[i]), 3),
                "random_forest_proba": round(float(rf_proba[i]), 3),
                "endpoint_suspicious": endpoint_suspicious,
                "user_agent_suspicious": user_agent_suspicious,
                "dataset_mode": self.dataset_mode,
            })

        return results


_detector_instance = None

def get_detector() -> AnomalyDetector:
    global _detector_instance
    if _detector_instance is None:
        _detector_instance = AnomalyDetector()
    return _detector_instance