"""
Entrenamiento del modelo de deteccion de anomalias.
Soporta dos modos:
  - synthetic: dataset ficticio generado por generate.py
  - kaggle: dataset CICIDS2017 de Kaggle
"""

import pandas as pd
import numpy as np
import pickle
import os
from sklearn.ensemble import IsolationForest, RandomForestClassifier
from sklearn.preprocessing import StandardScaler
from sklearn.model_selection import train_test_split
from sklearn.metrics import classification_report

from app.config import (
    DATASET_MODE, SYNTHETIC_CSV_PATH, KAGGLE_CSV_PATH,
    MODEL_PATH, SUPERVISED_MODEL_PATH, SCALER_PATH, DATASET_MODE_PATH,
    SYNTHETIC_FEATURES, KAGGLE_FEATURES,
    SUSPICIOUS_ENDPOINTS, SUSPICIOUS_UAS
)


def engineer_features_synthetic(df: pd.DataFrame) -> pd.DataFrame:
    """Feature engineering para dataset sintetico."""
    df = df.copy()

    method_map = {"GET": 0, "POST": 1, "PUT": 2, "DELETE": 3, "OPTIONS": 4, "TRACE": 5}
    df["method"] = df["method"].map(method_map).fillna(0)

    df["endpoint_suspicious"] = df["endpoint"].apply(
        lambda e: 1 if any(s in str(e) for s in SUSPICIOUS_ENDPOINTS) else 0
    )
    df["user_agent_suspicious"] = df["user_agent"].apply(
        lambda ua: 1 if any(s in str(ua).lower() for s in SUSPICIOUS_UAS) else 0
    )

    return df[SYNTHETIC_FEATURES]


def engineer_features_kaggle(df: pd.DataFrame) -> pd.DataFrame:
    """
    Feature engineering para dataset CICIDS2017 de Kaggle.
    Limpia infinitos, NaN y selecciona las features mas relevantes.
    """
    df = df.copy()
    df = df.replace([float('inf'), float('-inf')], 0)
    df = df.fillna(0)

    missing = [c for c in KAGGLE_FEATURES if c not in df.columns]
    if missing:
        raise ValueError(f"Columnas faltantes en el dataset de Kaggle: {missing}")

    return df[KAGGLE_FEATURES]


def load_dataset(mode: str) -> tuple[pd.DataFrame, pd.Series]:
    """Carga el dataset segun el modo configurado."""
    if mode == "kaggle":
        if not os.path.exists(KAGGLE_CSV_PATH):
            raise FileNotFoundError(
                f"Dataset de Kaggle no encontrado en {KAGGLE_CSV_PATH}. "
                "Descargalo desde Kaggle y copialo a app/data/cicids2017.csv"
            )
        print(f"Cargando dataset Kaggle CICIDS2017 desde {KAGGLE_CSV_PATH}...")
        df = pd.read_csv(KAGGLE_CSV_PATH)

        if "Attack Type" not in df.columns:
            raise ValueError("El dataset de Kaggle debe tener la columna 'Attack Type'")

        df["is_anomaly"] = df["Attack Type"].apply(
            lambda x: 0 if str(x).strip().upper() == "NORMAL TRAFFIC" else 1
        )

        print(f"Tipos de ataque encontrados: {df['Attack Type'].unique()}")
        X = engineer_features_kaggle(df)

    else:
        if not os.path.exists(SYNTHETIC_CSV_PATH):
            print("Generando dataset sintetico...")
            from app.data.generate import generate_dataset
            df = generate_dataset()
            df.to_csv(SYNTHETIC_CSV_PATH, index=False)
        else:
            print(f"Cargando dataset sintetico desde {SYNTHETIC_CSV_PATH}...")
            df = pd.read_csv(SYNTHETIC_CSV_PATH)

        X = engineer_features_synthetic(df)

    y = df["is_anomaly"]
    print(f"Dataset cargado: {len(df)} registros")
    print(f"Anomalias: {y.sum()} ({y.mean()*100:.1f}%)")
    return X, y, df


def train_unsupervised(X: pd.DataFrame) -> IsolationForest:
    """Entrena Isolation Forest — modelo no supervisado."""
    print("\nEntrenando Isolation Forest (no supervisado)...")
    model = IsolationForest(
        n_estimators=200,
        contamination=0.15,
        random_state=42,
        n_jobs=-1
    )
    model.fit(X)
    print("Isolation Forest entrenado.")
    return model


def train_supervised(X: pd.DataFrame, y: pd.Series) -> RandomForestClassifier:
    """Fine-tuning supervisado con 10% del dataset etiquetado."""
    print("\nFine-tuning con Random Forest (supervisado, 10% datos etiquetados)...")

    # Verificar que hay ambas clases
    unique_classes = y.unique()
    if len(unique_classes) < 2:
        print(f"Advertencia: solo hay una clase en la muestra ({unique_classes}). Ajustando muestra...")
        raise ValueError("La muestra no tiene suficiente diversidad de clases.")

    X_train, X_test, y_train, y_test = train_test_split(
        X, y, test_size=0.2, random_state=42, stratify=y
    )

    model = RandomForestClassifier(
        n_estimators=100,
        random_state=42,
        n_jobs=-1,
        class_weight="balanced"
    )
    model.fit(X_train, y_train)
    y_pred = model.predict(X_test)

    print("\nResultados del modelo supervisado:")
    print(classification_report(
        y_test, y_pred,
        target_names=["Normal", "Anomalia"],
        labels=[0, 1]  # Forzar ambas clases en el reporte
    ))
    return model


def get_stratified_sample(X: pd.DataFrame, y: pd.Series, sample_ratio: float = 0.10) -> tuple:
    """
    Obtiene una muestra estratificada garantizando ambas clases.
    Estratificada significa que mantiene la misma proporcion de
    normales y anomalias que el dataset original.
    """
    min_samples_per_class = 10
    sample_size = max(int(len(X) * sample_ratio), min_samples_per_class * 2)

    # Verificar que hay suficientes ejemplos de cada clase
    class_counts = y.value_counts()
    print(f"Distribucion de clases en dataset completo: {class_counts.to_dict()}")

    if len(class_counts) < 2:
        raise ValueError("El dataset debe tener al menos dos clases (normal y anomalia).")

    # Asegurar minimo por clase
    min_class_count = class_counts.min()
    if min_class_count < min_samples_per_class:
        print(f"Advertencia: clase minoritaria tiene solo {min_class_count} ejemplos.")
        min_samples_per_class = min_class_count

    # Muestra estratificada
    _, X_sample, _, y_sample = train_test_split(
        X, y,
        test_size=min(sample_size / len(X), 0.5),
        random_state=42,
        stratify=y
    )

    print(f"Muestra para fine-tuning: {len(X_sample)} registros")
    print(f"Distribucion en muestra: {y_sample.value_counts().to_dict()}")
    return X_sample, y_sample


def main(mode: str = None):
    """Entrena los modelos con el dataset seleccionado."""
    if mode is None:
        mode = DATASET_MODE

    print(f"\n{'='*50}")
    print(f"Modo de entrenamiento: {mode.upper()}")
    print(f"{'='*50}\n")

    os.makedirs("app/model", exist_ok=True)
    os.makedirs("app/data", exist_ok=True)

    # Cargar dataset
    X, y, _ = load_dataset(mode)

    # Escalar features
    scaler = StandardScaler()
    X_scaled = pd.DataFrame(scaler.fit_transform(X), columns=X.columns)

    # Modelo no supervisado con todos los datos
    iso_model = train_unsupervised(X_scaled)

    # Muestra estratificada para fine-tuning
    X_sample, y_sample = get_stratified_sample(X_scaled, y, sample_ratio=0.10)

    # Fine-tuning supervisado
    rf_model = train_supervised(X_sample, y_sample)

    # Guardar modelos
    with open(MODEL_PATH, "wb") as f:
        pickle.dump(iso_model, f)
    with open(SUPERVISED_MODEL_PATH, "wb") as f:
        pickle.dump(rf_model, f)
    with open(SCALER_PATH, "wb") as f:
        pickle.dump(scaler, f)
    with open(DATASET_MODE_PATH, "w") as f:
        f.write(mode)

    print(f"\nModelos guardados correctamente en modo: {mode}")


if __name__ == "__main__":
    main()