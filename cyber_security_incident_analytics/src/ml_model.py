"""
ml_model.py
-----------
Machine Learning module for CYBERSHIELD: Incident Severity Classifier.
Trains a Random Forest Classifier on historical incident telemetry to predict
incident severity tier with full evaluation metrics (Accuracy, Precision, Recall, F1, Confusion Matrix).
"""

import os
import joblib
import numpy as np
import pandas as pd
from sklearn.model_selection import train_test_split
from sklearn.ensemble import RandomForestClassifier
from sklearn.preprocessing import OneHotEncoder
from sklearn.compose import ColumnTransformer
from sklearn.pipeline import Pipeline
from sklearn.metrics import (
    accuracy_score,
    precision_recall_fscore_support,
    confusion_matrix,
    classification_report
)

SEVERITY_CLASSES = ["Low", "Medium", "High", "Critical"]

CATEGORICAL_FEATURES = [
    "Attack_Type",
    "Department",
    "Affected_Asset",
    "Attack_Vector",
    "Root_Cause",
    "Data_Exfiltration",
    "Multi_Factor_Authentication"
]

NUMERICAL_FEATURES = [
    "Financial_Loss",
    "Records_Affected",
    "Response_Time"
]

def build_pipeline() -> Pipeline:
    preprocessor = ColumnTransformer(
        transformers=[
            ("cat", OneHotEncoder(handle_unknown="ignore"), CATEGORICAL_FEATURES),
            ("num", "passthrough", NUMERICAL_FEATURES)
        ]
    )

    clf = RandomForestClassifier(
        n_estimators=120,
        max_depth=14,
        random_state=42,
        class_weight="balanced",
        n_jobs=-1
    )

    pipeline = Pipeline(steps=[
        ("preprocessor", preprocessor),
        ("classifier", clf)
    ])
    return pipeline

def train_severity_model(df: pd.DataFrame, model_path: str = None) -> dict:
    """
    Train and evaluate the Incident Severity Classification Model.
    """
    # Prepare features and target
    X = df[CATEGORICAL_FEATURES + NUMERICAL_FEATURES].copy()
    y = df["Severity"].copy()

    X_train, X_test, y_train, y_test = train_test_split(
        X, y, test_size=0.20, random_state=42, stratify=y
    )

    pipeline = build_pipeline()
    pipeline.fit(X_train, y_train)

    y_pred = pipeline.predict(X_test)
    y_prob = pipeline.predict_proba(X_test)

    # Metrics
    acc = accuracy_score(y_test, y_pred)
    prec, rec, f1, _ = precision_recall_fscore_support(y_test, y_pred, average="weighted", zero_division=0)
    
    # Class-wise metrics
    class_prec, class_rec, class_f1, _ = precision_recall_fscore_support(
        y_test, y_pred, labels=SEVERITY_CLASSES, average=None, zero_division=0
    )
    
    cm = confusion_matrix(y_test, y_pred, labels=SEVERITY_CLASSES)

    # Feature Importance extraction
    onehot_cols = pipeline.named_steps["preprocessor"].named_transformers_["cat"].get_feature_names_out(CATEGORICAL_FEATURES)
    all_feature_names = list(onehot_cols) + NUMERICAL_FEATURES
    raw_importances = pipeline.named_steps["classifier"].feature_importances_
    
    # Group feature importances back to high-level features
    feature_importance_map = {}
    for feat_name, imp in zip(all_feature_names, raw_importances):
        base_name = feat_name.split("__")[-1].split("_")[0] if "__" in feat_name else feat_name.split("_")[0]
        # Match with original column
        matched = None
        for orig in CATEGORICAL_FEATURES + NUMERICAL_FEATURES:
            if orig.startswith(base_name) or base_name in orig:
                matched = orig
                break
        matched = matched or base_name
        feature_importance_map[matched] = feature_importance_map.get(matched, 0.0) + imp

    fi_df = pd.DataFrame([
        {"Feature": k, "Importance": v} for k, v in feature_importance_map.items()
    ]).sort_values(by="Importance", ascending=False).reset_index(drop=True)

    results = {
        "pipeline": pipeline,
        "accuracy": round(acc * 100, 2),
        "precision": round(prec * 100, 2),
        "recall": round(rec * 100, 2),
        "f1_score": round(f1 * 100, 2),
        "confusion_matrix": cm,
        "classes": SEVERITY_CLASSES,
        "class_metrics": pd.DataFrame({
            "Severity": SEVERITY_CLASSES,
            "Precision": (class_prec * 100).round(1),
            "Recall": (class_rec * 100).round(1),
            "F1_Score": (class_f1 * 100).round(1)
        }),
        "feature_importances": fi_df,
        "test_size": len(y_test),
        "train_size": len(y_train)
    }

    if model_path:
        os.makedirs(os.path.dirname(os.path.abspath(model_path)), exist_ok=True)
        joblib.dump(pipeline, model_path)

    return results

def predict_single_incident(pipeline, sample_dict: dict) -> dict:
    """Predict severity for a user-configured incident payload."""
    df_sample = pd.DataFrame([sample_dict])
    pred_label = pipeline.predict(df_sample)[0]
    probs = pipeline.predict_proba(df_sample)[0]
    prob_dict = {cls: round(prob * 100, 1) for cls, prob in zip(pipeline.classes_, probs)}

    return {
        "predicted_severity": pred_label,
        "confidence": prob_dict[pred_label],
        "all_probabilities": prob_dict
    }

if __name__ == "__main__":
    script_dir = os.path.dirname(os.path.abspath(__file__))
    proj_root = os.path.dirname(script_dir)
    data_file = os.path.join(proj_root, "cyber_incidents_5_years.csv")
    model_save_file = os.path.join(proj_root, "outputs", "severity_classifier.joblib")

    print("[INFO] Loading 5-year dataset for ML training...")
    df = pd.read_csv(data_file)
    print(f"[INFO] Training Random Forest Severity Classifier on {len(df):,} incidents...")
    metrics = train_severity_model(df, model_save_file)
    print("\n--- MODEL PERFORMANCE EVALUATION ---")
    print(f"Accuracy : {metrics['accuracy']}%")
    print(f"Precision: {metrics['precision']}%")
    print(f"Recall   : {metrics['recall']}%")
    print(f"F1-Score : {metrics['f1_score']}%")
    print("\nConfusion Matrix:")
    print(metrics['confusion_matrix'])
    print("\nTop Predictor Features:")
    print(metrics['feature_importances'].head(6))

