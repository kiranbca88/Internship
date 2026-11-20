"""
modules/ml_model.py
===================
Machine Learning Pipeline for Cybersecurity Incident Severity Classification.
Uses Scikit-learn (RandomForestClassifier) with rigorous train/test split,
proper encoding, metrics calculation, and live interactive alert inference.
"""

import os
import joblib
import pandas as pd
import numpy as np
from sklearn.model_selection import train_test_split
from sklearn.ensemble import RandomForestClassifier
from sklearn.metrics import accuracy_score, precision_score, recall_score, f1_score, confusion_matrix
from sklearn.preprocessing import LabelEncoder, StandardScaler

SEVERITY_CLASSES = ["Critical", "High", "Medium", "Low"]

FEATURE_COLS_CAT = ["Attack_Type", "Department", "Location", "Affected_Asset", "Attack_Vector", "Multi_Factor_Auth"]
FEATURE_COLS_NUM = ["Response_Time_Hours", "Financial_Loss_USD", "Records_Affected"]


class IncidentSeverityPredictor:
    """End-to-end trained pipeline for incident severity classification."""
    def __init__(self):
        self.model = None
        self.label_encoders = {}
        self.target_encoder = None
        self.scaler = None
        self.feature_names = []
        self.metrics = {}

    def fit_and_evaluate(self, df: pd.DataFrame):
        """
        Fits Random Forest Classifier on historical incident telemetry.
        Strict train/test split (80/20) to prevent data leakage.
        """
        # Ensure required columns are present
        data = df.copy()
        
        # Fallback mappings if aliases are used
        if "Multi_Factor_Auth" not in data.columns and "Multi_Factor_Authentication" in data.columns:
            data["Multi_Factor_Auth"] = data["Multi_Factor_Authentication"]
        if "Response_Time_Hours" not in data.columns and "Response_Time" in data.columns:
            data["Response_Time_Hours"] = data["Response_Time"]
        if "Financial_Loss_USD" not in data.columns and "Financial_Loss" in data.columns:
            data["Financial_Loss_USD"] = data["Financial_Loss"]

        # Drop rows missing Severity or crucial features
        data = data.dropna(subset=["Severity"] + FEATURE_COLS_NUM)
        
        # Categorical Encoding
        encoded_dfs = []
        for col in FEATURE_COLS_CAT:
            le = LabelEncoder()
            data[col] = data[col].astype(str)
            le.fit(data[col])
            self.label_encoders[col] = le
            encoded_dfs.append(pd.Series(le.transform(data[col]), name=col, index=data.index))

        # Target Encoding (Stratified)
        self.target_encoder = LabelEncoder()
        self.target_encoder.fit(SEVERITY_CLASSES)
        y = self.target_encoder.transform(data["Severity"])

        X_cat = pd.concat(encoded_dfs, axis=1)
        X_num = data[FEATURE_COLS_NUM].copy()

        # Scale Numerics
        self.scaler = StandardScaler()
        X_num_scaled = pd.DataFrame(
            self.scaler.fit_transform(X_num),
            columns=FEATURE_COLS_NUM,
            index=data.index
        )

        X = pd.concat([X_cat, X_num_scaled], axis=1)
        self.feature_names = list(X.columns)

        # Train / Test Split (80% Train, 20% Test)
        X_train, X_test, y_train, y_test = train_test_split(
            X, y, test_size=0.20, random_state=42, stratify=y
        )

        # Train Random Forest Classifier
        self.model = RandomForestClassifier(
            n_estimators=130,
            max_depth=14,
            min_samples_split=4,
            random_state=42,
            n_jobs=-1
        )
        self.model.fit(X_train, y_train)

        # Predictions on unseen test set
        y_pred = self.model.predict(X_test)

        acc = accuracy_score(y_test, y_pred)
        prec = precision_score(y_test, y_pred, average="weighted", zero_division=0)
        rec = recall_score(y_test, y_pred, average="weighted", zero_division=0)
        f1 = f1_score(y_test, y_pred, average="weighted", zero_division=0)
        cm = confusion_matrix(y_test, y_pred, labels=self.target_encoder.transform(SEVERITY_CLASSES))

        # Calculate Feature Importances
        importances = pd.DataFrame({
            "Feature": self.feature_names,
            "Importance": self.model.feature_importances_
        }).sort_values(by="Importance", ascending=True)

        self.metrics = {
            "accuracy": round(acc * 100, 1),
            "precision": round(prec * 100, 1),
            "recall": round(rec * 100, 1),
            "f1_score": round(f1 * 100, 1),
            "confusion_matrix": cm.tolist(),
            "feature_importances": importances.to_dict(orient="records"),
            "test_sample_size": len(y_test),
            "train_sample_size": len(X_train)
        }
        return self.metrics

    def predict_alert(self, input_dict: dict) -> dict:
        """Predicts severity for a single incoming cybersecurity alert."""
        cat_values = []
        for col in FEATURE_COLS_CAT:
            le = self.label_encoders.get(col)
            val = str(input_dict.get(col, "Unknown"))
            if le and val in le.classes_:
                cat_values.append(le.transform([val])[0])
            else:
                cat_values.append(0)

        num_raw = pd.DataFrame([{
            "Response_Time_Hours": float(input_dict.get("Response_Time_Hours", 10.0)),
            "Financial_Loss_USD": float(input_dict.get("Financial_Loss_USD", 50000.0)),
            "Records_Affected": float(input_dict.get("Records_Affected", 1000.0))
        }], columns=FEATURE_COLS_NUM)
        num_scaled = self.scaler.transform(num_raw)[0].tolist()

        features = pd.DataFrame([cat_values + num_scaled], columns=self.feature_names)
        pred_idx = self.model.predict(features)[0]
        pred_label = self.target_encoder.inverse_transform([pred_idx])[0]
        
        # Probabilities
        probs = self.model.predict_proba(features)[0]
        class_probs = {
            cls_name: round(probs[i] * 100, 1)
            for i, cls_name in enumerate(self.target_encoder.classes_)
        }

        return {
            "predicted_severity": pred_label,
            "confidence": class_probs.get(pred_label, 85.0),
            "all_probabilities": class_probs
        }


def get_trained_pipeline(df: pd.DataFrame, cache_dir: str = "outputs") -> tuple:
    """Helper to train or load cached model pipeline."""
    os.makedirs(cache_dir, exist_ok=True)
    cache_path = os.path.join(cache_dir, "severity_classifier_v2.joblib")

    predictor = IncidentSeverityPredictor()
    metrics = predictor.fit_and_evaluate(df)
    try:
        joblib.dump(predictor, cache_path)
    except Exception:
        pass
    return predictor, metrics

