"""
QRShield AI - Model Training & Comparison
============================================
Trains Random Forest, Logistic Regression, Decision Tree, and Gradient
Boosting (used as the local stand-in for XGBoost -- see note below) on
the phishing URL feature dataset, performs 5-fold cross validation and
a small hyperparameter search for Random Forest, and saves:

  Models/model.pkl              - best model (pickled sklearn estimator)
  Models/model_metadata.json    - which model won + metrics for all 4
  Models/confusion_matrix.png
  Models/roc_curve.png
  Models/feature_importance.png

XGBOOST NOTE: this sandbox has no internet access to install the
`xgboost` package, so GradientBoostingClassifier (native to scikit-learn)
is used as a drop-in stand-in with an equivalent boosting algorithm. The
code below auto-detects and uses real XGBoost instead if it is installed
in your environment (it will be, once you `pip install -r requirements.txt`
on a machine with internet) -- no other code changes needed.
"""

import os
import sys
import json
import joblib
import numpy as np
import pandas as pd
import matplotlib
matplotlib.use("Agg")
import matplotlib.pyplot as plt

from sklearn.model_selection import train_test_split, cross_val_score, GridSearchCV
from sklearn.linear_model import LogisticRegression
from sklearn.tree import DecisionTreeClassifier
from sklearn.ensemble import RandomForestClassifier, GradientBoostingClassifier
from sklearn.metrics import (
    accuracy_score, precision_score, recall_score, f1_score,
    confusion_matrix, roc_curve, auc, classification_report
)

sys.path.append(os.path.join(os.path.dirname(__file__), "..", "Backend"))
from feature_extraction import FEATURE_ORDER  # noqa: E402

HERE = os.path.dirname(__file__)
DATASET_PATH = os.path.join(HERE, "..", "Dataset", "phishing_features.csv")
MODEL_PATH = os.path.join(HERE, "model.pkl")
META_PATH = os.path.join(HERE, "model_metadata.json")

try:
    import xgboost as xgb
    HAS_XGBOOST = True
except ImportError:
    HAS_XGBOOST = False


def load_data():
    df = pd.read_csv(DATASET_PATH)
    X = df[FEATURE_ORDER].values
    y = df["label"].values
    return X, y


def evaluate(name, model, X_test, y_test):
    y_pred = model.predict(X_test)
    y_proba = model.predict_proba(X_test)[:, 1] if hasattr(model, "predict_proba") else y_pred
    metrics = {
        "accuracy": round(accuracy_score(y_test, y_pred), 4),
        "precision": round(precision_score(y_test, y_pred), 4),
        "recall": round(recall_score(y_test, y_pred), 4),
        "f1_score": round(f1_score(y_test, y_pred), 4),
    }
    print(f"\n--- {name} ---")
    print(classification_report(y_test, y_pred, target_names=["Legitimate", "Phishing"]))
    return metrics, y_pred, y_proba


def main():
    X, y = load_data()
    X_train, X_test, y_train, y_test = train_test_split(
        X, y, test_size=0.2, random_state=42, stratify=y
    )

    models = {
        "LogisticRegression": LogisticRegression(max_iter=1000),
        "DecisionTree": DecisionTreeClassifier(max_depth=10, random_state=42),
        "RandomForest": RandomForestClassifier(n_estimators=200, random_state=42),
    }
    if HAS_XGBOOST:
        models["XGBoost"] = xgb.XGBClassifier(
            n_estimators=200, use_label_encoder=False, eval_metric="logloss", random_state=42
        )
    else:
        models["GradientBoosting(XGBoost-stand-in)"] = GradientBoostingClassifier(
            n_estimators=200, random_state=42
        )

    results = {}
    fitted = {}
    for name, model in models.items():
        model.fit(X_train, y_train)
        cv_scores = cross_val_score(model, X_train, y_train, cv=5, scoring="accuracy")
        metrics, y_pred, y_proba = evaluate(name, model, X_test, y_test)
        metrics["cv_mean_accuracy"] = round(cv_scores.mean(), 4)
        metrics["cv_std"] = round(cv_scores.std(), 4)
        results[name] = metrics
        fitted[name] = (model, y_pred, y_proba)

    # Hyperparameter tuning on the strongest candidate (Random Forest)
    print("\nRunning GridSearchCV for Random Forest hyperparameter tuning...")
    param_grid = {
        "n_estimators": [100, 200],
        "max_depth": [None, 10, 20],
        "min_samples_split": [2, 5],
    }
    grid = GridSearchCV(
        RandomForestClassifier(random_state=42), param_grid, cv=3, scoring="accuracy", n_jobs=-1
    )
    grid.fit(X_train, y_train)
    tuned_rf = grid.best_estimator_
    tuned_metrics, tuned_pred, tuned_proba = evaluate("RandomForest_Tuned", tuned_rf, X_test, y_test)
    tuned_metrics["cv_mean_accuracy"] = round(grid.best_score_, 4)
    tuned_metrics["best_params"] = grid.best_params_
    results["RandomForest_Tuned"] = tuned_metrics
    fitted["RandomForest_Tuned"] = (tuned_rf, tuned_pred, tuned_proba)

    # Pick best model by F1 score (balances precision/recall for security use case).
    # On ties, prefer RandomForest_Tuned then RandomForest (the spec's preferred
    # algorithm) -- ties are broken this way rather than arbitrarily by dict order.
    preference_order = ["RandomForest_Tuned", "RandomForest",
                         "XGBoost", "GradientBoosting(XGBoost-stand-in)",
                         "DecisionTree", "LogisticRegression"]
    best_f1 = max(v["f1_score"] for v in results.values())
    tied = [name for name, v in results.items() if v["f1_score"] == best_f1]
    best_name = next((n for n in preference_order if n in tied), tied[0])
    best_model, best_pred, best_proba = fitted[best_name]
    print(f"\n=== BEST MODEL: {best_name} (F1={results[best_name]['f1_score']}) ===")

    joblib.dump(best_model, MODEL_PATH)

    metadata = {
        "best_model": best_name,
        "feature_order": FEATURE_ORDER,
        "all_results": results,
        "note": ("Trained on a synthetically generated dataset mirroring real "
                 "phishing-URL feature distributions, since this build environment "
                 "had no internet access to fetch the live Kaggle dataset. Swap in "
                 "the real CSV via Dataset/generate_dataset.py --from-csv for production."),
        "xgboost_used": HAS_XGBOOST,
    }
    with open(META_PATH, "w") as f:
        json.dump(metadata, f, indent=2)

    # --- Confusion Matrix ---
    cm = confusion_matrix(y_test, best_pred)
    fig, ax = plt.subplots(figsize=(5, 4))
    im = ax.imshow(cm, cmap="Blues")
    ax.set_xticks([0, 1]); ax.set_yticks([0, 1])
    ax.set_xticklabels(["Legitimate", "Phishing"]); ax.set_yticklabels(["Legitimate", "Phishing"])
    ax.set_xlabel("Predicted"); ax.set_ylabel("Actual")
    ax.set_title(f"Confusion Matrix - {best_name}")
    for i in range(2):
        for j in range(2):
            ax.text(j, i, cm[i, j], ha="center", va="center", color="black", fontsize=14)
    plt.colorbar(im)
    plt.tight_layout()
    plt.savefig(os.path.join(HERE, "confusion_matrix.png"), dpi=120)
    plt.close()

    # --- ROC Curve ---
    fpr, tpr, _ = roc_curve(y_test, best_proba)
    roc_auc = auc(fpr, tpr)
    plt.figure(figsize=(5, 4))
    plt.plot(fpr, tpr, label=f"ROC curve (AUC = {roc_auc:.3f})", color="darkorange")
    plt.plot([0, 1], [0, 1], linestyle="--", color="gray")
    plt.xlabel("False Positive Rate"); plt.ylabel("True Positive Rate")
    plt.title(f"ROC Curve - {best_name}")
    plt.legend(loc="lower right")
    plt.tight_layout()
    plt.savefig(os.path.join(HERE, "roc_curve.png"), dpi=120)
    plt.close()

    # --- Feature Importance ---
    if hasattr(best_model, "feature_importances_"):
        importances = best_model.feature_importances_
        idx = np.argsort(importances)[::-1]
        plt.figure(figsize=(7, 5))
        plt.bar(range(len(FEATURE_ORDER)), importances[idx])
        plt.xticks(range(len(FEATURE_ORDER)), [FEATURE_ORDER[i] for i in idx], rotation=60, ha="right")
        plt.title(f"Feature Importance - {best_name}")
        plt.tight_layout()
        plt.savefig(os.path.join(HERE, "feature_importance.png"), dpi=120)
        plt.close()

    print(f"\nSaved model -> {MODEL_PATH}")
    print(f"Saved metadata -> {META_PATH}")
    print("Saved confusion_matrix.png, roc_curve.png, feature_importance.png")


if __name__ == "__main__":
    main()
