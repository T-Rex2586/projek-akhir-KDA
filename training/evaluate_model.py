# Copyright (c) 2024 - DDoS Detection Project
# Model Evaluation Module
#
# Evaluates the trained Random Forest model with full metrics:
# - Accuracy, Precision, Recall, F1-score
# - ROC-AUC
# - Confusion Matrix
# - False Positive Rate
#
# Usage:
#   python training/evaluate_model.py --dataset_folder ./data/processed/ --model ./models/rf_ddos_model.pkl

import sys
import os
import numpy as np
import argparse
import joblib
import time
import csv

# Add parent directory to path for imports
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from training.preprocess import preprocess_dataset
from sklearn.metrics import (
    accuracy_score, precision_score, recall_score, f1_score,
    roc_auc_score, confusion_matrix, classification_report,
    roc_curve
)

LOGS_FOLDER = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "logs")


def evaluate_model(model, X_test, Y_test, model_name="RF-DDoS"):
    """
    Comprehensive evaluation of the trained model.

    Metrics (as per CLAUDE.md Phase 5):
    - Accuracy
    - Precision
    - Recall
    - F1-score
    - ROC-AUC
    - Confusion Matrix
    - False Positive Rate

    Args:
        model: Trained sklearn model
        X_test: Test features
        Y_test: Test labels
        model_name: Name for logging

    Returns:
        results: Dict with all metrics
    """
    print(f"\n{'='*60}")
    print(f"  Model Evaluation: {model_name}")
    print(f"{'='*60}")

    # Prediction timing
    start_time = time.time()
    Y_pred = model.predict(X_test)
    prediction_time = time.time() - start_time
    detection_time_ms = (prediction_time / len(Y_test)) * 1000  # per-sample in ms

    # Probabilities for ROC-AUC
    Y_prob = model.predict_proba(X_test)[:, 1]

    # Core metrics
    accuracy = accuracy_score(Y_test, Y_pred)
    precision = precision_score(Y_test, Y_pred)
    recall = recall_score(Y_test, Y_pred)
    f1 = f1_score(Y_test, Y_pred)
    roc_auc = roc_auc_score(Y_test, Y_prob)

    # Confusion Matrix
    tn, fp, fn, tp = confusion_matrix(Y_test, Y_pred, labels=[0, 1]).ravel()
    fpr = fp / (fp + tn) if (fp + tn) > 0 else 0
    fnr = fn / (fn + tp) if (fn + tp) > 0 else 0
    tpr = tp / (tp + fn) if (tp + fn) > 0 else 0
    tnr = tn / (tn + fp) if (tn + fp) > 0 else 0

    results = {
        'model_name': model_name,
        'accuracy': accuracy,
        'precision': precision,
        'recall': recall,
        'f1_score': f1,
        'roc_auc': roc_auc,
        'tp': int(tp),
        'tn': int(tn),
        'fp': int(fp),
        'fn': int(fn),
        'tpr': tpr,
        'fpr': fpr,
        'tnr': tnr,
        'fnr': fnr,
        'total_samples': len(Y_test),
        'total_prediction_time': prediction_time,
        'detection_time_ms': detection_time_ms,
        'ddos_rate': sum(Y_pred) / len(Y_pred),
    }

    # Print results
    print(f"\n  Samples:           {len(Y_test)}")
    print(f"  Detection Time:    {detection_time_ms:.2f} ms/sample")
    print(f"  Total Pred Time:   {prediction_time:.4f} s")
    print(f"\n  --- Classification Metrics ---")
    print(f"  Accuracy:          {accuracy:.4f}  ({accuracy*100:.2f}%)")
    print(f"  Precision:         {precision:.4f}")
    print(f"  Recall (TPR):      {recall:.4f}")
    print(f"  F1-Score:          {f1:.4f}")
    print(f"  ROC-AUC:           {roc_auc:.4f}")
    print(f"\n  --- Confusion Matrix ---")
    print(f"                     Predicted")
    print(f"                  Normal  DDoS")
    print(f"  Actual Normal   {tn:6d}  {fp:6d}")
    print(f"  Actual DDoS     {fn:6d}  {tp:6d}")
    print(f"\n  --- Error Rates ---")
    print(f"  TPR (Sensitivity): {tpr:.4f}")
    print(f"  TNR (Specificity): {tnr:.4f}")
    print(f"  FPR:               {fpr:.4f}")
    print(f"  FNR:               {fnr:.4f}")

    # Comparison with paper results
    print(f"\n  --- Comparison with Paper Results ---")
    print(f"  {'Metric':<20} {'Our Model':>12} {'Paper':>12}")
    print(f"  {'Accuracy':<20} {accuracy*100:>11.2f}% {'98.38%':>12}")
    print(f"  {'Detection Time':<20} {detection_time_ms:>10.2f}ms {'36ms':>12}")

    print(f"\n{'='*60}")

    # Full classification report
    print("\n  Detailed Classification Report:")
    print(classification_report(Y_test, Y_pred, target_names=['Normal (0)', 'DDoS (1)']))

    return results


def save_evaluation_log(results, log_path=None):
    """Save evaluation results to CSV log file."""
    if log_path is None:
        os.makedirs(LOGS_FOLDER, exist_ok=True)
        log_path = os.path.join(LOGS_FOLDER, "evaluation_log.csv")

    fieldnames = [
        'model_name', 'accuracy', 'precision', 'recall', 'f1_score',
        'roc_auc', 'tp', 'tn', 'fp', 'fn', 'tpr', 'fpr', 'tnr', 'fnr',
        'total_samples', 'total_prediction_time', 'detection_time_ms', 'ddos_rate'
    ]

    file_exists = os.path.exists(log_path)
    with open(log_path, 'a', newline='') as f:
        writer = csv.DictWriter(f, fieldnames=fieldnames)
        if not file_exists:
            writer.writeheader()
        writer.writerow(results)

    print(f"Evaluation log saved to: {log_path}")


def main():
    parser = argparse.ArgumentParser(description='Evaluate Random Forest DDoS detection model')
    parser.add_argument('--dataset_folder', type=str, required=True,
                        help='Folder containing HDF5 test dataset files')
    parser.add_argument('--model', type=str, required=True,
                        help='Path to trained model (.pkl or .joblib)')
    args = parser.parse_args()

    # Load model
    print(f"Loading model from: {args.model}")
    model = joblib.load(args.model)

    # Preprocess data
    X_train, X_val, X_test, Y_train, Y_val, Y_test = preprocess_dataset(args.dataset_folder)

    # Evaluate on test set
    if X_test is not None:
        results = evaluate_model(model, X_test, Y_test)
    elif X_val is not None:
        print("No test set found, evaluating on validation set")
        results = evaluate_model(model, X_val, Y_val)
    else:
        print("No test or validation set found!")
        return

    save_evaluation_log(results)
    print("\nEvaluation complete!")


if __name__ == "__main__":
    main()
