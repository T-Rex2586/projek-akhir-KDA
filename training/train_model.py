# Copyright (c) 2024 - DDoS Detection Project
# Model Training Module
#
# Trains a Random Forest Classifier with GridSearchCV
# and saves the best model as a .pkl/.joblib file.
#
# Usage:
#   python training/train_model.py --dataset_folder ./data/processed/ --cv 5

import sys
import os
import numpy as np
import argparse
import joblib
import time

# Add parent directory to path for imports
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from training.preprocess import preprocess_dataset
from sklearn.ensemble import RandomForestClassifier
from sklearn.model_selection import GridSearchCV
from sklearn.metrics import f1_score, accuracy_score, classification_report
from src.util_functions import SEED

MODELS_FOLDER = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "models")

# Hyperparameters as specified in CLAUDE.md Phase 4
HYPERPARAMETERS = {
    "n_estimators": [50, 100, 200],
    "max_depth": [None, 10, 20],
    "min_samples_split": [2, 5, 10],
    "min_samples_leaf": [1, 2, 4]
}


def train_random_forest(X_train, Y_train, X_val=None, Y_val=None, cv=5, hyperparameters=None):
    """
    Train a Random Forest model using GridSearchCV.

    Args:
        X_train: Training features (2D array)
        Y_train: Training labels (1D array)
        X_val: Validation features (optional)
        Y_val: Validation labels (optional)
        cv: Number of cross-validation folds
        hyperparameters: Dict of hyperparameters for GridSearchCV

    Returns:
        best_model: Trained RandomForestClassifier with best hyperparameters
        best_params: Best hyperparameters found
        results: Dict with training results
    """
    if hyperparameters is None:
        hyperparameters = HYPERPARAMETERS

    print("\n=== Training Random Forest ===")
    print(f"Training samples: {X_train.shape[0]}")
    print(f"Features: {X_train.shape[1]}")
    print(f"Cross-validation folds: {cv}")
    print(f"Hyperparameter grid: {hyperparameters}")

    # Initialize Random Forest as per CLAUDE.md
    rf_classifier = RandomForestClassifier(
        random_state=SEED,
        n_jobs=-1,
        class_weight='balanced'
    )

    # GridSearchCV with cross-validation
    start_time = time.time()
    grid_search = GridSearchCV(
        rf_classifier,
        hyperparameters,
        cv=cv,
        refit=True,
        return_train_score=True,
        scoring='f1',
        verbose=1,
        n_jobs=-1
    )
    grid_search.fit(X_train, Y_train)
    training_time = time.time() - start_time

    best_model = grid_search.best_estimator_
    best_params = grid_search.best_params_

    print(f"\nTraining completed in {training_time:.2f} seconds")
    print(f"Best parameters: {best_params}")
    print(f"Best CV F1 score: {grid_search.best_score_:.4f}")

    results = {
        'training_time': training_time,
        'best_params': best_params,
        'best_cv_score': grid_search.best_score_,
    }

    # Evaluate on validation set if provided
    if X_val is not None and Y_val is not None:
        Y_pred_val = best_model.predict(X_val)
        val_accuracy = accuracy_score(Y_val, Y_pred_val)
        val_f1 = f1_score(Y_val, Y_pred_val)
        results['val_accuracy'] = val_accuracy
        results['val_f1'] = val_f1

        print(f"\n--- Validation Results ---")
        print(f"Accuracy: {val_accuracy:.4f}")
        print(f"F1 Score: {val_f1:.4f}")
        print("\nClassification Report:")
        print(classification_report(Y_val, Y_pred_val, target_names=['Normal', 'DDoS']))

    return best_model, best_params, results


def save_model(model, filepath):
    """Save trained model using joblib."""
    os.makedirs(os.path.dirname(filepath), exist_ok=True)
    joblib.dump(model, filepath)
    print(f"Model saved to: {filepath}")


def main():
    parser = argparse.ArgumentParser(description='Train Random Forest for DDoS detection')
    parser.add_argument('--dataset_folder', type=str, required=True,
                        help='Folder containing HDF5 dataset files')
    parser.add_argument('--cv', type=int, default=5,
                        help='Number of cross-validation folds (default: 5)')
    parser.add_argument('--output', type=str, default=None,
                        help='Output path for the trained model')
    args = parser.parse_args()

    # Preprocess data
    X_train, X_val, X_test, Y_train, Y_val, Y_test = preprocess_dataset(args.dataset_folder)

    # Train model
    best_model, best_params, results = train_random_forest(
        X_train, Y_train, X_val, Y_val, cv=args.cv
    )

    # Save model
    if args.output:
        model_path = args.output
    else:
        os.makedirs(MODELS_FOLDER, exist_ok=True)
        model_path = os.path.join(MODELS_FOLDER, "rf_ddos_model.pkl")

    save_model(best_model, model_path)
    print("\nTraining complete!")


if __name__ == "__main__":
    main()
