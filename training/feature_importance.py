# Copyright (c) 2024 - DDoS Detection Project
# Feature Importance Analysis Module
#
# Analyzes and visualizes the feature importance from the trained Random Forest model.
#
# Usage:
#   python training/feature_importance.py --model ./models/rf_ddos_model.pkl

import sys
import os
import numpy as np
import argparse
import joblib

# Add parent directory to path for imports
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from src.util_functions import feature_list

OUTPUT_FOLDER = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "output")


def analyze_feature_importance(model, max_flow_len=10):
    """
    Analyze and display feature importance from the Random Forest model.

    The features are organized as: for each packet in the flow (up to max_flow_len),
    there are len(feature_list) features. This function aggregates importance
    across all packet positions.

    Args:
        model: Trained RandomForestClassifier
        max_flow_len: Number of packets per flow sample

    Returns:
        importance_dict: Dict mapping feature names to aggregated importance scores
    """
    importances = model.feature_importances_
    feature_names = list(feature_list.keys())
    n_features = len(feature_names)

    # Total features = n_features * max_flow_len (flattened)
    total_features = len(importances)
    print(f"\nTotal features in model: {total_features}")
    print(f"Features per packet: {n_features}")
    print(f"Packets per flow: {max_flow_len}")

    # Aggregate importance across packet positions
    aggregated_importance = np.zeros(n_features)
    for i in range(total_features):
        feature_idx = i % n_features
        aggregated_importance[feature_idx] += importances[i]

    # Normalize
    aggregated_importance = aggregated_importance / aggregated_importance.sum()

    # Create sorted importance dict
    importance_dict = {}
    for name, imp in zip(feature_names, aggregated_importance):
        importance_dict[name] = imp

    # Sort by importance
    sorted_importance = sorted(importance_dict.items(), key=lambda x: x[1], reverse=True)

    print(f"\n{'='*50}")
    print(f"  Feature Importance Analysis (Random Forest)")
    print(f"{'='*50}")
    print(f"\n  {'Feature':<20} {'Importance':>12} {'Bar':>20}")
    print(f"  {'-'*52}")

    for name, imp in sorted_importance:
        bar = '#' * int(imp * 50)
        print(f"  {name:<20} {imp:>12.4f} {bar}")

    print(f"\n  Top-3 most important features:")
    for i, (name, imp) in enumerate(sorted_importance[:3], 1):
        print(f"    {i}. {name}: {imp:.4f} ({imp*100:.1f}%)")

    return dict(sorted_importance)


def save_feature_importance(importance_dict, filepath=None):
    """Save feature importance to CSV."""
    import csv

    if filepath is None:
        os.makedirs(OUTPUT_FOLDER, exist_ok=True)
        filepath = os.path.join(OUTPUT_FOLDER, "feature_importance.csv")

    with open(filepath, 'w', newline='') as f:
        writer = csv.writer(f)
        writer.writerow(['Feature', 'Importance'])
        for name, imp in importance_dict.items():
            writer.writerow([name, f'{imp:.6f}'])

    print(f"\nFeature importance saved to: {filepath}")


def main():
    parser = argparse.ArgumentParser(description='Analyze feature importance of RF DDoS model')
    parser.add_argument('--model', type=str, required=True,
                        help='Path to trained model (.pkl or .joblib)')
    parser.add_argument('--max_flow_len', type=int, default=10,
                        help='Number of packets per flow (default: 10)')
    args = parser.parse_args()

    print(f"Loading model from: {args.model}")
    model = joblib.load(args.model)

    importance_dict = analyze_feature_importance(model, args.max_flow_len)
    save_feature_importance(importance_dict)
    print("\nAnalysis complete!")


if __name__ == "__main__":
    main()
