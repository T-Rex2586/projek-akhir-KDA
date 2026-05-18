# Copyright (c) 2024 - DDoS Detection Project
# Predictor Module
#
# Loads a trained Random Forest model and performs inference
# on extracted features.
#
# Usage:
#   from controller.predictor import DDoSPredictor
#   predictor = DDoSPredictor("models/rf_ddos_model.pkl")
#   prediction, confidence = predictor.predict(features)

import numpy as np
import joblib
import time
import os
import sys

# Add parent directory to path for imports
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))


class DDoSPredictor:
    """
    DDoS attack predictor using a trained Random Forest model.

    Loads a serialized model and provides prediction methods
    with confidence scores and detection timing.
    """

    def __init__(self, model_path):
        """
        Initialize the predictor by loading the trained model.

        Args:
            model_path: Path to the trained model file (.pkl or .joblib)

        Raises:
            FileNotFoundError: If the model file does not exist
            ValueError: If the model file is not a valid format
        """
        if not os.path.exists(model_path):
            raise FileNotFoundError(f"Model file not found: {model_path}")

        if not (model_path.endswith('.pkl') or model_path.endswith('.joblib')):
            raise ValueError("Model file must be .pkl or .joblib format")

        print(f"Loading model from: {model_path}")
        self.model = joblib.load(model_path)
        self.model_path = model_path
        self.model_name = os.path.basename(model_path).split('.')[0]
        self.prediction_count = 0
        self.total_prediction_time = 0

        # Warm up the model with a dummy prediction
        self._warm_up()
        print(f"Model loaded successfully: {self.model_name}")

    def _warm_up(self):
        """Warm up the model with a dummy prediction to initialize internals."""
        try:
            n_features = self.model.n_features_in_
            dummy = np.zeros((1, n_features))
            self.model.predict(dummy)
        except Exception:
            pass  # Warm-up is optional

    def predict(self, X):
        """
        Predict whether traffic samples are DDoS attacks.

        Args:
            X: Feature array of shape (n_samples, n_features)
               Must be 2D (flattened for RF)

        Returns:
            predictions: Array of predictions (0=Normal, 1=DDoS)
            confidence: Array of confidence scores (probability of DDoS)
            detection_time: Time taken for prediction in seconds
        """
        if X.ndim == 1:
            X = X.reshape(1, -1)

        start_time = time.time()
        predictions = self.model.predict(X)
        confidence = self.model.predict_proba(X)[:, 1]
        detection_time = time.time() - start_time

        self.prediction_count += len(predictions)
        self.total_prediction_time += detection_time

        return predictions, confidence, detection_time

    def predict_single(self, features):
        """
        Predict a single sample.

        Args:
            features: 1D feature array

        Returns:
            is_ddos: Boolean indicating if DDoS is detected
            confidence: Confidence score (0.0 to 1.0)
            detection_time_ms: Detection time in milliseconds
        """
        predictions, confidence, detection_time = self.predict(features.reshape(1, -1))
        return bool(predictions[0]), float(confidence[0]), detection_time * 1000

    def get_stats(self):
        """Get prediction statistics."""
        avg_time = (self.total_prediction_time / self.prediction_count
                    if self.prediction_count > 0 else 0)
        return {
            'model_name': self.model_name,
            'total_predictions': self.prediction_count,
            'total_time': self.total_prediction_time,
            'avg_time_per_sample': avg_time,
            'avg_time_ms': avg_time * 1000,
        }

    def __repr__(self):
        return f"DDoSPredictor(model={self.model_name}, predictions={self.prediction_count})"
