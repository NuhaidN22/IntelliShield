"""
Isolation Forest - Anomaly detection
Detects unknown/zero-day attacks by finding "weird" traffic
"""

from sklearn.ensemble import IsolationForest
from sklearn.metrics import accuracy_score
import joblib
import numpy as np

class IsolationForestDetector:
    def __init__(self):
        self.model = IsolationForest(
            contamination=0.1,      # Expected % of anomalies
            random_state=42,
            n_jobs=-1
        )
    
    def train(self, X_train, y_train):
        """Train the Isolation Forest (unsupervised)"""
        print("  Training Isolation Forest...")
        # Note: Isolation Forest is unsupervised, but we still train on data
        self.model.fit(X_train)
    
    def predict(self, X):
        """Predict if traffic is an attack (1) or normal (0)"""
        # Isolation Forest returns -1 for anomalies, 1 for normal
        # We convert: -1 -> 1 (attack), 1 -> 0 (normal)
        predictions = self.model.predict(X)
        return np.where(predictions == -1, 1, 0)
    
    def predict_proba(self, X):
        """Get anomaly scores (higher = more anomalous)"""
        # Get anomaly scores (negative scores = anomalies)
        scores = self.model.score_samples(X)
        # Normalize to 0-1 range
        scores_normalized = (scores - scores.min()) / (scores.max() - scores.min())
        # Invert so high score = attack
        return 1 - scores_normalized
    
    def evaluate(self, X_test, y_test):
        """Evaluate model accuracy"""
        predictions = self.predict(X_test)
        accuracy = accuracy_score(y_test, predictions)
        return accuracy
    
    def save(self, filepath):
        """Save model to file"""
        joblib.dump(self.model, filepath)
    
    def load(self, filepath):
        """Load model from file"""
        self.model = joblib.load(filepath)