"""
XGBoost Model - Best for known attack patterns
Fast and accurate for DDoS, Brute Force, Port Scans
"""

import xgboost as xgb
from sklearn.metrics import accuracy_score
import joblib

class XGBoostDetector:
    def __init__(self):
        self.model = xgb.XGBClassifier(
            n_estimators=100,       # Number of trees
            max_depth=6,            # Tree depth
            learning_rate=0.1,      # Learning rate
            objective='binary:logistic',
            random_state=42,
            n_jobs=-1               # Use all CPU cores
        )
    
    def train(self, X_train, y_train):
        """Train the XGBoost model"""
        print("  Training XGBoost...")
        self.model.fit(X_train, y_train)
    
    def predict(self, X):
        """Predict if traffic is an attack (1) or normal (0)"""
        return self.model.predict(X)
    
    def predict_proba(self, X):
        """Get probability scores"""
        return self.model.predict_proba(X)[:, 1]  # Probability of attack
    
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