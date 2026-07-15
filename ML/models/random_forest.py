"""
Random Forest Model - General classification
Handles noisy data well, good all-around detector
"""

from sklearn.ensemble import RandomForestClassifier
from sklearn.metrics import accuracy_score
import joblib

class RandomForestDetector:
    def __init__(self):
        self.model = RandomForestClassifier(
            n_estimators=100,       # Number of trees
            max_depth=10,           # Tree depth
            min_samples_split=5,    # Min samples to split node
            random_state=42,
            n_jobs=-1               # Use all CPU cores
        )
    
    def train(self, X_train, y_train):
        """Train the Random Forest model"""
        print("  Training Random Forest...")
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