"""
LSTM Neural Network - Time series patterns
Detects attacks that evolve over time (slow attacks)
"""

from xml.parsers.expat import model
import numpy as np
from tensorflow import keras
from tensorflow.keras.models import Sequential
from tensorflow.keras.layers import LSTM, Dense, Dropout
from sklearn.metrics import accuracy_score
import joblib

class LSTMDetector:
    def __init__(self, input_dim):
        self.input_dim = input_dim
        self.model = self._build_model()
    

    def _build_model(self):
        model = Sequential([
            # LSTM expects (batch_size, timesteps, features)
            LSTM(64, input_shape=(1, self.input_dim), return_sequences=True),
            Dropout(0.2),
            LSTM(32, return_sequences=False),
            Dropout(0.2),
            Dense(16, activation='relu'),
            Dense(1, activation='sigmoid')
        ])

        model.compile(
            optimizer='adam',
            loss='binary_crossentropy',
            metrics=['accuracy']
        )

        return model


    def train(self, X_train, y_train, epochs=10, batch_size=128):
        """Train the LSTM model"""
        print(f"  Training LSTM for {epochs} epochs...")
        
        # Ensure X_train is 3D (samples, timesteps, features)
        if len(X_train.shape) == 2:
            X_train = X_train.reshape((X_train.shape[0], 1, X_train.shape[1]))
        
        # Train with validation split
        history = self.model.fit(
            X_train, y_train,
            epochs=epochs,
            batch_size=batch_size,
            validation_split=0.1,
            verbose=0  # Silent training
        )
        
        print(f"  Final training accuracy: {history.history['accuracy'][-1]:.4f}")
    
    def predict(self, X):
        """Predict if traffic is an attack (1) or normal (0)"""
        # Ensure X is 3D (samples, timesteps, features)
        if len(X.shape) == 2:
            X = X.reshape((X.shape[0], 1, X.shape[1]))
        predictions = self.model.predict(X, verbose=0)
        return (predictions > 0.5).astype(int).flatten()
    
    def predict_proba(self, X):
        """Get probability scores"""
        # Ensure X is 3D (samples, timesteps, features)
        if len(X.shape) == 2:
            X = X.reshape((X.shape[0], 1, X.shape[1]))
        return self.model.predict(X, verbose=0).flatten()
    
    def evaluate(self, X_test, y_test):
        """Evaluate model accuracy"""
        # Ensure X_test is 3D (samples, timesteps, features)
        if len(X_test.shape) == 2:
            X_test = X_test.reshape((X_test.shape[0], 1, X_test.shape[1]))
        predictions = self.predict(X_test)
        accuracy = accuracy_score(y_test, predictions)
        return accuracy
    
    def save(self, filepath):
        """Save model to file"""
        # Save as Keras model
        self.model.save(filepath.replace('.pkl', '.h5'))
    
    def load(self, filepath):
        """Load model from file"""
        self.model = keras.models.load_model(filepath.replace('.pkl', '.h5'))