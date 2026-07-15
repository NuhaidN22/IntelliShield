import numpy as np
from models.lstm_model import LSTMDetector

# Create detector and load model
lstm = LSTMDetector(input_dim=39)
lstm.load('models/saved/lstm_model.h5')

# Test prediction with dummy data
X_test = np.random.randn(10, 39)
predictions = lstm.predict(X_test)
probs = lstm.predict_proba(X_test)

print(f"✓ LSTM model loaded successfully!")
print(f"✓ Sample predictions shape: {predictions.shape}")
print(f"✓ Sample probabilities shape: {probs.shape}")
print(f"✓ Predictions: {predictions[:3]}")
