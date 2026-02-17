"""
IntelliShield ML API Server
Receives network features from Go, runs ML predictions, returns results
"""

from fastapi import FastAPI, HTTPException
from pydantic import BaseModel
import numpy as np
import pandas as pd
import joblib
import os
import sys
from typing import List, Dict

# Add models directory to path
sys.path.append(os.path.join(os.path.dirname(__file__), '..', 'ML'))

from models.xgboost_model import XGBoostDetector
from models.random_forest import RandomForestDetector
from models.isolation_forest import IsolationForestDetector
from models.lstm_model import LSTMDetector
from models.dbscan_cluster import DBSCANDetector

# Initialize FastAPI
app = FastAPI(title="IntelliShield ML API", version="1.0.0")

# Global variables for models
models = {}
scaler = None
feature_names = None

class PacketFeatures(BaseModel):
    """Single packet feature set"""
    source_ip: str
    dest_ip: str
    source_port: int
    dest_port: int
    protocol: str
    packet_length: int
    payload_length: int
    inter_arrival_time: float
    tcp_flags: str = ""
    
class PredictionRequest(BaseModel):
    """Batch prediction request"""
    features: List[Dict]

class PredictionResponse(BaseModel):
    """Prediction result"""
    is_attack: bool
    confidence: float
    predictions: Dict[str, float]
    ensemble_score: float

@app.on_event("startup")
async def load_models():
    """Load trained ML models on startup"""
    global models, scaler, feature_names
    
    print("🔧 Loading IntelliShield ML models...")
    
    model_path = os.path.join(os.path.dirname(__file__), '..', 'ML', 'models', 'saved')
    
    try:
        # Load scaler
        scaler_file = os.path.join(model_path, 'scaler.pkl')
        scaler = joblib.load(scaler_file)
        print("  ✓ Loaded scaler")
        
        # Load XGBoost
        xgb = XGBoostDetector()
        xgb.load(os.path.join(model_path, 'xgboost_model.pkl'))
        models['xgboost'] = xgb
        print("  ✓ Loaded XGBoost")
        
        # Load Random Forest
        rf = RandomForestDetector()
        rf.load(os.path.join(model_path, 'random_forest_model.pkl'))
        models['random_forest'] = rf
        print("  ✓ Loaded Random Forest")
        
        # Load Isolation Forest
        iso = IsolationForestDetector()
        iso.load(os.path.join(model_path, 'isolation_forest_model.pkl'))
        models['isolation_forest'] = iso
        print("  ✓ Loaded Isolation Forest")
        
        # Load LSTM
        lstm = LSTMDetector(input_dim=39)  # UNSW-NB15 has 39 features
        lstm.load(os.path.join(model_path, 'lstm_model.pkl'))
        models['lstm'] = lstm
        print("  ✓ Loaded LSTM")
        
        # Load DBSCAN (optional)
        try:
            dbscan = DBSCANDetector()
            dbscan.load(os.path.join(model_path, 'dbscan_model.pkl'))
            models['dbscan'] = dbscan
            print("  ✓ Loaded DBSCAN")
        except:
            print("  ⚠️  DBSCAN not loaded (optional)")
        
        print("✅ All models loaded successfully!")
        
    except Exception as e:
        print(f"❌ Error loading models: {e}")
        raise

def extract_features_from_packet(packet_data: Dict) -> np.ndarray:
    """
    Convert packet data to ML features (39 features matching UNSW-NB15)
    This is a simplified version - you'll need to match your actual features
    """
    
    # For now, create a basic feature vector
    # TODO: Map your Go packet features to the 39 UNSW-NB15 features
    features = np.zeros(39)
    
    # Example mappings (you'll need to customize these):
    features[0] = packet_data.get('source_port', 0)
    features[1] = packet_data.get('dest_port', 0)
    features[2] = packet_data.get('packet_length', 0)
    features[3] = packet_data.get('payload_length', 0)
    features[4] = packet_data.get('inter_arrival_time', 0)
    
    # Protocol encoding
    protocol = packet_data.get('protocol', '').upper()
    if protocol == 'TCP':
        features[5] = 6
    elif protocol == 'UDP':
        features[5] = 17
    elif protocol == 'ICMP':
        features[5] = 1
    
    # Fill remaining features with defaults for now
    # In production, you'd extract all 39 features properly
    
    return features

@app.get("/")
async def root():
    """Health check endpoint"""
    return {
        "service": "IntelliShield ML API",
        "status": "running",
        "models_loaded": len(models),
        "version": "1.0.0"
    }

@app.get("/health")
async def health_check():
    """Detailed health check"""
    return {
        "status": "healthy",
        "models": list(models.keys()),
        "scaler_loaded": scaler is not None
    }

@app.post("/predict", response_model=PredictionResponse)
async def predict(request: PredictionRequest):
    """
    Predict if network traffic is an attack
    Uses ensemble of 4-5 ML models
    """
    
    if not models:
        raise HTTPException(status_code=503, detail="Models not loaded")
    
    try:
        # Extract features from request
        feature_vectors = []
        for packet in request.features:
            features = extract_features_from_packet(packet)
            feature_vectors.append(features)
        
        # Convert to DataFrame
        X = pd.DataFrame(feature_vectors)
        
        # Scale features
        X_scaled = scaler.transform(X)
        
        # Get predictions from each model
        predictions = {}
        
        # XGBoost
        xgb_proba = models['xgboost'].predict_proba(X_scaled)
        predictions['xgboost'] = float(xgb_proba.mean())
        
        # Random Forest
        rf_proba = models['random_forest'].predict_proba(X_scaled)
        predictions['random_forest'] = float(rf_proba.mean())
        
        # Isolation Forest
        iso_proba = models['isolation_forest'].predict_proba(X_scaled)
        predictions['isolation_forest'] = float(iso_proba.mean())
        
        # LSTM (needs reshaping)
        X_lstm = X_scaled.reshape((X_scaled.shape[0], 1, X_scaled.shape[1]))
        lstm_proba = models['lstm'].predict_proba(X_lstm)
        predictions['lstm'] = float(lstm_proba.mean())
        
        # DBSCAN (if available)
        if 'dbscan' in models:
            dbscan_proba = models['dbscan'].predict_proba(X_scaled)
            predictions['dbscan'] = float(dbscan_proba.mean())
        
        # Ensemble voting (weighted average)
        # Weights based on model reliability and balance
        if 'dbscan' in predictions:
            # Include DBSCAN in weights
            weights = {
                'lstm': 0.30,              # Best for sequential patterns
                'isolation_forest': 0.25, # Good for anomaly detection
                'random_forest': 0.20,    # Balanced classifier
                'dbscan': 0.15,            # Clustering-based detection
                'xgboost': 0.10            # Lower weight due to lower confidence
            }
        else:
            weights = {
                'lstm': 0.35,              # Best for sequential patterns
                'isolation_forest': 0.30, # Good for anomaly detection
                'random_forest': 0.25,    # Balanced classifier
                'xgboost': 0.10            # Lower weight due to lower confidence
            }
        
        ensemble_score = sum(predictions.get(model, 0) * weight 
                           for model, weight in weights.items())
        
        # Decision threshold: 0.4 (40%) for better IDS sensitivity
        # IDS should err on the side of detection vs false negatives
        is_attack = ensemble_score > 0.40
        
        return PredictionResponse(
            is_attack=is_attack,
            confidence=ensemble_score,
            predictions=predictions,
            ensemble_score=ensemble_score
        )
        
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Prediction error: {str(e)}")

@app.post("/predict/single")
async def predict_single(packet: Dict):
    """
    Predict for a single packet (simplified endpoint)
    """
    request = PredictionRequest(features=[packet])
    return await predict(request)

if __name__ == "__main__":
    import uvicorn
    
    print("=" * 60)
    print("🛡️  Starting IntelliShield ML API Server")
    print("=" * 60)
    
    # Run server
    uvicorn.run(
        app, 
        host="0.0.0.0",  # Listen on all interfaces
        port=8000,        # API port
        log_level="info"
    )