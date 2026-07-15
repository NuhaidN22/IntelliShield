from fastapi import FastAPI, HTTPException
from pydantic import BaseModel
import numpy as np
import pandas as pd
import joblib
import os
import sys
from typing import List, Dict
import logging
from tensorflow import keras

# Setup logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

# Initialize FastAPI
app = FastAPI(title="IntelliShield ML API", version="1.0.0")

# Global variables for models
models = {}
scaler = None

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

def get_model_path():
    """Get the correct model path based on environment"""
    # Check if running in Docker
    if os.path.exists("/app/models/saved"):
        return "/app/models/saved"
    
    # Running locally
    script_dir = os.path.dirname(os.path.abspath(__file__))
    model_path = os.path.join(script_dir, "models", "saved")
    return model_path

def load_models_sync():
    """Load trained ML models - SYNCHRONOUS VERSION"""
    global models, scaler
    
    logger.info("=" * 60)
    logger.info("🔧 Loading IntelliShield ML models...")
    logger.info("=" * 60)
    
    model_path = get_model_path()
    logger.info(f"Model path: {model_path}")
    
    try:
        # Check if path exists
        if not os.path.exists(model_path):
            logger.error(f"❌ Model directory not found: {model_path}")
            logger.info(f"Creating dummy scaler and models for testing...")
            # Create dummy objects so server can start
            scaler = None
            models = {}
            return
        
        # List files in directory
        logger.info(f"📁 Files in {model_path}:")
        files = os.listdir(model_path)
        for f in files:
            logger.info(f"   - {f}")
        
        # Try to load scaler
        scaler_file = os.path.join(model_path, 'scaler.pkl')
        if os.path.exists(scaler_file):
            try:
                scaler = joblib.load(scaler_file)
                logger.info("✓ Loaded scaler")
            except Exception as e:
                logger.warning(f"⚠️  Could not load scaler: {e}")
                scaler = None
        else:
            logger.warning(f"⚠️  Scaler file not found: {scaler_file}")
        
        # Try to load models (optional - don't fail if models not available)
        model_files = {
            'xgboost': 'xgboost_model.pkl',
            'random_forest': 'random_forest_model.pkl',
            'isolation_forest': 'isolation_forest_model.pkl',
            'dbscan': 'dbscan_model.pkl'
        }
        
        for model_name, filename in model_files.items():
            filepath = os.path.join(model_path, filename)
            if os.path.exists(filepath):
                try:
                    models[model_name] = joblib.load(filepath)
                    logger.info(f"✓ Loaded {model_name}")
                except Exception as e:
                    logger.warning(f"⚠️  Could not load {model_name}: {e}")
            else:
                # Only log info for optional models (DBSCAN)
                if model_name in ['dbscan']:
                    logger.info(f"ℹ️  Optional model not found: {model_name}")
                else:
                    logger.warning(f"⚠️  {model_name} not found: {filename}")
        
        # Load LSTM separately (uses Keras/TensorFlow)
        lstm_file = os.path.join(model_path, 'lstm_model.h5')
        if os.path.exists(lstm_file):
            try:
                from models.lstm_model import LSTMDetector
                # Create wrapper that loads the Keras model
                lstm = LSTMDetector(input_dim=39)
                lstm.load(lstm_file)
                models['lstm'] = lstm
                logger.info(f"✓ Loaded lstm")
            except Exception as e:
                logger.warning(f"⚠️  Could not load lstm: {e}")
                import traceback
                traceback.print_exc()
        else:
            logger.info(f"ℹ️  Optional model not found: lstm")
        
        if models:
            logger.info(f"✅ Loaded {len(models)} models")
        else:
            logger.warning("⚠️  No models loaded - predictions will use defaults")
            
    except Exception as e:
        logger.error(f"❌ Error loading models: {e}")
        import traceback
        traceback.print_exc()

# Load models when server starts (NOT async)
load_models_sync()

def extract_features_from_packet(packet_data: Dict) -> np.ndarray:
    """
    Convert packet data to ML features (39 features matching UNSW-NB15)
    """
    features = np.zeros(39)
    
    # Flow features
    features[0] = float(packet_data.get('source_port', 0))
    features[1] = float(packet_data.get('dest_port', 0))
    features[2] = float(packet_data.get('packet_length', 0))
    features[3] = float(packet_data.get('payload_length', 0))
    features[4] = float(packet_data.get('inter_arrival_time', 0))
    
    # Protocol encoding
    protocol = str(packet_data.get('protocol', '')).upper()
    if protocol == 'TCP':
        features[5] = 6
    elif protocol == 'UDP':
        features[5] = 17
    elif protocol == 'ICMP':
        features[5] = 1
    else:
        features[5] = 0
    
    # TCP flags
    tcp_flags = str(packet_data.get('tcp_flags', ''))
    features[6] = len(tcp_flags)
    features[7] = 1 if 'S' in tcp_flags else 0  # SYN
    features[8] = 1 if 'A' in tcp_flags else 0  # ACK
    features[9] = 1 if 'F' in tcp_flags else 0  # FIN
    features[10] = 1 if 'R' in tcp_flags else 0  # RST
    features[11] = 1 if 'P' in tcp_flags else 0  # PUSH
    
    # Fill remaining features with 0
    for i in range(12, 39):
        features[i] = 0
    
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
        "scaler_loaded": scaler is not None,
        "message": "Server is running"
    }

@app.post("/predict", response_model=PredictionResponse)
async def predict(request: PredictionRequest):
    """
    Predict if network traffic is an attack
    Uses ensemble of ML models if available
    """
    
    try:
        # Extract features from request
        feature_vectors = []
        for packet in request.features:
            features = extract_features_from_packet(packet)
            feature_vectors.append(features)
        
        # Convert to DataFrame
        X = pd.DataFrame(feature_vectors)
        
        # Scale features if scaler available
        if scaler is not None:
            try:
                X_scaled = scaler.transform(X)
            except Exception as e:
                logger.warning(f"Could not scale features: {e}, using unscaled")
                X_scaled = X.values
        else:
            X_scaled = X.values
        
        # Get predictions from each model
        predictions = {}
        
        if not models:
            # No models loaded, return default prediction
            logger.warning("No models available, returning default prediction")
            ensemble_score = 0.5
            predictions = {
                'default': 0.5
            }
        else:
            # Try to get predictions from each model
            try:
                if 'xgboost' in models:
                    try:
                        xgb_proba = models['xgboost'].predict_proba(X_scaled)
                        predictions['xgboost'] = float(np.mean(xgb_proba))
                    except Exception as e:
                        logger.warning(f"XGBoost prediction error: {e}")
                        predictions['xgboost'] = 0.5
                
                if 'random_forest' in models:
                    try:
                        rf_proba = models['random_forest'].predict_proba(X_scaled)
                        predictions['random_forest'] = float(np.mean(rf_proba))
                    except Exception as e:
                        logger.warning(f"Random Forest prediction error: {e}")
                        predictions['random_forest'] = 0.5
                
                if 'isolation_forest' in models:
                    try:
                        iso_proba = models['isolation_forest'].predict_proba(X_scaled)
                        predictions['isolation_forest'] = float(np.mean(iso_proba))
                    except Exception as e:
                        logger.warning(f"Isolation Forest prediction error: {e}")
                        predictions['isolation_forest'] = 0.5
                
                if 'lstm' in models:
                    try:
                        X_lstm = X_scaled.reshape((X_scaled.shape[0], 1, X_scaled.shape[1]))
                        lstm_proba = models['lstm'].predict_proba(X_lstm)
                        predictions['lstm'] = float(np.mean(lstm_proba))
                    except Exception as e:
                        logger.warning(f"LSTM prediction error: {e}")
                        predictions['lstm'] = 0.5
                
                if 'dbscan' in models:
                    try:
                        dbscan_proba = models['dbscan'].predict_proba(X_scaled)
                        predictions['dbscan'] = float(np.mean(dbscan_proba))
                    except Exception as e:
                        logger.warning(f"DBSCAN prediction error: {e}")
                        predictions['dbscan'] = 0.5
            
            except Exception as e:
                logger.error(f"Prediction error: {e}")
                predictions = {'error': 0.5}
            
            # Calculate ensemble score
            if predictions:
                ensemble_score = float(np.mean(list(predictions.values())))
            else:
                ensemble_score = 0.5
        
        # Decision threshold: 0.45 (45%)
        is_attack = ensemble_score > 0.45
        
        return PredictionResponse(
            is_attack=is_attack,
            confidence=ensemble_score,
            predictions=predictions,
            ensemble_score=ensemble_score
        )
        
    except Exception as e:
        logger.error(f"Error in predict: {e}")
        import traceback
        traceback.print_exc()
        raise HTTPException(status_code=500, detail=f"Prediction error: {str(e)}")

@app.post("/predict/single")
async def predict_single(packet: Dict):
    """
    Predict for a single packet
    """
    request = PredictionRequest(features=[packet])
    return await predict(request)

if __name__ == "__main__":
    import uvicorn
    
    logger.info("=" * 60)
    logger.info("🛡️  Starting IntelliShield ML API Server")
    logger.info("=" * 60)
    
    # Run server
    uvicorn.run(
        app, 
        host="0.0.0.0",
        port=8000,
        log_level="info"
    )