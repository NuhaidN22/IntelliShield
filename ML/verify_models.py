"""
Verify that saved models are valid
"""

import joblib
import os
from tensorflow import keras
import pickle

print("=" * 60)
print("🔍 Verifying Saved Models")
print("=" * 60)

model_path = "models/saved"

# 1. Check scaler
print("\n1️⃣  SCALER")
try:
    scaler = joblib.load(os.path.join(model_path, 'scaler.pkl'))
    print(f"   ✓ Loaded scaler")
    print(f"   ✓ Feature means: {scaler.mean_[:5]}...")
    print(f"   ✓ N features: {len(scaler.mean_)}")
except Exception as e:
    print(f"   ❌ Error: {e}")

# 2. Check XGBoost
print("\n2️⃣  XGBOOST")
try:
    xgb = joblib.load(os.path.join(model_path, 'xgboost_model.pkl'))
    print(f"   ✓ Loaded XGBoost")
    print(f"   ✓ Type: {type(xgb)}")
    print(f"   ✓ Has predict: {hasattr(xgb, 'predict')}")
except Exception as e:
    print(f"   ❌ Error: {e}")

# 3. Check Random Forest
print("\n3️⃣  RANDOM FOREST")
try:
    rf = joblib.load(os.path.join(model_path, 'random_forest_model.pkl'))
    print(f"   ✓ Loaded Random Forest")
    print(f"   ✓ Type: {type(rf)}")
    print(f"   ✓ Has predict: {hasattr(rf, 'predict')}")
except Exception as e:
    print(f"   ❌ Error: {e}")

# 4. Check Isolation Forest
print("\n4️⃣  ISOLATION FOREST")
try:
    iso = joblib.load(os.path.join(model_path, 'isolation_forest_model.pkl'))
    print(f"   ✓ Loaded Isolation Forest")
    print(f"   ✓ Type: {type(iso)}")
    print(f"   ✓ Has predict: {hasattr(iso, 'predict')}")
except Exception as e:
    print(f"   ❌ Error: {e}")

# 5. Check LSTM
print("\n5️⃣  LSTM")
try:
    # Try loading as .h5
    lstm_h5 = os.path.join(model_path, 'lstm_model.h5')
    lstm_pkl = os.path.join(model_path, 'lstm_model.pkl')
    
    if os.path.exists(lstm_h5):
        lstm = keras.models.load_model(lstm_h5)
        print(f"   ✓ Loaded LSTM from .h5")
    elif os.path.exists(lstm_pkl):
        lstm = joblib.load(lstm_pkl)
        print(f"   ✓ Loaded LSTM from .pkl")
    else:
        print(f"   ❌ LSTM not found")
    
    print(f"   ✓ Type: {type(lstm)}")
    print(f"   ✓ Has predict: {hasattr(lstm, 'predict')}")
except Exception as e:
    print(f"   ❌ Error: {e}")

# 6. Check DBSCAN
print("\n6️⃣  DBSCAN")
try:
    dbscan = joblib.load(os.path.join(model_path, 'dbscan_model.pkl'))
    print(f"   ✓ Loaded DBSCAN")
    print(f"   ✓ Type: {type(dbscan)}")
    print(f"   ✓ Is dict: {isinstance(dbscan, dict)}")
    if isinstance(dbscan, dict):
        print(f"   ⚠️  DBSCAN is a dict, not a model object!")
        print(f"   ✓ Dict keys: {list(dbscan.keys())}")
    print(f"   ✓ Has predict: {hasattr(dbscan, 'predict')}")
except Exception as e:
    print(f"   ❌ Error: {e}")

print("\n" + "=" * 60)
print("✅ Verification Complete!")
print("=" * 60)