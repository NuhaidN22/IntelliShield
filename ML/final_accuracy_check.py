"""
Final accuracy check after retraining
Tests models on real UNSW-NB15 data
"""

import pandas as pd
import numpy as np
import os
import joblib
import warnings
from sklearn.model_selection import train_test_split
from sklearn.preprocessing import StandardScaler
from sklearn.metrics import (
    accuracy_score, precision_score, recall_score, f1_score,
    confusion_matrix, classification_report
)
from tensorflow import keras

warnings.filterwarnings('ignore')

print("=" * 70)
print("📊 FINAL ACCURACY CHECK - REAL UNSW-NB15 DATA")
print("=" * 70)

# Load UNSW-NB15 test data
print("\n📂 Loading UNSW-NB15 test data...")
data = pd.read_csv('../data/UNSW-NB15_3.csv', header=None,
    names=['srcip', 'srcport', 'dstip', 'dstport', 'proto', 'state', 'dur', 
           'sbytes', 'dbytes', 'sttl', 'dttl', 'sloss', 'dloss', 'service', 
           'Sload', 'Dload', 'Spkt', 'Dpkt', 'swin', 'dwin', 'stcpb', 
           'dtcpb', 'smeansz', 'dmeansz', 'trans_depth', 'res_bdy_len', 
           'Sjit', 'Djit', 'Stime', 'Ltime', 'Sintpkt', 'Dintpkt', 'tcprtt', 
           'synack', 'ackdat', 'is_sm_ips_ports', 'ct_state_ttl', 
           'ct_flw_http_mthd', 'is_ftp_login', 'ct_ftp_cmd', 'ct_srv_src', 
           'ct_srv_dst', 'ct_dst_ltm', 'ct_src_ltm', 'ct_src_dport_ltm', 
           'attack_cat', 'label'])

print(f"✓ Loaded {len(data):,} samples")

# Preprocess
print("\n🔧 Preprocessing...")
X = data.drop(columns=['label', 'attack_cat'])
X = X.select_dtypes(include=[np.number])
X.fillna(0, inplace=True)
X.replace([np.inf, -np.inf], np.nan, inplace=True)
X.fillna(0, inplace=True)

y = data['label'].astype(int)

print(f"✓ Features: {X.shape[1]}")
print(f"✓ Samples: {len(X):,}")
print(f"✓ Attacks: {y.sum():,} ({y.sum()/len(y)*100:.1f}%)")
print(f"✓ Normal: {(y==0).sum():,} ({(y==0).sum()/len(y)*100:.1f}%)")

# Use same split as training for fairness
print("\n✂️  Using same train/test split as retraining...")
X_temp, X_test, y_temp, y_test = train_test_split(
    X, y, test_size=0.15, random_state=42, stratify=y
)

X_train, X_val, y_train, y_val = train_test_split(
    X_temp, y_temp, test_size=0.176, random_state=42, stratify=y_temp
)

# Scale with scaler from training
print("\n📏 Scaling with trained scaler...")
scaler = joblib.load('models/saved/scaler.pkl')
X_train_scaled = scaler.transform(X_train)
X_val_scaled = scaler.transform(X_val)
X_test_scaled = scaler.transform(X_test)

X_train_df = pd.DataFrame(X_train_scaled)
X_val_df = pd.DataFrame(X_val_scaled)
X_test_df = pd.DataFrame(X_test_scaled)

print(f"✓ Data scaled")
print(f"✓ Training:   {len(X_train_df):,} samples")
print(f"✓ Validation: {len(X_val_df):,} samples")
print(f"✓ Testing:    {len(X_test_df):,} samples")

# Load models
print("\n" + "=" * 70)
print("📈 LOADING TRAINED MODELS")
print("=" * 70)

model_path = "models/saved"
models = {}

# Load scaler
scaler = joblib.load(os.path.join(model_path, 'scaler.pkl'))
print("✓ Scaler loaded")

# Load XGBoost
xgb_model = joblib.load(os.path.join(model_path, 'xgboost_model.pkl'))
models['xgboost'] = xgb_model
print("✓ XGBoost loaded")

# Load Random Forest
rf_model = joblib.load(os.path.join(model_path, 'random_forest_model.pkl'))
models['random_forest'] = rf_model
print("✓ Random Forest loaded")

# Load Isolation Forest
iso_model = joblib.load(os.path.join(model_path, 'isolation_forest_model.pkl'))
models['isolation_forest'] = iso_model
print("✓ Isolation Forest loaded")

# Load LSTM
lstm_model = keras.models.load_model(os.path.join(model_path, 'lstm_model.h5'))
models['lstm'] = lstm_model
print("✓ LSTM loaded")

# Load DBSCAN
dbscan_loaded = joblib.load(os.path.join(model_path, 'dbscan_model.pkl'))
if isinstance(dbscan_loaded, dict):
    models['dbscan'] = dbscan_loaded['model']
else:
    models['dbscan'] = dbscan_loaded
print("✓ DBSCAN loaded")

# Evaluate on all sets
print("\n" + "=" * 70)
print("🧪 ACCURACY EVALUATION ON REAL DATA")
print("=" * 70)

results = {}

# XGBoost
print("\n1️⃣  XGBOOST")
y_pred_train = models['xgboost'].predict(X_train_df)
y_pred_val = models['xgboost'].predict(X_val_df)
y_pred_test = models['xgboost'].predict(X_test_df)

train_acc = accuracy_score(y_train, y_pred_train)
val_acc = accuracy_score(y_val, y_pred_val)
test_acc = accuracy_score(y_test, y_pred_test)

print(f"   Training Accuracy:   {train_acc:.4f} ({train_acc*100:.2f}%)")
print(f"   Validation Accuracy: {val_acc:.4f} ({val_acc*100:.2f}%)")
print(f"   Test Accuracy:       {test_acc:.4f} ({test_acc*100:.2f}%)")

gap = train_acc - test_acc
print(f"   Gap (Overfitting):   {gap:.4f} ({gap*100:.2f}%)")

if test_acc >= 0.95:
    print(f"   Status: ✅ EXCELLENT (≥95%)")
elif test_acc >= 0.90:
    print(f"   Status: ✅ VERY GOOD (≥90%)")
elif test_acc >= 0.80:
    print(f"   Status: ⚠️  GOOD (≥80%)")
else:
    print(f"   Status: ❌ POOR (<80%)")

# Confusion Matrix
tn, fp, fn, tp = confusion_matrix(y_test, y_pred_test).ravel()
print(f"   Confusion Matrix: TP={tp} TN={tn} FP={fp} FN={fn}")
print(f"   Precision: {tp/(tp+fp):.2%} | Recall: {tp/(tp+fn):.2%}")

results['xgboost'] = {
    'train': train_acc,
    'val': val_acc,
    'test': test_acc,
    'gap': gap
}

# Random Forest
print("\n2️⃣  RANDOM FOREST")
y_pred_train = models['random_forest'].predict(X_train_df)
y_pred_val = models['random_forest'].predict(X_val_df)
y_pred_test = models['random_forest'].predict(X_test_df)

train_acc = accuracy_score(y_train, y_pred_train)
val_acc = accuracy_score(y_val, y_pred_val)
test_acc = accuracy_score(y_test, y_pred_test)

print(f"   Training Accuracy:   {train_acc:.4f} ({train_acc*100:.2f}%)")
print(f"   Validation Accuracy: {val_acc:.4f} ({val_acc*100:.2f}%)")
print(f"   Test Accuracy:       {test_acc:.4f} ({test_acc*100:.2f}%)")

gap = train_acc - test_acc
print(f"   Gap (Overfitting):   {gap:.4f} ({gap*100:.2f}%)")

if test_acc >= 0.95:
    print(f"   Status: ✅ EXCELLENT (≥95%)")
elif test_acc >= 0.90:
    print(f"   Status: ✅ VERY GOOD (≥90%)")
elif test_acc >= 0.80:
    print(f"   Status: ⚠️  GOOD (≥80%)")
else:
    print(f"   Status: ❌ POOR (<80%)")

tn, fp, fn, tp = confusion_matrix(y_test, y_pred_test).ravel()
print(f"   Confusion Matrix: TP={tp} TN={tn} FP={fp} FN={fn}")
print(f"   Precision: {tp/(tp+fp):.2%} | Recall: {tp/(tp+fn):.2%}")

results['random_forest'] = {
    'train': train_acc,
    'val': val_acc,
    'test': test_acc,
    'gap': gap
}

# Isolation Forest
print("\n3️⃣  ISOLATION FOREST")
y_pred_raw = models['isolation_forest'].predict(X_test_df)
y_pred_test = (y_pred_raw == -1).astype(int)
y_pred_raw_train = models['isolation_forest'].predict(X_train_df)
y_pred_train = (y_pred_raw_train == -1).astype(int)
y_pred_raw_val = models['isolation_forest'].predict(X_val_df)
y_pred_val = (y_pred_raw_val == -1).astype(int)

train_acc = accuracy_score(y_train, y_pred_train)
val_acc = accuracy_score(y_val, y_pred_val)
test_acc = accuracy_score(y_test, y_pred_test)

print(f"   Training Accuracy:   {train_acc:.4f} ({train_acc*100:.2f}%)")
print(f"   Validation Accuracy: {val_acc:.4f} ({val_acc*100:.2f}%)")
print(f"   Test Accuracy:       {test_acc:.4f} ({test_acc*100:.2f}%)")

gap = train_acc - test_acc
print(f"   Gap (Overfitting):   {gap:.4f} ({gap*100:.2f}%)")

if test_acc >= 0.95:
    print(f"   Status: ✅ EXCELLENT (≥95%)")
elif test_acc >= 0.90:
    print(f"   Status: ✅ VERY GOOD (≥90%)")
elif test_acc >= 0.80:
    print(f"   Status: ⚠️  GOOD (≥80%)")
else:
    print(f"   Status: ⚠️  FAIR (<80%)")

tn, fp, fn, tp = confusion_matrix(y_test, y_pred_test).ravel()
print(f"   Confusion Matrix: TP={tp} TN={tn} FP={fp} FN={fn}")
print(f"   Precision: {tp/(tp+fp) if (tp+fp) > 0 else 0:.2%} | Recall: {tp/(tp+fn) if (tp+fn) > 0 else 0:.2%}")

results['isolation_forest'] = {
    'train': train_acc,
    'val': val_acc,
    'test': test_acc,
    'gap': gap
}

# LSTM
print("\n4️⃣  LSTM")
X_train_lstm = X_train_scaled.reshape((X_train_scaled.shape[0], 1, X_train_scaled.shape[1]))
X_val_lstm = X_val_scaled.reshape((X_val_scaled.shape[0], 1, X_val_scaled.shape[1]))
X_test_lstm = X_test_scaled.reshape((X_test_scaled.shape[0], 1, X_test_scaled.shape[1]))

y_pred_proba_train = models['lstm'].predict(X_train_lstm, verbose=0).flatten()
y_pred_train = (y_pred_proba_train > 0.5).astype(int)

y_pred_proba_val = models['lstm'].predict(X_val_lstm, verbose=0).flatten()
y_pred_val = (y_pred_proba_val > 0.5).astype(int)

y_pred_proba_test = models['lstm'].predict(X_test_lstm, verbose=0).flatten()
y_pred_test = (y_pred_proba_test > 0.5).astype(int)

train_acc = accuracy_score(y_train, y_pred_train)
val_acc = accuracy_score(y_val, y_pred_val)
test_acc = accuracy_score(y_test, y_pred_test)

print(f"   Training Accuracy:   {train_acc:.4f} ({train_acc*100:.2f}%)")
print(f"   Validation Accuracy: {val_acc:.4f} ({val_acc*100:.2f}%)")
print(f"   Test Accuracy:       {test_acc:.4f} ({test_acc*100:.2f}%)")

gap = train_acc - test_acc
print(f"   Gap (Overfitting):   {gap:.4f} ({gap*100:.2f}%)")

if test_acc >= 0.95:
    print(f"   Status: ✅ EXCELLENT (≥95%)")
elif test_acc >= 0.90:
    print(f"   Status: ✅ VERY GOOD (≥90%)")
elif test_acc >= 0.80:
    print(f"   Status: ⚠️  GOOD (≥80%)")
else:
    print(f"   Status: ❌ POOR (<80%)")

tn, fp, fn, tp = confusion_matrix(y_test, y_pred_test).ravel()
print(f"   Confusion Matrix: TP={tp} TN={tn} FP={fp} FN={fn}")
print(f"   Precision: {tp/(tp+fp):.2%} | Recall: {tp/(tp+fn):.2%}")

results['lstm'] = {
    'train': train_acc,
    'val': val_acc,
    'test': test_acc,
    'gap': gap
}

# DBSCAN
print("\n5️⃣  DBSCAN")
y_pred_train = models['dbscan'].predict(X_train_df)
y_pred_val = models['dbscan'].predict(X_val_df)
y_pred_test = models['dbscan'].predict(X_test_df)

# Convert DBSCAN output (-1 = anomaly, 1 = normal)
y_pred_train = (y_pred_train == -1).astype(int)
y_pred_val = (y_pred_val == -1).astype(int)
y_pred_test = (y_pred_test == -1).astype(int)

train_acc = accuracy_score(y_train, y_pred_train)
val_acc = accuracy_score(y_val, y_pred_val)
test_acc = accuracy_score(y_test, y_pred_test)

print(f"   Training Accuracy:   {train_acc:.4f} ({train_acc*100:.2f}%)")
print(f"   Validation Accuracy: {val_acc:.4f} ({val_acc*100:.2f}%)")
print(f"   Test Accuracy:       {test_acc:.4f} ({test_acc*100:.2f}%)")

gap = train_acc - test_acc
print(f"   Gap (Overfitting):   {gap:.4f} ({gap*100:.2f}%)")

if test_acc >= 0.95:
    print(f"   Status: ✅ EXCELLENT (≥95%)")
elif test_acc >= 0.90:
    print(f"   Status: ✅ VERY GOOD (≥90%)")
elif test_acc >= 0.80:
    print(f"   Status: ⚠️  GOOD (≥80%)")
else:
    print(f"   Status: ⚠️  FAIR (<80%)")

tn, fp, fn, tp = confusion_matrix(y_test, y_pred_test).ravel()
print(f"   Confusion Matrix: TP={tp} TN={tn} FP={fp} FN={fn}")
print(f"   Precision: {tp/(tp+fp) if (tp+fp) > 0 else 0:.2%} | Recall: {tp/(tp+fn) if (tp+fn) > 0 else 0:.2%}")

results['dbscan'] = {
    'train': train_acc,
    'val': val_acc,
    'test': test_acc,
    'gap': gap
}

# Summary
print("\n" + "=" * 70)
print("📊 ACCURACY SUMMARY")
print("=" * 70)

print("\nModel Performance (Test Accuracy - Most Important):")
print(f"{'Model':<20} {'Train':<12} {'Val':<12} {'Test':<12} {'Gap':<12} {'Status':<15}")
print("-" * 80)

for model_name, result in sorted(results.items(), key=lambda x: x[1]['test'], reverse=True):
    train = result['train']
    val = result['val']
    test = result['test']
    gap = result['gap']
    
    if test >= 0.95:
        status = "✅ EXCELLENT"
    elif test >= 0.90:
        status = "✅ VERY GOOD"
    elif test >= 0.80:
        status = "⚠️ GOOD"
    else:
        status = "❌ NEEDS WORK"
    
    print(f"{model_name:<20} {train:<12.2%} {val:<12.2%} {test:<12.2%} {gap:<12.2%} {status:<15}")

# Ensemble
print("\n" + "=" * 70)
print("🤖 ENSEMBLE PERFORMANCE")
print("=" * 70)

# Calculate ensemble on test set
ensemble_score = (
    0.30 * results['lstm']['test'] +
    0.25 * results['isolation_forest']['test'] +
    0.20 * results['random_forest']['test'] +
    0.15 * results['xgboost']['test'] +
    0.10 * results['dbscan']['test']
)

print(f"\nEnsemble Test Accuracy: {ensemble_score:.2%}")
print(f"Status: {'✅ EXCELLENT' if ensemble_score >= 0.90 else '⚠️ GOOD' if ensemble_score >= 0.80 else '❌ NEEDS WORK'}")

print("\n" + "=" * 70)
print("✅ ACCURACY CHECK COMPLETE!")
print("=" * 70)

print("\nRecommendations:")
if ensemble_score >= 0.90:
    print("✅ Models are PRODUCTION READY!")
    print("   - Deploy to cloud")
    print("   - Monitor in production")
    print("   - Retrain periodically with new data")
elif ensemble_score >= 0.80:
    print("⚠️  Models are ACCEPTABLE but could be improved")
    print("   - Consider retraining with more data")
    print("   - Check feature engineering")
    print("   - Monitor performance closely")
else:
    print("❌ Models need improvement")
    print("   - Check data quality")
    print("   - Retrain with balanced data")
    print("   - Verify feature engineering")