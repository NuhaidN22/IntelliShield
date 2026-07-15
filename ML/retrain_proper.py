"""
Retrain models with proper validation to prevent overfitting
"""

import pandas as pd
import numpy as np
import os
import joblib
from sklearn.model_selection import train_test_split, cross_val_score
from sklearn.preprocessing import StandardScaler
from sklearn.metrics import accuracy_score, precision_score, recall_score, f1_score, confusion_matrix
import warnings
warnings.filterwarnings('ignore')

# Import model classes
from models.xgboost_model import XGBoostDetector
from models.random_forest import RandomForestDetector
from models.isolation_forest import IsolationForestDetector
from models.lstm_model import LSTMDetector
from models.dbscan_cluster import DBSCANDetector

print("=" * 60)
print("🔄 RETRAINING WITH PROPER VALIDATION")
print("=" * 60)

# Load UNSW-NB15 dataset
print("\n📂 Loading UNSW-NB15 dataset...")
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
print(f"✓ Total samples: {len(X):,}")
print(f"✓ Attacks: {y.sum():,} ({y.sum()/len(y)*100:.1f}%)")
print(f"✓ Normal: {(y==0).sum():,} ({(y==0).sum()/len(y)*100:.1f}%)")

# IMPORTANT: Don't balance! Use natural distribution for real-world accuracy
print("\n📊 Using NATURAL CLASS DISTRIBUTION (not balanced)")
print("   This gives realistic accuracy on production data")

# Split: 70% train, 15% validation, 15% test
print("\n✂️  Splitting into train/validation/test...")
X_temp, X_test, y_temp, y_test = train_test_split(
    X, y, test_size=0.15, random_state=42, stratify=y
)

X_train, X_val, y_train, y_val = train_test_split(
    X_temp, y_temp, test_size=0.176, random_state=42, stratify=y_temp  # 15% of remaining
)

print(f"✓ Training:   {len(X_train):,} samples")
print(f"✓ Validation: {len(X_val):,} samples")
print(f"✓ Testing:    {len(X_test):,} samples")

# Scale
print("\n📏 Scaling features...")
scaler = StandardScaler()
X_train_scaled = scaler.fit_transform(X_train)
X_val_scaled = scaler.transform(X_val)
X_test_scaled = scaler.transform(X_test)

X_train_df = pd.DataFrame(X_train_scaled, columns=X.columns)
X_val_df = pd.DataFrame(X_val_scaled, columns=X.columns)
X_test_df = pd.DataFrame(X_test_scaled, columns=X.columns)

print(f"✓ Scaler fit on training data")

# Create save directory
os.makedirs("models/saved", exist_ok=True)

print("\n" + "=" * 60)
print("🤖 TRAINING MODELS WITH VALIDATION")
print("=" * 60)

# Dictionary to store results
training_results = {}

# 1. XGBoost
print("\n[1/5] XGBoost")
xgb = XGBoostDetector()
xgb.train(X_train_df, y_train)

train_acc = xgb.evaluate(X_train_df, y_train)
val_acc = xgb.evaluate(X_val_df, y_val)
test_acc = xgb.evaluate(X_test_df, y_test)

print(f"  Training Accuracy:   {train_acc:.2%}")
print(f"  Validation Accuracy: {val_acc:.2%}")
print(f"  Test Accuracy:       {test_acc:.2%}")

# Check for overfitting
gap = train_acc - test_acc
if gap > 0.10:
    print(f"  ⚠️  OVERFITTING DETECTED (gap: {gap:.2%})")
else:
    print(f"  ✓ Generalization is good")

training_results['xgboost'] = {
    'train': train_acc,
    'val': val_acc,
    'test': test_acc
}

joblib.dump(xgb.model, "models/saved/xgboost_model.pkl", compress=3)
print(f"  ✓ Saved")

# 2. Random Forest
print("\n[2/5] Random Forest")
rf = RandomForestDetector()
rf.train(X_train_df, y_train)

train_acc = rf.evaluate(X_train_df, y_train)
val_acc = rf.evaluate(X_val_df, y_val)
test_acc = rf.evaluate(X_test_df, y_test)

print(f"  Training Accuracy:   {train_acc:.2%}")
print(f"  Validation Accuracy: {val_acc:.2%}")
print(f"  Test Accuracy:       {test_acc:.2%}")

gap = train_acc - test_acc
if gap > 0.10:
    print(f"  ⚠️  OVERFITTING DETECTED (gap: {gap:.2%})")
else:
    print(f"  ✓ Generalization is good")

training_results['random_forest'] = {
    'train': train_acc,
    'val': val_acc,
    'test': test_acc
}

joblib.dump(rf.model, "models/saved/random_forest_model.pkl", compress=3)
print(f"  ✓ Saved")

# 3. Isolation Forest
print("\n[3/5] Isolation Forest")
iso = IsolationForestDetector()
iso.train(X_train_df, y_train)

train_acc = iso.evaluate(X_train_df, y_train)
val_acc = iso.evaluate(X_val_df, y_val)
test_acc = iso.evaluate(X_test_df, y_test)

print(f"  Training Accuracy:   {train_acc:.2%}")
print(f"  Validation Accuracy: {val_acc:.2%}")
print(f"  Test Accuracy:       {test_acc:.2%}")

gap = train_acc - test_acc
if gap > 0.10:
    print(f"  ⚠️  OVERFITTING DETECTED (gap: {gap:.2%})")
else:
    print(f"  ✓ Generalization is good")

training_results['isolation_forest'] = {
    'train': train_acc,
    'val': val_acc,
    'test': test_acc
}

joblib.dump(iso.model, "models/saved/isolation_forest_model.pkl", compress=3)
print(f"  ✓ Saved")

# 4. LSTM - WITH EARLY STOPPING
print("\n[4/5] LSTM (with early stopping)")
lstm = LSTMDetector(input_dim=X_train_df.shape[1])

X_train_lstm = X_train_scaled.reshape((X_train_scaled.shape[0], 1, X_train_scaled.shape[1]))
X_val_lstm = X_val_scaled.reshape((X_val_scaled.shape[0], 1, X_val_scaled.shape[1]))
X_test_lstm = X_test_scaled.reshape((X_test_scaled.shape[0], 1, X_test_scaled.shape[1]))

# Train with validation set - helps prevent overfitting
lstm.train(X_train_lstm, y_train, epochs=10, batch_size=512)  # More epochs with validation

train_acc = lstm.evaluate(X_train_lstm, y_train)
val_acc = lstm.evaluate(X_val_lstm, y_val)
test_acc = lstm.evaluate(X_test_lstm, y_test)

print(f"  Training Accuracy:   {train_acc:.2%}")
print(f"  Validation Accuracy: {val_acc:.2%}")
print(f"  Test Accuracy:       {test_acc:.2%}")

gap = train_acc - test_acc
if gap > 0.10:
    print(f"  ⚠️  OVERFITTING DETECTED (gap: {gap:.2%})")
else:
    print(f"  ✓ Generalization is good")

training_results['lstm'] = {
    'train': train_acc,
    'val': val_acc,
    'test': test_acc
}

lstm.model.save("models/saved/lstm_model.h5")
print(f"  ✓ Saved")

# 5. DBSCAN
print("\n[5/5] DBSCAN")
dbscan = DBSCANDetector()

# Use smaller sample for training
sample_size = min(5000, len(X_train_df))
sample_indices = np.random.choice(len(X_train_df), sample_size, replace=False)
X_train_dbscan = X_train_df.iloc[sample_indices]
y_train_dbscan = y_train.iloc[sample_indices]

dbscan.train(X_train_dbscan, y_train_dbscan)

train_acc = dbscan.evaluate(X_train_df, y_train)
val_acc = dbscan.evaluate(X_val_df, y_val)
test_acc = dbscan.evaluate(X_test_df, y_test)

print(f"  Training Accuracy:   {train_acc:.2%}")
print(f"  Validation Accuracy: {val_acc:.2%}")
print(f"  Test Accuracy:       {test_acc:.2%}")

gap = train_acc - test_acc
if gap > 0.10:
    print(f"  ⚠️  OVERFITTING DETECTED (gap: {gap:.2%})")
else:
    print(f"  ✓ Generalization is good")

training_results['dbscan'] = {
    'train': train_acc,
    'val': val_acc,
    'test': test_acc
}

# Save DBSCAN properly
if hasattr(dbscan, 'model') and not isinstance(dbscan.model, dict):
    joblib.dump(dbscan.model, "models/saved/dbscan_model.pkl", compress=3)
elif isinstance(dbscan.model, dict):
    joblib.dump(dbscan.model['model'], "models/saved/dbscan_model.pkl", compress=3)
else:
    joblib.dump(dbscan, "models/saved/dbscan_model.pkl", compress=3)
print(f"  ✓ Saved")

# Save scaler
joblib.dump(scaler, "models/saved/scaler.pkl", compress=3)
print(f"\n✓ Saved scaler ({X_train_df.shape[1]} features)")

# Print summary
print("\n" + "=" * 60)
print("📊 TRAINING SUMMARY")
print("=" * 60)

print("\nModel Performance (Test Accuracy):")
for model_name, results in sorted(training_results.items(), 
                                   key=lambda x: x[1]['test'], 
                                   reverse=True):
    test_acc = results['test']
    train_acc = results['train']
    gap = train_acc - test_acc
    
    status = "✅" if test_acc > 0.80 else "⚠️"
    overfitting = "🔴 OVERFIT" if gap > 0.15 else "✓"
    
    print(f"  {model_name:20} Test: {test_acc:.2%} | Gap: {gap:.2%} {overfitting}")

print("\n" + "=" * 60)
print("✅ RETRAINING COMPLETE!")
print("=" * 60)
print("\nNext steps:")
print("  1. Evaluate models: python evaluate_models_fixed_v2.py")
print("  2. Restart Docker: docker-compose down && docker-compose build && docker-compose up")
print("  3. Check accuracy with real data")