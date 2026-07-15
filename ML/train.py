"""
IntelliShield ML Training Script
Trains 5 machine learning models on UNSW-NB15 dataset
"""

import pandas as pd
import numpy as np
import os
import joblib
from sklearn.model_selection import train_test_split
from sklearn.preprocessing import StandardScaler, LabelEncoder
from sklearn.metrics import classification_report, accuracy_score, confusion_matrix
import warnings
warnings.filterwarnings('ignore')

# Import our model classes
from models.xgboost_model import XGBoostDetector
from models.random_forest import RandomForestDetector
from models.isolation_forest import IsolationForestDetector
from models.lstm_model import LSTMDetector
from models.dbscan_cluster import DBSCANDetector

class IntelliShieldTrainer:
    def __init__(self, data_path=None):
        # Use provided path or default to ../data directory
        if data_path is None:
            data_path = os.path.join(os.path.dirname(__file__), '..', 'data')
        self.data_path = data_path
        self.scaler = StandardScaler()
        self.label_encoder = LabelEncoder()
    
    def load_dataset(self):
        """Load and combine all CSV files from UNSW-NB15"""
        print("🔍 Loading UNSW-NB15 Dataset...")
        
        csv_files = [
        
            "UNSW-NB15_3.csv"
            
        ]
        
        # UNSW-NB15 column names (43 features + 1 label)
        column_names = [
            'srcip', 'srcport', 'dstip', 'dstport', 'proto', 'state', 'dur', 
            'sbytes', 'dbytes', 'sttl', 'dttl', 'sloss', 'dloss', 'service', 
            'Sload', 'Dload', 'Spkt', 'Dpkt', 'swin', 'dwin', 'stcpb', 
            'dtcpb', 'smeansz', 'dmeansz', 'trans_depth', 'res_bdy_len', 
            'Sjit', 'Djit', 'Stime', 'Ltime', 'Sintpkt', 'Dintpkt', 'tcprtt', 
            'synack', 'ackdat', 'is_sm_ips_ports', 'ct_state_ttl', 
            'ct_flw_http_mthd', 'is_ftp_login', 'ct_ftp_cmd', 'ct_srv_src', 
            'ct_srv_dst', 'ct_dst_ltm', 'ct_src_ltm', 'ct_src_dport_ltm', 
            'attack_cat', 'label'
        ]
        
        dataframes = []
        for file in csv_files:
            file_path = os.path.join(self.data_path, file)
            if os.path.exists(file_path):
                print(f"  ✓ Loading {file}...")
                df = pd.read_csv(file_path, header=None, names=column_names, 
                                encoding='utf-8', low_memory=True)
                dataframes.append(df)
            else:
                print(f"  ⚠️  File not found: {file}")
                print(f"     Looking in: {file_path}")
        
        if not dataframes:
            raise FileNotFoundError(f"No dataset files found in {self.data_path}!")
        
        # Combine all dataframes
        data = pd.concat(dataframes, ignore_index=True)
        print(f"✅ Loaded {len(data):,} total samples")
        
        return data
    
    def preprocess_data(self, data):
        """Clean and prepare data for training"""
        print("\n🔧 Preprocessing data...")
        
        # Remove spaces from column names
        data.columns = data.columns.str.strip()
        
        # UNSW-NB15 has 'label' column (0=normal, 1=attack)
        label_col = 'label'
        
        print(f"  Label column: {label_col}")
        
        # Separate features and labels - exclude 'attack_cat' and 'label'
        X = data.drop(columns=['label', 'attack_cat'])
        y = data['label']
        
        # Remove non-numeric columns (like IP addresses, protocols as strings)
        # Keep only numeric features
        numeric_cols = X.select_dtypes(include=[np.number]).columns
        X = X[numeric_cols]
        
        # Handle infinite values
        X.replace([np.inf, -np.inf], np.nan, inplace=True)
        
        # Fill missing values with 0
        X.fillna(0, inplace=True)
        
        # UNSW-NB15 labels are already binary (0=normal, 1=attack)
        y = pd.to_numeric(y, errors="coerce")  # convert invalid values to NaN
        y = y.fillna(0)                        # treat NaN as normal traffic
        y_binary = y.astype(int)  # Clean label column


        
        print(f"  ✓ Features: {X.shape[1]} columns")
        print(f"  ✓ Samples: {len(X):,}")
        print(f"  ✓ Attacks: {y_binary.sum():,} ({y_binary.sum()/len(y_binary)*100:.1f}%)")
        print(f"  ✓ Normal: {(y_binary==0).sum():,} ({(y_binary==0).sum()/len(y_binary)*100:.1f}%)")
        
        return X, y_binary, y
    
    def balance_dataset(self, X, y, attack_ratio=0.3):
        """Balance the dataset (optional - reduces training time)"""
        print("\n⚖️  Balancing dataset...")
        
        # Separate attack and normal samples
        attack_mask = y == 1
        normal_mask = y == 0
        
        X_attack = X[attack_mask]
        X_normal = X[normal_mask]
        y_attack = y[attack_mask]
        y_normal = y[normal_mask]
        
        # Sample normal traffic to match attack ratio
        n_attacks = len(X_attack)
        n_normal_desired = int(n_attacks * (1 - attack_ratio) / attack_ratio)
        
        if n_normal_desired < len(X_normal):
            X_normal_sampled = X_normal.sample(n=n_normal_desired, random_state=42)
            y_normal_sampled = y_normal.loc[X_normal_sampled.index]
        else:
            X_normal_sampled = X_normal
            y_normal_sampled = y_normal
        
        # Combine
        X_balanced = pd.concat([X_attack, X_normal_sampled])
        y_balanced = pd.concat([y_attack, y_normal_sampled])
        
        print(f"  ✓ Balanced dataset: {len(X_balanced):,} samples")
        print(f"  ✓ Attacks: {y_balanced.sum():,} ({y_balanced.sum()/len(y_balanced)*100:.1f}%)")
        
        return X_balanced, y_balanced
    
    def train_models(self, X_train, X_test, y_train, y_test):
        """Train all 5 ML models"""
        print("\n🤖 Training Machine Learning Models...")
        
        models = {}
        
        # 1. XGBoost
        print("\n[1/5] Training XGBoost...")
        xgb = XGBoostDetector()
        xgb.train(X_train, y_train)
        accuracy = xgb.evaluate(X_test, y_test)
        print(f"  ✓ XGBoost Accuracy: {accuracy:.2%}")
        models['xgboost'] = xgb
        
        # 2. Random Forest
        print("\n[2/5] Training Random Forest...")
        rf = RandomForestDetector()
        rf.train(X_train, y_train)
        accuracy = rf.evaluate(X_test, y_test)
        print(f"  ✓ Random Forest Accuracy: {accuracy:.2%}")
        models['random_forest'] = rf
        
        # 3. Isolation Forest
        print("\n[3/5] Training Isolation Forest...")
        iso = IsolationForestDetector()
        iso.train(X_train, y_train)
        accuracy = iso.evaluate(X_test, y_test)
        print(f"  ✓ Isolation Forest Accuracy: {accuracy:.2%}")
        models['isolation_forest'] = iso
        
        # 4. LSTM (Deep Learning)
        print("\n[4/5] Training LSTM Neural Network...")
        lstm = LSTMDetector(input_dim=X_train.shape[1])
        X_train_lstm = X_train.values.reshape((X_train.shape[0], 1, X_train.shape[1]))
        X_test_lstm  = X_test.values.reshape((X_test.shape[0], 1, X_test.shape[1]))
        lstm.train(X_train_lstm, y_train, epochs=3, batch_size=512)
        accuracy = lstm.evaluate(X_test_lstm, y_test)
        print(f"  ✓ LSTM Accuracy: {accuracy:.2%}")
        models['lstm'] = lstm
    

        # 5. DBSCAN (on small sample)
        print("\n[5/5] Training DBSCAN Clustering...")
        print("  ⚠️  Using small sample (1000 points) due to DBSCAN's O(n²) complexity...")

        # Sample only 1000 points for DBSCAN
        sample_size = 1000
        if len(X_train) > sample_size:
            sample_indices = np.random.choice(len(X_train), sample_size, replace=False)
            X_train_dbscan = X_train.iloc[sample_indices]
            y_train_dbscan = y_train.iloc[sample_indices]
        else:
            X_train_dbscan = X_train
            y_train_dbscan = y_train

        dbscan = DBSCANDetector()
        dbscan.train(X_train_dbscan, y_train_dbscan)
        accuracy = dbscan.evaluate(X_test, y_test)
        print(f"  ✓ DBSCAN Accuracy: {accuracy:.2%}")
        models['dbscan'] = dbscan
        
        return models
    
    def save_models(self, models):
        """Save all trained models"""
        print("\n💾 Saving models...")
        
        os.makedirs("models/saved", exist_ok=True)
        
        for name, model in models.items():
            model.save(f"models/saved/{name}_model.pkl")
            print(f"  ✓ Saved {name}")
        
        # Save scaler
        joblib.dump(self.scaler, "models/saved/scaler.pkl")
        print("  ✓ Saved scaler")
        
        print("\n✅ All models saved successfully!")

def main():
    """Main training pipeline"""
    print("=" * 60)
    print("🛡️  IntelliShield ML Model Training")
    print("=" * 60)
    
    # Initialize trainer
    trainer = IntelliShieldTrainer()
    
    # Load dataset
    data = trainer.load_dataset()
    
    # Preprocess
    X, y_binary, y_multiclass = trainer.preprocess_data(data)
    
    # Balance dataset (optional - comment out to use full dataset)
    X, y_binary = trainer.balance_dataset(X, y_binary)
    
    # Scale features
    print("\n📏 Scaling features...")
    X_scaled = trainer.scaler.fit_transform(X)
    X_scaled = pd.DataFrame(X_scaled, columns=X.columns)
    
    # Split into train/test
    print("\n✂️  Splitting into train/test...")
    X_train, X_test, y_train, y_test = train_test_split(
        X_scaled, y_binary, test_size=0.2, random_state=42, stratify=y_binary
    )
    print(f"  ✓ Training samples: {len(X_train):,}")
    print(f"  ✓ Testing samples: {len(X_test):,}")
    
    # Train all models
    models = trainer.train_models(X_train, X_test, y_train, y_test)
    
    # Save models
    trainer.save_models(models)
    
    print("\n" + "=" * 60)
    print("✅ Training Complete!")
    print("=" * 60)
    print("\nNext steps:")
    print("  1. Start the API server: python api/server.py")
    print("  2. Run packet capture: go run capture/main.go")
    print("=" * 60)

if __name__ == "__main__":
    main()