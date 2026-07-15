# IntelliShield Copilot Instructions

## Project Overview
IntelliShield is a network intrusion detection system (NIDS) with dual architecture:
- **capture/** (Go): Real-time packet capture and feature extraction from network interfaces
- **ML/** (Python): Ensemble of 5 detection models trained on UNSW-NB15 dataset

Data flows: Raw packets → Feature extraction → ML predictions → Responses (future: blocking/alerting)

## Architecture Essentials

### Packet Capture Pipeline (capture/*.go)
- **capture_packet.go**: Uses `github.com/gopacket` to open network interfaces in promiscuous mode (snapshot: 1600 bytes, timeout: 30s)
- **feature_extractor.go**: Extracts 43+ features from packets (IPs, ports, TCP flags, inter-arrival times, payload sizes)
- **main.go**: Orchestrates capture → buffering → processing with graceful shutdown handling
- **Design pattern**: Channel-based communication (packetChan, stopChan); background goroutines

### ML Detection Ensemble (ML/models/*.py)
Five complementary detectors in [train.py](ML/train.py):
1. **XGBoostDetector**: High accuracy for labeled attacks
2. **RandomForestDetector**: Robust to noisy data
3. **IsolationForestDetector**: Unsupervised anomaly detection (no labeled data needed)
4. **LSTMDetector**: Sequential/temporal patterns
5. **DBSCANDetector**: Clustering-based anomalies

Each model has standard interface: `train(X, y)`, `predict(X)`, `predict_proba(X)`, `evaluate()`, `save()`, `load()`

### Dataset: UNSW-NB15
- Location: `data/UNSW-NB15/` (3 CSV files: _1, _2, _3)
- 43 features + 2 labels (attack_cat, label where 0=normal, 1=attack)
- **Important**: Features are numeric; categorical (srcip, dstip, proto, service) must be dropped or encoded before training
- Data loading: [train.py](ML/train.py#L30-L45) hardcoded path `C:/Users/musae/Downloads/IntelliShield/data/UNSW-NB15`

## Development Workflows

### Running Packet Capture (Go)
```bash
cd capture/
go mod tidy  # sync dependencies
go run main.go  # interactive device selection
```
**Note**: Requires network interface permissions; may need admin/sudo on Windows/Linux

### Training ML Models (Python)
```bash
cd ML/
python train.py  # loads UNSW-NB15, trains all 5 models, saves to models/
```
- Trains on 80% data, validates on 20%
- Prints classification reports per model
- Saves `.pkl` files in `models/` directory for later inference

### Integration Point (Future)
API communication expected between Go client (capture/) and Python server (ML/) for real-time prediction—not yet implemented in current structure

## Key Conventions & Patterns

### Go Code Style
- Channel-based async: `go func()` + channels preferred over mutexes
- Error handling: Return errors explicitly, use `log.Fatalf()` for fatal setup errors
- Struct methods for state (e.g., PacketCapture, FeatureExtractor)

### Python Code Style
- Model classes inherit no base class; implement duck-typed interface
- `joblib.dump()` / `joblib.load()` for model persistence
- `sklearn.preprocessing` (StandardScaler, LabelEncoder) for feature normalization before training

### Data Handling
- **Feature engineering**: Performed in Go (feature_extractor.go); Python models expect cleaned numeric input
- **Scaling required**: All Python models expect `StandardScaler` fit on training data
- **Label encoding**: UNSW-NB15 attack categories encoded as binary (0/1) in `label` column

## Critical Implementation Details

1. **Network Interface Selection** ([capture/main.go](capture/main.go#L17-L18)): Device name varies by OS (eth0/wlan0 Linux, en0 macOS, `\\Device\\NPF_{...}` Windows)
2. **Buffer Strategy** ([capture/main.go](capture/main.go#L35)): 1000 packet capacity or 5-second flush—tunable for throughput/latency tradeoff
3. **Model Evaluation Metric**: Binary classification (attack vs. normal); focus on precision+recall balance for IDS use case
4. **Joblib Over Pickle**: All model saving uses `joblib` for scikit-learn compatibility and optional compression

## When Adding Features

- **New detection model**: Add class to `ML/models/`, update imports in `ML/__init__.py` and train.py
- **New packet features**: Extract in [feature_extractor.go](capture/feature_extractor.go), add to FlowFeatures struct
- **Dataset changes**: Update column names list in [train.py](ML/train.py#L33-L45)
- **Cross-language communication**: Design Go→Python serialization format (JSON or Protocol Buffers recommended)
