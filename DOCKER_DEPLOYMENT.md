# IntelliShield Docker Deployment Guide

## Prerequisites
- Docker installed and running
- Docker Compose 1.29+
- On Windows: WSL2 backend recommended
- On Linux: Run with sudo or add user to docker group

## Directory Structure
```
IntelliShield/
├── docker/
│   └── docker-compose.yml
├── capture/
│   ├── Dockerfile
│   ├── main.go
│   └── ...
├── ML/
│   ├── Dockerfile
│   ├── requirements.txt
│   ├── server.py
│   ├── train.py
│   └── models/
│       └── saved/
│           ├── lstm_model.h5
│           ├── xgboost_model.pkl
│           └── ...
└── data/
    └── UNSW-NB15/
        ├── UNSW-NB15_1.csv
        └── ...
```

## Deployment Steps

### 1. Pre-build: Train ML Models (if not already done)
```bash
cd ML
python train.py  # Generates model files in models/saved/
cd ..
```

### 2. Build Docker Images
```bash
cd docker
docker-compose build
```

### 3. Start All Services
```bash
docker-compose up -d
```

This will start:
- **ml-api** (port 8000) - Python ML server
- **packet-capture** - Go packet capture
- **elasticsearch** (port 9200) - Log storage
- **kibana** (port 5601) - Log visualization

### 4. Verify Services Running
```bash
docker-compose ps
```

Expected output:
```
NAME                            STATUS
intellishield-ml-api           Up (healthy)
intellishield-capture          Up
intellishield-elasticsearch    Up (healthy)
intellishield-kibana           Up (healthy)
```

### 5. Check Logs
```bash
# View all logs
docker-compose logs -f

# View specific service
docker-compose logs -f ml-api
docker-compose logs -f packet-capture
```

### 6. Stop Services
```bash
docker-compose down
```

## Service Details

### ML API Server (Port 8000)
- **Container**: intellishield-ml-api
- **Health Check**: http://localhost:8000/health
- **Volumes**: 
  - Models: `/app/models/saved`
  - Dataset: `/app/data`

### Packet Capture
- **Container**: intellishield-capture
- **Privileges**: Runs with CAP_NET_ADMIN, CAP_NET_RAW to capture packets
- **Output**: Logs to `/logs` (mounted volume)

### Elasticsearch (Port 9200)
- **Container**: intellishield-elasticsearch
- **API**: http://localhost:9200
- **Storage**: Persistent volume `elasticsearch-data`

### Kibana (Port 5601)
- **Container**: intellishield-kibana
- **Dashboard**: http://localhost:5601
- **Elasticsearch Link**: http://elasticsearch:9200

## Network Configuration

Services communicate via Docker network `intellishield-network`:
- **ml-api** ↔ **packet-capture** (internal: http://ml-api:8000)
- All services ↔ **elasticsearch** (internal: http://elasticsearch:9200)

## Troubleshooting

### ML API Won't Start
```bash
# Check Python dependencies
docker exec intellishield-ml-api pip list

# Check if models exist
docker exec intellishield-ml-api ls -la models/saved/
```

### Packet Capture Can't Access Network Interface
```bash
# On Linux, packet-capture needs network_mode: host
# Uncomment in docker-compose.yml for Linux

# On Windows/macOS with Docker Desktop, this limitation doesn't apply
```

### Health Checks Failing
```bash
# Check if service is actually running
docker exec intellishield-ml-api curl http://localhost:8000/health

# View service logs
docker logs intellishield-ml-api
```

## Production Recommendations

1. **Use environment variables** for configuration:
   ```yaml
   environment:
     - ML_API_URL=http://ml-api:8000
     - AUTO_BLOCK=true
     - LOG_LEVEL=INFO
   ```

2. **Add resource limits**:
   ```yaml
   resources:
     limits:
       cpus: '2'
       memory: 2G
   ```

3. **Use health checks** to restart failed services

4. **Mount persistent volumes** for logs and models

5. **Use secrets** for sensitive data (API keys, credentials)

## Monitoring

### View Real-time Logs
```bash
docker-compose logs -f
```

### Monitor Resource Usage
```bash
docker stats
```

### Check Network Traffic
```bash
docker exec intellishield-capture ifconfig  # Linux
```

## Example: Full Stack Startup

```bash
# 1. Navigate to docker directory
cd docker

# 2. Build images
docker-compose build

# 3. Start all services
docker-compose up -d

# 4. Wait for services to be healthy
sleep 10

# 5. Verify status
docker-compose ps

# 6. Check logs
docker-compose logs ml-api

# 7. Access services
# ML API: http://localhost:8000
# Kibana: http://localhost:5601
# Elasticsearch: http://localhost:9200
```
