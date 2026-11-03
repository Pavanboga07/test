# Deployment Guide — `ai-nexus-gateway`

## 1. Standalone Development Deployment
```bash
cd ai-nexus-gateway
npm install
PORT=4000 HOST=0.0.0.0 ALLOWED_ORIGINS=http://localhost:3000 NODE_WS_PATH=/ws/node npm run dev
```

## 2. Health & Readiness Verification
```bash
curl -s http://localhost:4000/health
curl -s http://localhost:4000/ready
```
- `/health` reports Gateway status, version, uptime, database status, active node WebSocket connection count, and queue status.
- `/ready` reports readiness of `identityRegistry`, `messageRouter`, `offlineQueue`, and `webSocketTransport`.

## 3. Container Deployment
```bash
docker build -t ai-nexus-gateway:1.0.0 .
docker run -p 4000:4000 \
  -e PORT=4000 \
  -e ALLOWED_ORIGINS=http://localhost:3000 \
  -e NODE_WS_PATH=/ws/node \
  ai-nexus-gateway:1.0.0
```
