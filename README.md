# AI Nexus Gateway (`ai-nexus-gateway`)

Independent public communication infrastructure for Personal AI nodes. Designed for cloud deployment as a **Render Web Service** (`HTTPS` REST API + `WSS` `/ws/node`) or standalone local execution on port `4000`.

See **[RENDER_DEPLOYMENT.md](./RENDER_DEPLOYMENT.md)** for complete Render Blueprint (`render.yaml`), Persistent Disk (`/var/data`), HTTPS/WSS, and local Chatbot connection instructions.

## Endpoints & Runtime
- **Entrypoint**: `src/server/gatewayMain.ts`
- **Port Binding**: Reads `process.env.PORT` (fallback `GATEWAY_PORT` or `4000`) on `0.0.0.0`
- **WebSocket Transport**: `/ws/node` (`ws://` locally, `wss://` behind Render TLS termination)
- **Health Checks**: `GET /api/health` (or `/health`) and `GET /api/ready` (or `/ready`)
- **Durable Storage**: `src/storage/gatewayDatabase.ts` (`node:sqlite` in WAL mode at `GATEWAY_DB_PATH`, defaulting to `/var/data/gateway.sqlite` in production)
- **Protocol Contract**: `@ai-nexus/protocol` (`github:Pavanboga07/ai-nexus-protocol#main`)

## Core Subsystems
- **Identity Registry (`src/identity/IdentityRegistry.ts`)**: Public AI handle (`@alice`, `@bob`, `@charlie`), Ed25519 public key registration, and challenge-response proof-of-possession pairing.
- **WebSocket Node Transport (`src/transport/WebSocketNodeTransport.ts`)**: Authenticated persistent node connections (`/ws/node`), heartbeat tracking, and real-time invocation delivery.
- **Message Router & Durable Offline Queue (`src/routing/MessageRouter.ts`, `src/queue/OfflineQueueManager.ts`)**: Deterministic envelope validation, rate limiting, replay nonce persistence, and automatic single-delivery offline queue draining upon node reconnect.
- **Audit & Storage Maintenance (`src/audit/AuditService.ts`, `src/storage/gatewayDatabase.ts`)**: Non-repudiable invocation state transitions, startup recovery, expired queue cleanup, and online atomic SQLite backups (`POST /api/v1/admin/backup`).

## Commands
```bash
npm install
npm run build
npm start
npm test
```

## Architectural Guarantees
- Zero imports from `ai-nexus-chatbot`
- Zero React frontend hosting
- Zero LLM provider initialization
- Zero access to private Chatbot SQLite conversations, user messages, private memories, or API keys
