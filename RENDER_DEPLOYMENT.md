# AI Nexus Gateway — Render Production Deployment Guide

This guide covers deploying **`ai-nexus-gateway`** (`https://github.com/Pavanboga07/ai-nexus-gateway`) as a standalone public Web Service on **Render**, while keeping **`ai-nexus-chatbot`** and its private SQLite database (`chatbot.sqlite`) running locally on your computer.

---

## 1. Architecture Overview

- **Public Infrastructure (`ai-nexus-gateway` on Render)**:
  - Provides public HTTPS REST API (`/api/v1/*`, `/api/health`, `/api/ready`) and secure WSS real-time node transport (`wss://<service>.onrender.com/ws/node`).
  - Persists **only** public Gateway infrastructure state in `/var/data/gateway.sqlite` (registered public AI identities, Ed25519 pairing challenges, offline delivery queue, invocation state transitions, consumed replay nonces, revoked permission references, and Gateway audit events).
- **Local Application (`ai-nexus-chatbot` on User's Computer)**:
  - Runs locally on `http://localhost:3000`.
  - Stores all conversations, messages, private memories, user settings, attachments, and owner context in a local SQLite database (`~/.ai-nexus-chatbot/chatbot.sqlite` or `CHATBOT_DB_PATH`).
  - Connects outbound to the Render Gateway via `GATEWAY_PUBLIC_URL` (`https://...`) and `GATEWAY_WS_URL` (`wss://.../ws/node`).
  - Works offline for normal local AI conversations even if the public Gateway is unreachable.

---

## 2. Option A: Deploy via Render Blueprint (`render.yaml` — Recommended)

The repository includes a ready-to-use `render.yaml` Blueprint at the root of `ai-nexus-gateway`.

1. Ensure the latest changes are pushed to:
   - `https://github.com/Pavanboga07/ai-nexus-protocol`
   - `https://github.com/Pavanboga07/ai-nexus-gateway`
2. Log in to the [Render Dashboard](https://dashboard.render.com/).
3. Click **New +** → **Blueprint**.
4. Connect your GitHub account and select **`Pavanboga07/ai-nexus-gateway`**.
5. Render will detect `render.yaml` and configure:
   - **Service Name**: `ai-nexus-gateway`
   - **Runtime**: `Node` (Node `>=22.5.0` for built-in `node:sqlite`)
   - **Plan**: `starter` (required for Persistent Disk support)
   - **Instances**: `1` (`numInstances: 1`)
   - **Persistent Disk**: `gateway-sqlite-data` mounted at `/var/data` (`1 GB`)
   - **Health Check Path**: `/api/ready`
6. When prompted for `sync: false` environment variables (`GATEWAY_PUBLIC_URL` and `GATEWAY_WS_URL`), set them to your service's Render URL (e.g., `https://ai-nexus-gateway.onrender.com` and `wss://ai-nexus-gateway.onrender.com/ws/node`), or leave them blank on initial creation and set them once Render assigns your `.onrender.com` subdomain.
7. Click **Apply** to provision and deploy.

---

## 3. Option B: Manual Render Web Service Configuration

If creating the Web Service manually in the Render UI without Blueprints:

- **Repository**: `https://github.com/Pavanboga07/ai-nexus-gateway`
- **Branch**: `main`
- **Runtime**: `Node`
- **Build Command**: `npm install && npm run build`
- **Start Command**: `npm start`
- **Instance Type**: **Starter** (or higher paid plan if mounting a Persistent Disk)
- **Health Check Path**: `/api/ready`
- **Persistent Disk**:
  - **Name**: `gateway-sqlite-data`
  - **Mount Path**: `/var/data`
  - **Size**: `1 GB`

---

## 4. Required Environment Variables

Configure the following in **Render Dashboard → `ai-nexus-gateway` → Environment**:

| Variable | Value | Description |
| --- | --- | --- |
| `NODE_ENV` | `production` | Enables production reverse-proxy trust (`trust proxy = 1`) and `/var/data` defaults. |
| `GATEWAY_HOST` | `0.0.0.0` | Binds HTTP & WebSocket server to all container interfaces (Render injects `PORT` automatically). |
| `GATEWAY_DATA_DIR` | `/var/data` | Mount directory for the Render Persistent Disk. |
| `GATEWAY_DB_PATH` | `/var/data/gateway.sqlite` | Path to the Gateway SQLite database file (WAL mode). |
| `NODE_WS_PATH` | `/ws/node` | WebSocket upgrade path for Personal AI nodes. |
| `GATEWAY_PUBLIC_URL` | `https://<your-service>.onrender.com` | Public HTTPS base URL of the deployed Gateway. |
| `GATEWAY_WS_URL` | `wss://<your-service>.onrender.com/ws/node` | Public WSS WebSocket endpoint for Personal AI nodes. |
| `ALLOWED_ORIGINS` | `*` *(or comma-separated origins)* | Allowed CORS & WebSocket `Origin` headers. Node-to-Node backend connections without browser `Origin` headers are always permitted after Ed25519 signature verification. |
| `GATEWAY_RATE_LIMIT_PER_MINUTE` | `60` | Per-sender AI invocation rate limit per minute. |

> **Note on `PORT`**: Render automatically injects `process.env.PORT` (typically `10000`). The Gateway reads `process.env.PORT` first and binds to `0.0.0.0:${PORT}`. You do not need to hardcode `PORT` in Render.

---

## 5. Secret Configuration

- The Gateway **never** uses LLM API keys (`GEMINI_API_KEY`, `OPENAI_API_KEY`) or Personal AI private keys.
- All node authentication uses asymmetric proof-of-possession signatures (`@ai-nexus/protocol`) verified against registered public keys in `IdentityRegistry`.
- No secrets need to be committed to Git.

---

## 6. Persistent Disk & Scaling Limitations

1. **Paid Plan Requirement**: Render Persistent Disks (`/var/data`) require a compatible paid instance plan (**Starter** or above).
2. **Single-Instance Restriction (`numInstances: 1`)**:
   - Render Persistent Disks can only be mounted to a **single instance** at a time.
   - SQLite in WAL mode is a single-writer embedded database. **Never** scale `ai-nexus-gateway` above `1` instance when backed by SQLite on `/var/data`.
3. **Stateless Free-Tier Alternative**:
   - If you deploy on Render's **Free** tier (which does not support Persistent Disks), set `GATEWAY_DB_PATH=:memory:` (or omit the disk so it writes to ephemeral container storage `./data/gateway.sqlite`).
   - Under the stateless/ephemeral alternative, active nodes will automatically re-register their public identities when they reconnect after a cold start, **but** any offline queued messages waiting for an offline node during a container restart will be lost. Mounting `/var/data` preserves offline queued messages across restarts and redeployments.

---

## 7. Health & Readiness Checks

- **`GET /api/health` (and `GET /health`)**:
  - Returns HTTP `200` with process status, uptime, supported protocol versions (`["1.0"]`), connected node count, and queue metrics.
- **`GET /api/ready` (and `GET /ready`)**:
  - Configured as Render's `healthCheckPath`.
  - Executes `PRAGMA quick_check;` against `/var/data/gateway.sqlite` and verifies `identityRegistry`, `messageRouter`, `offlineQueue`, and `webSocketTransport`.
  - Returns HTTP `200` (`ready: true`) when healthy or HTTP `503` (`ready: false`) if storage is unavailable.

---

## 8. HTTPS, WSS & Custom Domain Setup

- Render terminates TLS (`HTTPS` and `WSS`) at its edge load balancer and forwards traffic to the Gateway container over HTTP/WS with `X-Forwarded-Proto: https`.
- The Gateway configures `app.set('trust proxy', 1)` and handles WebSocket `Upgrade` requests at `/ws/node`.
- **Custom Domain**:
  1. Go to **Render Dashboard → `ai-nexus-gateway` → Settings → Custom Domains**.
  2. Add your domain (e.g., `gateway.yourdomain.com`) and configure the CNAME/ANAME DNS record shown by Render.
  3. Render automatically provisions a free Let's Encrypt TLS certificate.
  4. Update `GATEWAY_PUBLIC_URL=https://gateway.yourdomain.com` and `GATEWAY_WS_URL=wss://gateway.yourdomain.com/ws/node`.

---

## 9. Durable vs. Transient State & Restart Recovery

### Durable in `/var/data/gateway.sqlite` (Survives Restarts & Redeploys)
- Registered `PublicAIIdentity` records (`gateway_identities`)
- Pairing challenges & consumed status (`pairing_challenges`)
- Pending offline queue records (`offline_queue` with `UNIQUE(idempotency_key)` and `delivered_at` tracking)
- Invocation lifecycle records & delivery acknowledgements (`invocations`)
- Consumed cryptographic nonces (`consumed_nonces` for replay protection)
- Revoked permission references (`revoked_permissions`)
- Security & routing audit trail (`gateway_audit_log`)

### Intentionally Transient (In-Memory Only)
- Live WebSocket TCP sockets (`activeNodeSockets`). On Gateway startup, `recoverOnStartup()` resets persisted identities to `online: false` and cleans expired offline queue entries. Connected Chatbot nodes automatically reconnect over WSS within seconds and drain their pending offline queue.

---

## 10. Backup & Integrity Procedure

- **Create an Online Atomic Backup**:
  ```bash
  curl -X POST https://<your-service>.onrender.com/api/v1/admin/backup
  ```
  This executes `VACUUM INTO '/var/data/backups/gateway-backup-<timestamp>.sqlite'`, creating a consistent snapshot while the Gateway remains online.
- **Clean Expired Offline Queue Entries Manually**:
  ```bash
  curl -X POST https://<your-service>.onrender.com/api/v1/admin/cleanup-expired
  ```

---

## 11. Connecting Your Locally Running Chatbot (`ai-nexus-chatbot`)

On your local computer inside `ai-nexus-chatbot`, create or update `.env`:

```env
CHATBOT_PORT=3000
HOST=0.0.0.0

# Keep Chatbot SQLite 100% local on your machine (outside the Git repository)
CHATBOT_DB_PATH=~/.ai-nexus-chatbot/chatbot.sqlite

# Your local LLM API key (never sent to the Gateway)
LLM_PROVIDER=gemini
LLM_MODEL=gemini-3.8-flash
GEMINI_API_KEY=your_actual_gemini_api_key

# Point to your deployed Render Gateway
GATEWAY_PUBLIC_URL=https://<your-service>.onrender.com
GATEWAY_WS_URL=wss://<your-service>.onrender.com/ws/node
```

Then start your local Chatbot:
```bash
npm install
npm run dev
```

Verify connectivity at `http://localhost:3000/health` — `gatewayDependency.connected` will report `true` and `authenticatedNodeWebSockets` will list your connected local Personal AI nodes.

---

## 12. Logs & Troubleshooting

- **Gateway shows `UNAVAILABLE` in local Chatbot**:
  - Verify `curl https://<your-service>.onrender.com/api/ready` returns `{"ready":true,...}`.
  - Ensure `GATEWAY_WS_URL` uses `wss://` (not `ws://`) when connecting to an `https://` Render URL.
- ** HTTP `403 Origin not allowed`**:
  - Check `ALLOWED_ORIGINS` in the Render Environment tab. Set `ALLOWED_ORIGINS=*` or include your local origin `http://localhost:3000`.
- **`ERR_MODULE_NOT_FOUND: @ai-nexus/protocol` during build**:
  - Ensure `https://github.com/Pavanboga07/ai-nexus-protocol` is public and pushed to `main` so `npm install` can fetch `"github:Pavanboga07/ai-nexus-protocol#main"`.
