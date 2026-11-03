FROM node:22-bookworm-slim
WORKDIR /app

RUN apt-get update && apt-get install -y --no-install-recommends git ca-certificates curl && rm -rf /var/lib/apt/lists/*

COPY package.json tsconfig.json ./
RUN npm install

COPY src ./src
COPY .env.example ./.env.example

RUN mkdir -p /var/data && npm run build

ENV NODE_ENV=production
ENV PORT=4000
ENV GATEWAY_HOST=0.0.0.0
ENV GATEWAY_DATA_DIR=/var/data
ENV GATEWAY_DB_PATH=/var/data/gateway.sqlite
ENV NODE_WS_PATH=/ws/node

EXPOSE 4000

HEALTHCHECK --interval=15s --timeout=5s --start-period=10s --retries=3 \
  CMD curl -fsS http://127.0.0.1:${PORT:-4000}/api/ready || exit 1

CMD ["npm", "start"]
