# SECURE COUNTERPART — negative-control fixture. Hardened version of vulnerable-app/Dockerfile.
# Stricter still: pin by @sha256 digest — omitted here only to avoid committing a stale hash.
# S9 — Container misconfig fixed (CWE-250 / CWE-1104): pinned base version, non-root user, no
# secret baked into the image. The marker form matches every other secure fixture file so
# eval/build_ground_truth.py picks it up as a false-positive trap.
FROM node:20.11.1-bookworm-slim
WORKDIR /app
# In a real project commit package-lock.json and use `npm ci --omit=dev` for reproducible,
# integrity-checked installs.
COPY package.json ./
RUN npm install --omit=dev
COPY . .
# API_TOKEN is injected at runtime (`docker run --env API_TOKEN=…`), never baked in.
USER node
CMD ["node", "server.js"]
