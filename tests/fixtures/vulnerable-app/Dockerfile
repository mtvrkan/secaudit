# INTENTIONALLY VULNERABLE — SecAudit test fixture. Not a real image.
# V9 — Container misconfig: unpinned 'latest' base, runs as root, secret in ENV.
FROM node:latest
ENV API_TOKEN=sk-test-EXAMPLE-not-a-real-secret-000000000000
COPY . /app
WORKDIR /app
RUN npm install
# No USER directive → runs as root (CWE-250). Base image not pinned to a digest.
CMD ["node", "server.js"]
