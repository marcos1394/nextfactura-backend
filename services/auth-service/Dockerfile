# ==========================================================
# Dockerfile con Base Robusta (Solución Definitiva)
# ==========================================================

# --- Etapa 1: Build ---
# CAMBIO: Usamos node:18-bullseye, una base Debian robusta y compatible
FROM node:18-bullseye-slim AS builder
WORKDIR /app

COPY package.json package-lock.json* ./

# Instala dependencias necesarias para los healthchecks
RUN apt-get update && apt-get install -y wget && rm -rf /var/lib/apt/lists/*

# Instala dependencias de Node
RUN npm install --only=production

# --- Etapa 2: Producción ---
FROM node:18-bullseye-slim AS production
WORKDIR /app

COPY --from=builder /app/node_modules ./node_modules
COPY --from=builder /usr/bin/wget /usr/bin/wget 

COPY . .

EXPOSE 8080

CMD [ "node", "server.js" ]