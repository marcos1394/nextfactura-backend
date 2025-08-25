# Dockerfile para services/connector-service

# --- Etapa 1: Build (Construcción) ---
FROM node:18-bullseye-slim AS builder
WORKDIR /app

# Copiamos solo los archivos de manifiesto para aprovechar la caché de Docker
COPY package.json package-lock.json* ./

# Instalamos solo las dependencias de producción
RUN npm install --only=production


# --- Etapa 2: Producción ---
FROM node:18-bullseye-slim AS production
WORKDIR /app

# Copiamos las dependencias ya instaladas desde la etapa de 'builder'
COPY --from=builder /app/node_modules ./node_modules

# Copiamos el código fuente de la aplicación
COPY . .

# Comando para iniciar el servicio cuando el contenedor se ejecute
CMD [ "node", "server.js" ]