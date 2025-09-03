# Dockerfile para notification-service

# --- Etapa 1: Build (Construcción de dependencias) ---
FROM node:18-bullseye-slim AS builder
WORKDIR /app

# Copiamos solo los archivos de manifiesto para aprovechar la caché de Docker
COPY package*.json ./

# Instalamos solo las dependencias de producción
RUN npm install --only=production


# --- Etapa 2: Producción (Imagen final) ---
FROM node:18-bullseye-slim AS production
WORKDIR /app

# Copiamos las dependencias ya instaladas desde la etapa de 'builder'
COPY --from=builder /app/node_modules ./node_modules

# Copiamos el código fuente de la aplicación
COPY . .

# Expone el puerto que la aplicación usará dentro del contenedor
EXPOSE 4007

# Comando para iniciar el servicio
CMD [ "node", "server.js" ]