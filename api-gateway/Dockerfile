# Dockerfile para cada microservicio (Versión Corregida)

# --- Etapa 1: Build (Construcción) ---
# Usamos una imagen completa de Node para instalar dependencias de forma segura
FROM node:18-alpine AS builder
WORKDIR /app

# Copiamos solo los archivos de manifiesto para aprovechar la caché de Docker
COPY package.json package-lock.json* ./

# --- CORRECCIÓN DEFINITIVA ---
# Usamos 'npm install' en lugar de 'npm ci'.
# 'npm install' es más flexible y creará un package-lock.json si no existe.
# Usamos '--omit=dev' para no instalar las dependencias de desarrollo.
RUN npm install --omit=dev

# --- Etapa 2: Producción ---
# Usamos una imagen 'slim' de Node, que es más pequeña y tiene menos vulnerabilidades
FROM node:18-alpine AS production
WORKDIR /app

# Copiamos las dependencias ya instaladas desde la etapa de 'builder'
COPY --from=builder /app/node_modules ./node_modules

# Copiamos el código fuente de la aplicación
COPY . .

# Exponemos el puerto interno del contenedor
EXPOSE 8080

# Comando para iniciar el servicio cuando el contenedor se ejecute
CMD [ "node", "server.js" ]
