# Dockerfile para cada microservicio

# --- Etapa 1: Build (Construcción) ---
# Usamos una imagen completa de Node para instalar dependencias de forma segura
FROM node:18-alpine AS builder
WORKDIR /app

# Copiamos solo los archivos de manifiesto para aprovechar la caché de Docker
# Esto evita reinstalar todo si solo cambia el código fuente
COPY package.json package-lock.json* ./

# Instalamos solo las dependencias de producción para una imagen final más ligera y segura
RUN npm install --only=production

# --- Etapa 2: Producción ---
# Usamos una imagen 'slim' de Node, que es más pequeña y tiene menos vulnerabilidades
FROM node:18-alpine AS production
WORKDIR /app

# Copiamos las dependencias ya instaladas desde la etapa de 'builder'
COPY --from=builder /app/node_modules ./node_modules

# Copiamos el código fuente de la aplicación
COPY . .

# Exponemos el puerto en el que correrá la aplicación
# Docker Compose se encargará de mapear este puerto
EXPOSE 8080

# Comando para iniciar el servicio cuando el contenedor se ejecute
CMD [ "node", "server.js" ]
