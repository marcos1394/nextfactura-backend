# Dockerfile Definitivo para cada microservicio (Versión Debian)

# --- Etapa 1: Build (Construcción) ---
# Usamos una imagen 'slim' de Node para instalar dependencias. Es un buen balance entre tamaño y compatibilidad.
FROM node:18-bullseye-slim AS builder
WORKDIR /app

# Copiamos solo los archivos de manifiesto para aprovechar la caché de Docker
COPY package.json package-lock.json* ./

# Instalamos solo las dependencias de producción
RUN npm install --only=production


# --- Etapa 2: Producción ---
# Partimos de la misma imagen base para la etapa final
FROM node:18-bullseye-slim AS production
WORKDIR /app

# --- INSTALACIÓN DE DEPENDENCIAS DE RED ---
# Se instalan las herramientas necesarias para el script de espera y los healthchecks.
# 'netcat-traditional' provee el comando 'nc' que necesita wait-for-it.sh.
# 'wget' es usado por los healthchecks en docker-compose.yml.
RUN apt-get update && apt-get install -y netcat-traditional wget && rm -rf /var/lib/apt/lists/*

# Copia el script de espera y dale permisos de ejecución

# Copiamos las dependencias ya instaladas desde la etapa de 'builder'
COPY --from=builder /app/node_modules ./node_modules

# Copiamos el código fuente de la aplicación
COPY . .

# EXPOSE no es estrictamente necesario con network_mode:host, pero es una buena práctica
# para documentar en qué puerto la aplicación INTENTA escuchar.
# El puerto real es controlado por tu variable de entorno PORT.

# Comando para iniciar el servicio cuando el contenedor se ejecute
CMD [ "node", "server.js" ]
