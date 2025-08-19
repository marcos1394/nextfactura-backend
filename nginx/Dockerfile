# nginx/Dockerfile
# Usa una imagen oficial y ligera de Nginx
FROM nginx:stable-alpine

# Elimina la configuración por defecto
RUN rm /etc/nginx/conf.d/default.conf

# Copia nuestra configuración personalizada al lugar correcto dentro del contenedor
COPY nginx.conf /etc/nginx/conf.d/
