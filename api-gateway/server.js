// --- api-gateway/server.js ---
require('dotenv').config();
const express = require('express');
const cors = require('cors');
const { createProxyMiddleware } = require('http-proxy-middleware');

const app = express();
app.use(cors());

// --- Definición de Rutas y Servicios de Destino ---
// Las URLs de destino serán las URLs internas que Render nos proporciona para cada servicio.
// Las cargamos desde variables de entorno para máxima flexibilidad.
const services = [
    {
        route: '/api/auth',
        target: process.env.AUTH_SERVICE_URL || 'http://localhost:3001'
    },
    {
        route: '/api/restaurants',
        target: process.env.RESTAURANT_SERVICE_URL || 'http://localhost:3002'
    },
    {
        route: '/api/portal',
        target: process.env.RESTAURANT_SERVICE_URL || 'http://localhost:3002'
    },
    {
        route: '/api/payment',
        target: process.env.PAYMENT_SERVICE_URL || 'http://localhost:3003'
    },
    {
        route: '/api/pos',
        target: process.env.POS_SERVICE_URL || 'http://localhost:3004'
    }
    // Agrega más rutas y servicios aquí a medida que crezcan
];

// --- Configuración del Proxy ---
// Iteramos sobre nuestra configuración y creamos un proxy para cada ruta.
services.forEach(({ route, target }) => {
    app.use(route, createProxyMiddleware({
        target,
        changeOrigin: true,
        pathRewrite: (path, req) => {
            // Re-escribe la ruta para eliminar el prefijo base.
            // Ejemplo: /api/auth/login -> /login
            return path.replace(route, '');
        },
        onProxyReq: (proxyReq, req, res) => {
            console.log(`[Gateway] Redirigiendo ${req.method} ${req.originalUrl} -> ${target}${proxyReq.path}`);
        }
    }));
});

// Endpoint de estado del Gateway
app.get('/api/gateway/status', (req, res) => {
    res.json({ success: true, message: 'API Gateway is running.' });
});

// --- Arranque del Servidor ---
const PORT = process.env.PORT || 8080;
app.listen(PORT, () => {
    console.log(`🚀 API Gateway escuchando en el puerto ${PORT}`);
});
