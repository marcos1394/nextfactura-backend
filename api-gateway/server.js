const express = require('express');
const cors = require('cors');
const { createProxyMiddleware } = require('http-proxy-middleware');

const app = express();
// --- Middlewares estándar ---
app.use(cors({
    origin: 'https://www.nextmanager.com.mx', // Solo permite peticiones desde tu frontend
    credentials: true                         // ¡CRÍTICO! Permite el intercambio de cookies
}));

// --- URLs de los microservicios ---
const AUTH_SERVICE_URL = process.env.AUTH_SERVICE_URL;
const RESTAURANT_SERVICE_URL = process.env.RESTAURANT_SERVICE_URL;
const PAYMENT_SERVICE_URL = process.env.PAYMENT_SERVICE_URL;
const PAC_SERVICE_URL = process.env.PAC_SERVICE_URL;
const POS_SERVICE_URL = process.env.POS_SERVICE_URL;
const CONNECTOR_SERVICE_URL = process.env.CONNECTOR_SERVICE_URL;
const NOTIFICATION_SERVICE_URL = process.env.NOTIFICATION_SERVICE_URL;
const CONTENT_SERVICE_URL = process.env.CONTENT_SERVICE_URL;

console.log('API Gateway iniciando...');

app.get('/health', (req, res) => res.status(200).json({ status: 'ok' }));

// --- Función para crear la configuración del proxy ---
const createProxyOptions = (targetUrl, routePrefix) => ({
    target: targetUrl,
    changeOrigin: true,
    ws: true,
    pathRewrite: {
        [`^/api${routePrefix}`]: '', // Reescribe /api/auth -> /
    },
    
    // --- LÍNEA CLAVE FINAL ---
    // Esto soluciona el problema de las cookies que no se guardan en el navegador
    // al estar detrás de múltiples proxies. Elimina el dominio de la cookie
    // para que el navegador la asocie con el dominio que está visitando.
    cookieDomainRewrite: "",

    on: {
        proxyReq: (proxyReq, req, res) => {
            console.log(`[Proxy -> Service] Redirigiendo ${req.method} ${req.originalUrl} a ${targetUrl}${proxyReq.path}`);
            console.log('[Proxy -> Service] Cabecera Cookie:', req.headers['cookie'] || 'No presente');
            
            // Reenviamos la cabecera de autorización (para la app mobile)
            if (req.headers.authorization) {
                proxyReq.setHeader('authorization', req.headers.authorization);
            }
        },
        proxyRes: (proxyRes, req, res) => {
            console.log(`[Service -> Gateway] Respuesta de ${targetUrl}${req.originalUrl} | STATUS: ${proxyRes.statusCode}`);
        },
        error: (err, req, res) => {
            console.error(`[Proxy ERROR] Petición a ${targetUrl}: ${err.message}`);
        },
    },
});

// --- Reglas de Proxy ---
const services = [
    { route: '/auth', target: AUTH_SERVICE_URL },
    { route: '/restaurants', target: RESTAURANT_SERVICE_URL },
    { route: '/payments', target: PAYMENT_SERVICE_URL },
    { route: '/pac', target: PAC_SERVICE_URL },
    { route: '/pos', target: POS_SERVICE_URL },
    { route: '/connector', target: CONNECTOR_SERVICE_URL },
    { route: '/notifications', target: NOTIFICATION_SERVICE_URL },
    { route: '/content', target: CONTENT_SERVICE_URL },
];

// Aplicamos el prefijo /api a todas las rutas
services.forEach(({ route, target }) => {
    if (target) {
        const apiRoute = `/api${route}`;
        app.use(apiRoute, createProxyMiddleware(createProxyOptions(target, apiRoute)));
        console.log(`[Proxy] Enrutando ${apiRoute} -> ${target}`);
    }
});

const PORT = process.env.API_GATEWAY_PORT || 8080;
app.listen(PORT, () => {
    console.log(`🚀 API Gateway escuchando en el puerto ${PORT}`);
});