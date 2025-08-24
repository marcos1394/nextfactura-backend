// api-gateway/server.js (Versión Profesional y Completa con Logs Detallados)
require('dotenv').config();
const express = require('express');
const cors = require('cors');
const { createProxyMiddleware } = require('http-proxy-middleware');

const app = express();

// --- Middlewares estándar ---
app.use(cors());
app.use(express.json());

// --- URLs de los microservicios (leídas desde .env) ---
const AUTH_SERVICE_URL = process.env.AUTH_SERVICE_URL || 'http://auth-service:3001';
const RESTAURANT_SERVICE_URL = process.env.RESTAURANT_SERVICE_URL || 'http://restaurant-service:4002';
const PAYMENT_SERVICE_URL = process.env.PAYMENT_SERVICE_URL || 'http://payment-service:4003';
const PAC_SERVICE_URL = process.env.PAC_SERVICE_URL || 'http://pac-service:4005';
const POS_SERVICE_URL = process.env.POS_SERVICE_URL || 'http://pos-service:4004';

console.log('API Gateway (vProfesional) iniciando...');

// --- Middleware de Logging para CADA petición entrante ---
app.use((req, res, next) => {
    console.log(`[Gateway IN] ${new Date().toISOString()} | ${req.ip} | ${req.method} ${req.originalUrl}`);
    next();
});

// Endpoint de salud para que Docker sepa que está vivo
app.get('/health', (req, res) => res.status(200).json({ status: 'ok' }));

// --- Función reutilizable para crear la configuración del proxy con logs ---
const createProxyOptions = (targetUrl, routePrefix) => ({
    target: targetUrl,
    changeOrigin: true,

    // --- CORRECCIÓN FINAL ---
    // Se añade un timeout de 60 segundos (60000 ms). El nombre correcto de 
    // la opción es 'timeout'. Esto evita que el proxy aborte peticiones largas.
    timeout: 60000,

    pathRewrite: {
        // Reescribe la ruta, ej: /auth/login -> /login
        [`^${routePrefix}`]: '',
    },
    logLevel: 'debug', // Nivel de log del proxy
    on: {
        // Evento: Ocurre un error al conectar con el microservicio
        error: (err, req, res) => {
            console.error(`[Proxy ERROR] Petición ${req.method} ${req.originalUrl} a ${targetUrl}`);
            console.error(`[Proxy ERROR] Causa: ${err.message}`);
            // http-proxy-middleware ya envía una respuesta 500, aquí solo registramos el error.
        },

        // Evento: Se envía la petición al microservicio
        proxyReq: (proxyReq, req, res) => {
            console.log(`[Proxy -> Service] Redirigiendo ${req.method} ${req.originalUrl} hacia ${targetUrl}${proxyReq.path}`);
        },

        // Evento: Se recibe la respuesta del microservicio
        proxyRes: (proxyRes, req, res) => {
            console.log(`[Service -> Gateway] Respuesta de ${targetUrl}${req.originalUrl} | STATUS: ${proxyRes.statusCode}`);
        },
    },
});

// --- Reglas de Proxy (Usando la configuración con logs) ---
const services = [
    { route: '/auth', target: AUTH_SERVICE_URL },
    { route: '/restaurants', target: RESTAURANT_SERVICE_URL },
    { route: '/payments', target: PAYMENT_SERVICE_URL },
    { route: '/pac', target: PAC_SERVICE_URL },
    { route: '/pos', target: POS_SERVICE_URL },
];

services.forEach(({ route, target }) => {
    if (target) {
        app.use(route, createProxyMiddleware(createProxyOptions(target, route)));
        console.log(`[Proxy] Enrutando ${route} -> ${target}`);
    } else {
        console.warn(`[Proxy WARN] La URL para la ruta ${route} no está definida en .env. La ruta será ignorada.`);
    }
});


const PORT = process.env.API_GATEWAY_PORT || 8080;

app.listen(PORT, () => {
    console.log(`🚀 API Gateway profesional escuchando en el puerto ${PORT}`);
});