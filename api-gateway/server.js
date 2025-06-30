require('dotenv').config();
const express = require('express');
const { createProxyMiddleware } = require('http-proxy-middleware');
const cors = require('cors');

const app = express();

app.use(cors());
app.use(express.json());

// --- Obtener las URLs de los microservicios desde las variables de entorno ---
const authServiceUrl = process.env.AUTH_SERVICE_URL;
const restaurantServiceUrl = process.env.RESTAURANT_SERVICE_URL;
const paymentServiceUrl = process.env.PAYMENT_SERVICE_URL;
const posServiceUrl = process.env.POS_SERVICE_URL;
const pacServiceUrl = process.env.PAC_SERVICE_URL;

console.log(`Auth Service URL: ${authServiceUrl}`);
console.log(`Restaurant Service URL: ${restaurantServiceUrl}`);

// --- Endpoint de Healthcheck para el propio Gateway ---
app.get('/health', (req, res) => {
    res.status(200).json({ status: 'ok', service: 'api-gateway' });
});

// --- Configuración de las Reglas de Proxy (VERSIÓN CORREGIDA) ---

// Función para loguear los errores del proxy
const onProxyError = (err, req, res) => {
    console.error('Proxy Error:', err);
    res.status(500).send('Proxy Error');
};

// Si la petición empieza con /auth, reenvíala a auth-service
if (authServiceUrl) {
    app.use('/auth', createProxyMiddleware({
        target: authServiceUrl,
        changeOrigin: true,
        pathRewrite: {
            '^/auth': '', // IMPORTANTE: Reescribe /auth/register a /register
        },
        onError: onProxyError,
    }));
}

// Para los demás servicios, que esperan la ruta completa (ej. /restaurants)
// No necesitamos reescribir la ruta, el comportamiento por defecto funciona.
if (restaurantServiceUrl) app.use('/restaurants', createProxyMiddleware({ target: restaurantServiceUrl, changeOrigin: true, onError: onProxyError }));
if (paymentServiceUrl) app.use('/payments', createProxyMiddleware({ target: paymentServiceUrl, changeOrigin: true, onError: onProxyError }));
if (posServiceUrl) app.use('/pos', createProxyMiddleware({ target: posServiceUrl, changeOrigin: true, onError: onProxyError }));
if (pacServiceUrl) app.use('/pac', createProxyMiddleware({ target: pacServiceUrl, changeOrigin: true, onError: onProxyError }));


// --- Arranque del Servidor ---
const PORT = process.env.PORT || 10000;
app.listen(PORT, () => {
    console.log(`🚀 API Gateway (v3 - Corregido) escuchando en el puerto ${PORT}`);
});