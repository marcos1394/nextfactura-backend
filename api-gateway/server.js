require('dotenv').config();
const express = require('express');
const { createProxyMiddleware } = require('http-proxy-middleware');
const cors = require('cors');

const app = express();

app.use(cors());
app.use(express.json());

// --- Obtener las URLs de los microservicios ---
const authServiceUrl = process.env.AUTH_SERVICE_URL;
const restaurantServiceUrl = process.env.RESTAURANT_SERVICE_URL;
const paymentServiceUrl = process.env.PAYMENT_SERVICE_URL;
const posServiceUrl = process.env.POS_SERVICE_URL;
const pacServiceUrl = process.env.PAC_SERVICE_URL;

// --- Endpoint de Healthcheck ---
app.get('/health', (req, res) => {
    res.status(200).json({ status: 'ok', service: 'api-gateway' });
});

// --- Configuración de las Reglas de Proxy (Versión Final y Robusta) ---
console.log('--- Configurando Proxies ---');

// Función para loguear errores del proxy
const onProxyError = (err, req, res) => {
    console.error(`[Proxy Error] para ${req.path}:`, err.message);
    res.status(502).send('Bad Gateway');
};

// Función para loguear la petición que se va a hacer
const onProxyReq = (proxyReq, req, res) => {
    console.log(`[Gateway] Redirigiendo ${req.method} ${req.path} a -> ${proxyReq.host}${proxyReq.path}`);
};

// Regla para AUTH: Necesita que le quitemos el prefijo /auth
if (authServiceUrl) {
    console.log(`- Ruta: /auth -> Target: ${authServiceUrl} (con reescritura de ruta)`);
    app.use('/auth', createProxyMiddleware({
        target: authServiceUrl,
        changeOrigin: true,
        pathRewrite: { '^/auth': '' }, // Reescribe /auth/register a /register
        onProxyError,
        onProxyReq
    }));
}

// Regla para RESTAURANTS: El servicio espera la ruta completa /restaurants
if (restaurantServiceUrl) {
    console.log(`- Ruta: /restaurants -> Target: ${restaurantServiceUrl} (sin reescritura de ruta)`);
    // No usamos pathRewrite porque el servicio de restaurantes ya espera /restaurants
    app.use('/restaurants', createProxyMiddleware({ 
        target: restaurantServiceUrl, 
        changeOrigin: true,
        onProxyError,
        onProxyReq
    }));
}

// Añade aquí las reglas para los otros servicios, siguiendo el patrón que necesiten
// Probablemente tampoco necesiten pathRewrite
if (paymentServiceUrl) app.use('/payments', createProxyMiddleware({ target: paymentServiceUrl, changeOrigin: true, onProxyError, onProxyReq }));
if (posServiceUrl) app.use('/pos', createProxyMiddleware({ target: posServiceUrl, changeOrigin: true, onProxyError, onProxyReq }));
if (pacServiceUrl) app.use('/pac', createProxyMiddleware({ target: pacServiceUrl, changeOrigin: true, onProxyError, onProxyReq }));

console.log('--------------------------');


// --- Arranque del Servidor ---
const PORT = process.env.PORT || 10000;
app.listen(PORT, () => {
    console.log(`🚀 API Gateway (v4 - Lógica Final) escuchando en el puerto ${PORT}`);
});