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

console.log(`Auth Service URL: ${authServiceUrl}`);
console.log(`Restaurant Service URL: ${restaurantServiceUrl}`);

// --- Endpoint de Healthcheck ---
app.get('/health', (req, res) => {
    res.status(200).json({ status: 'ok', service: 'api-gateway' });
});

// --- Configuración de las Reglas de Proxy ---
// Esta librería SÍ reenvía la ruta completa, que es lo que tus servicios esperan.
// Por ejemplo, una petición a /restaurants se reenvía como /restaurants al servicio de destino.

if (authServiceUrl) app.use('/auth', createProxyMiddleware({ target: authServiceUrl, changeOrigin: true }));
if (restaurantServiceUrl) app.use('/restaurants', createProxyMiddleware({ target: restaurantServiceUrl, changeOrigin: true }));
if (paymentServiceUrl) app.use('/payments', createProxyMiddleware({ target: paymentServiceUrl, changeOrigin: true }));
if (posServiceUrl) app.use('/pos', createProxyMiddleware({ target: posServiceUrl, changeOrigin: true }));
if (pacServiceUrl) app.use('/pac', createProxyMiddleware({ target: pacServiceUrl, changeOrigin: true }));

// --- Arranque del Servidor ---
const PORT = process.env.PORT || 10000;
app.listen(PORT, () => {
    console.log(`🚀 API Gateway (v2 - http-proxy-middleware) escuchando en el puerto ${PORT}`);
});