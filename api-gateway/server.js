// api-gateway/server.js (Versión Profesional y Completa)
require('dotenv').config();
const express = require('express');
const cors = require('cors');
const { createProxyMiddleware } = require('http-proxy-middleware');

const app = express();

// Middlewares estándar
app.use(cors());
app.use(express.json());

// --- URLs de los microservicios (leídas desde .env) ---
const AUTH_SERVICE_URL = process.env.AUTH_SERVICE_URL;
const RESTAURANT_SERVICE_URL = process.env.RESTAURANT_SERVICE_URL;
const PAYMENT_SERVICE_URL = process.env.PAYMENT_SERVICE_URL;
const PAC_SERVICE_URL = process.env.PAC_SERVICE_URL;
const POS_SERVICE_URL = process.env.POS_SERVICE_URL;

console.log('API Gateway (vProfesional) iniciando...');

// Endpoint de salud para que Docker sepa que está vivo
app.get('/health', (req, res) => res.status(200).json({ status: 'ok' }));

// --- Reglas de Proxy ---
// Se crea una regla de proxy solo si la URL del servicio está definida en .env
if (AUTH_SERVICE_URL) {
  app.use('/auth', createProxyMiddleware({
    target: AUTH_SERVICE_URL,
    changeOrigin: true,
    // Reescribimos la ruta: una petición a /api/auth/login se convierte en /login
    // para el auth-service, que es lo que espera tu backend.
    pathRewrite: {
      [`^/auth`]: '',
    },
  }));
  console.log(`[Proxy] Enrutando /auth -> ${AUTH_SERVICE_URL}`);
}

if (RESTAURANT_SERVICE_URL) {
  app.use('/restaurants', createProxyMiddleware({
    target: RESTAURANT_SERVICE_URL,
    changeOrigin: true,
    pathRewrite: {
      [`^/restaurants`]: '',
    },
  }));
  console.log(`[Proxy] Enrutando /restaurants -> ${RESTAURANT_SERVICE_URL}`);
}

if (PAYMENT_SERVICE_URL) {
  app.use('/payments', createProxyMiddleware({
    target: PAYMENT_SERVICE_URL,
    changeOrigin: true,
    pathRewrite: {
      [`^/payments`]: '',
    },
  }));
  console.log(`[Proxy] Enrutando /payments -> ${PAYMENT_SERVICE_URL}`);
}

if (PAC_SERVICE_URL) {
  app.use('/pac', createProxyMiddleware({
    target: PAC_SERVICE_URL,
    changeOrigin: true,
    pathRewrite: {
      [`^/pac`]: '',
    },
  }));
  console.log(`[Proxy] Enrutando /pac -> ${PAC_SERVICE_URL}`);
}

if (POS_SERVICE_URL) {
  app.use('/pos', createProxyMiddleware({
    target: POS_SERVICE_URL,
    changeOrigin: true,
    pathRewrite: {
      [`^/pos`]: '',
    },
  }));
  console.log(`[Proxy] Enrutando /pos -> ${POS_SERVICE_URL}`);
}

// El puerto se define en el Dockerfile o aquí, pero tu log decía 10000, así que lo respetamos.
const PORT = process.env.API_GATEWAY_PORT || 8080;

app.listen(PORT, () => {
  console.log(`🚀 API Gateway profesional escuchando en el puerto ${PORT}`);
});