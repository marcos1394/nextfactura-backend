require('dotenv').config();
const express = require('express');
const { createProxyMiddleware } = require('http-proxy-middleware');
const cors = require('cors');

const app = express();
app.use(cors());
app.use(express.json());

const authServiceUrl = process.env.AUTH_SERVICE_URL;
const restaurantServiceUrl = process.env.RESTAURANT_SERVICE_URL;
// ... define las otras URLs de servicios aquí

console.log(`API Gateway iniciando...`);
console.log(`AUTH_SERVICE_URL: ${authServiceUrl}`);
console.log(`RESTAURANT_SERVICE_URL: ${restaurantServiceUrl}`);

app.get('/health', (req, res) => res.status(200).json({ status: 'ok' }));

// Middleware para loguear errores del proxy
const onProxyError = (err, req, res) => {
    console.error(`Error en el Proxy para ${req.path}:`, err.message);
    res.status(502).send('Bad Gateway: No se pudo comunicar con el servicio de destino.');
};

// Regla para AUTH: Necesita que quitemos el prefijo /auth
if (authServiceUrl) {
    app.use('/auth', createProxyMiddleware({
        target: authServiceUrl,
        changeOrigin: true,
        pathRewrite: { '^/auth': '' }, // Reescribe /auth/register a /register
        onError: onProxyError
    }));
}

// Regla para RESTAURANTS: El servicio espera la ruta completa /restaurants
if (restaurantServiceUrl) {
    app.use('/restaurants', createProxyMiddleware({
        target: restaurantServiceUrl,
        changeOrigin: true,
        onError: onProxyError
        // No necesita pathRewrite
    }));
}

// ... añade las reglas para los otros servicios aquí ...

const PORT = process.env.PORT || 10000;
app.listen(PORT, () => {
    console.log(`🚀 API Gateway (Versión Final) escuchando en el puerto ${PORT}`);
});