require('dotenv').config();
const express = require('express');
const proxy = require('express-http-proxy');
const cors = require('cors');

const app = express();

app.use(cors());
app.use(express.json());

// --- URLs de los servicios de destino ---
const authServiceUrl = process.env.AUTH_SERVICE_URL;
const restaurantServiceUrl = process.env.RESTAURANT_SERVICE_URL;
const paymentServiceUrl = process.env.PAYMENT_SERVICE_URL;
const pacServiceUrl = process.env.PAC_SERVICE_URL;
const posServiceUrl = process.env.POS_SERVICE_URL;

console.log(`API Gateway (vDefinitiva) iniciando...`);

// --- Endpoints de la aplicación ---
app.get('/health', (req, res) => res.status(200).json({ status: 'ok' }));

// --- Reglas de Proxy ---
// Esta librería recorta el prefijo de la ruta por defecto.
// Petición a /auth/login -> Se reenvía como /login a authServiceUrl
// Petición a /restaurants -> Se reenvía como / a restaurantServiceUrl
// Petición a /restaurants/123 -> Se reenvía como /123 a restaurantServiceUrl

if (authServiceUrl) app.use('/auth', proxy(authServiceUrl));
if (restaurantServiceUrl) app.use('/restaurants', proxy(restaurantServiceUrl));
if (paymentServiceUrl) app.use('/payments', proxy(paymentServiceUrl));
if (pacServiceUrl) app.use('/pac', proxy(pacServiceUrl));
if (posServiceUrl) app.use('/pos', proxy(posServiceUrl));

const PORT = process.env.PORT || 10000;
app.listen(PORT, () => {
    console.log(`🚀 API Gateway (vDefinitiva) escuchando en el puerto ${PORT}`);
});