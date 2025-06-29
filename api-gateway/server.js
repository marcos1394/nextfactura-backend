require('dotenv').config();
const express = require('express');
const proxy = require('express-http-proxy');
const cors = require('cors');

const app = express();

app.use(cors());
app.use(express.json());

// --- Obtener las URLs de los microservicios desde las variables de entorno ---
// (Estas son las que configuraste en el panel de Environment de Render)
const authServiceUrl = process.env.AUTH_SERVICE_URL;
const restaurantServiceUrl = process.env.RESTAURANT_SERVICE_URL;
const paymentServiceUrl = process.env.PAYMENT_SERVICE_URL;
const posServiceUrl = process.env.POS_SERVICE_URL;
const pacServiceUrl = process.env.PAC_SERVICE_URL;

// Imprimimos las URLs al iniciar para verificar que se cargaron bien
console.log(`Redirigiendo a AUTH_SERVICE: ${authServiceUrl}`);
console.log(`Redirigiendo a RESTAURANT_SERVICE: ${restaurantServiceUrl}`);
// ... puedes añadir logs para las otras si quieres

// --- Endpoint de Healthcheck para el propio Gateway ---
app.get('/health', (req, res) => {
    res.status(200).json({ status: 'ok', service: 'api-gateway' });
});

// --- Configuración de las Reglas de Proxy ---
// Aquí está la magia. Cada línea es una regla de enrutamiento.

// Si la petición empieza con /auth, reenvíala a auth-service
app.use('/auth', proxy(authServiceUrl));

// Si la petición empieza con /restaurants, reenvíala a restaurant-service
app.use('/restaurants', proxy(restaurantServiceUrl));

// Si la petición empieza con /payments, reenvíala a payment-service
app.use('/payments', proxy(paymentServiceUrl));

// Si la petición empieza con /pos, reenvíala a pos-service
app.use('/pos', proxy(posServiceUrl));

// Si la petición empieza con /pac, reenvíala a pac-service
app.use('/pac', proxy(pacServiceUrl));


// --- Arranque del Servidor ---
const PORT = process.env.PORT || 10000; // Render usa el PORT que te asigna
app.listen(PORT, () => {
    console.log(`🚀 API Gateway funcional escuchando en el puerto ${PORT}`);
});