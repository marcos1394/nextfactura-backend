require('dotenv').config();
const express = require('express');
const proxy = require('express-http-proxy'); // Usando la librería original
const cors = require('cors');

const app = express();

app.use(cors());
app.use(express.json());

const authServiceUrl = process.env.AUTH_SERVICE_URL;

console.log(`API Gateway (v1 - Clásico) iniciando...`);
console.log(`Redirigiendo /auth a: ${authServiceUrl}`);

// --- Endpoint de Healthcheck ---
app.get('/health', (req, res) => {
    res.status(200).json({ status: 'ok', service: 'api-gateway' });
});

// --- ÚNICA REGLA DE PROXY: SOLO PARA AUTH ---
// Esta es la regla que SÍ funcionaba. Recuerda que le quita el '/auth' a la ruta.
if (authServiceUrl) {
    app.use('/auth', proxy(authServiceUrl));
} else {
    console.error("ADVERTENCIA: AUTH_SERVICE_URL no está definida.");
}

const PORT = process.env.PORT || 10000;
app.listen(PORT, () => {
    console.log(`🚀 API Gateway (v1 - Clásico) escuchando en el puerto ${PORT}`);
});