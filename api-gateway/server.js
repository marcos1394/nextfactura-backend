// --- api-gateway/server.js (Versión Profesional y Completa) ---

// Carga las variables de entorno desde un archivo .env al inicio
require('dotenv').config();

const express = require('express');
const cors = require('cors');
const { createProxyMiddleware, responseInterceptor } = require('http-proxy-middleware');

const app = express();

// --- Configuración de CORS ---
// Permite peticiones de cualquier origen. En un entorno de producción estricto,
// podrías configurar aquí una lista blanca de dominios permitidos.
app.use(cors());
app.use(express.json());


// --- Tabla de Enrutamiento de Microservicios ---
// Esta es la configuración definitiva que mapea prefijos de ruta a los microservicios de destino.
// Las URLs de destino se cargan desde variables de entorno para máxima flexibilidad
// entre entornos de desarrollo y producción (Render).
const services = [
    // Servicio de Autenticación: Gestiona usuarios, roles, registro, login y perfiles.
    {
        route: '/api/auth',
        target: process.env.AUTH_SERVICE_URL || 'http://localhost:3001'
    },
    {
        route: '/api/users', // Rutas relacionadas con la gestión del estado del usuario.
        target: process.env.AUTH_SERVICE_URL || 'http://localhost:3001'
    },
    // Servicio de Restaurantes: Gestiona restaurantes, portales, datos fiscales y configuración.
    {
        route: '/api/restaurants',
        target: process.env.RESTAURANT_SERVICE_URL || 'http://localhost:3002'
    },
    {
        route: '/api/portal',
        target: process.env.RESTAURANT_SERVICE_URL || 'http://localhost:3002'
    },
    // Servicio de Pagos: Gestiona planes, preferencias de Mercado Pago y webhooks de confirmación.
    {
        route: '/api/payment',
        target: process.env.PAYMENT_SERVICE_URL || 'http://localhost:3003'
    },
    // Servicio de POS: Gestiona la comunicación directa con los sistemas POS remotos.
    {
        route: '/api/pos',
        target: process.env.POS_SERVICE_URL || 'http://localhost:3004'
    }
];

// --- Configuración Dinámica del Proxy ---
console.log('[Gateway] Configurando rutas de microservicios...');

services.forEach(({ route, target }) => {
    // Opciones del proxy para esta ruta específica
    const proxyOptions = {
        target,
        changeOrigin: true, // Necesario para que el servicio de destino reciba correctamente el host
        pathRewrite: (path, req) => {
            // Re-escribe la ruta para que el microservicio no reciba el prefijo.
            // Ejemplo: una petición a /api/auth/login se convierte en /login para el auth-service.
            const newPath = path.replace(route, '');
            console.log(`[Gateway] Path Rewrite: ${path} -> ${newPath}`);
            return newPath === '' ? '/' : newPath; // Asegura que no enviemos una ruta vacía
        },
        on: {
            // Manejo de eventos del proxy para un logging robusto
            proxyReq: (proxyReq, req, res) => {
                console.log(`[Gateway] Petición -> ${req.method} ${req.originalUrl} | Redirigiendo a: ${target}${proxyReq.path}`);
                // Reenvía el body si existe
                if (req.body) {
                    const bodyData = JSON.stringify(req.body);
                    proxyReq.setHeader('Content-Type', 'application/json');
                    proxyReq.setHeader('Content-Length', Buffer.byteLength(bodyData));
                    proxyReq.write(bodyData);
                }
            },
            proxyRes: (proxyRes, req, res) => {
                console.log(`[Gateway] Respuesta <- ${req.method} ${req.originalUrl} | Estado: ${proxyRes.statusCode}`);
            },
            error: (err, req, res) => {
                console.error(`[Gateway] Error de Proxy: ${err.message} para la ruta ${req.originalUrl}`);
                if (!res.headersSent) {
                    res.status(503).json({ success: false, message: 'Servicio no disponible.', error: 'Proxy-Error' });
                }
            }
        }
    };

    // Aplica el middleware del proxy a la ruta correspondiente
    app.use(route, createProxyMiddleware(proxyOptions));
});

console.log('[Gateway] Todas las rutas de microservicios configuradas.');


// --- Endpoint de Estado del Propio Gateway ---
// Es una buena práctica tener un endpoint que confirme que el Gateway está vivo.
app.get('/api/gateway/health', (req, res) => {
    res.status(200).json({ 
        success: true, 
        message: 'API Gateway is operational.' 
    });
});

// --- Arranque del Servidor del Gateway ---
const PORT = process.env.PORT || 8080; // El Gateway suele correr en el puerto 80 u 8080
app.listen(PORT, () => {
    console.log(`🚀 API Gateway Profesional escuchando en el puerto ${PORT}`);
    console.log('Este es el único punto de entrada para todas las aplicaciones cliente.');
});
