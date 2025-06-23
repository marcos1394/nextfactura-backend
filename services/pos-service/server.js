// --- services/pos-service/server.js (Versión Profesional y Completa) ---

require('dotenv').config();

// --- Imports de Librerías ---
const express = require('express');
const cors = require('cors');
const jwt = require('jsonwebtoken');
const sql = require('mssql');
const fetch = require('node-fetch');

const app = express();
app.use(cors());
app.use(express.json());

// --- Función Auxiliar para la Conexión a MS SQL ---
// Crea y gestiona un pool de conexiones para una consulta específica.
async function getConnectedPool(connectionConfig) {
    try {
        const pool = new sql.ConnectionPool({
            user: connectionConfig.user,
            password: connectionConfig.password,
            server: connectionConfig.host,
            database: connectionConfig.database,
            port: parseInt(connectionConfig.port || '1433', 10),
            options: {
                trustServerCertificate: true, // Necesario para conexiones a SQL Server sin un certificado validado
            },
            pool: {
                max: 10,
                min: 0,
                idleTimeoutMillis: 30000
            },
            requestTimeout: 15000 // Timeout de 15 segundos por petición
        });
        
        await pool.connect();
        console.log(`[POS-Service] Conexión exitosa a ${connectionConfig.host}`);
        return pool;
    } catch (error) {
        console.error(`[POS-Service] Error al conectar a la BD del POS:`, error);
        throw new Error('No se pudo establecer la conexión con la base de datos del restaurante.');
    }
}

// --- Middleware de Autenticación ---
const authenticateToken = (req, res, next) => {
    const authHeader = req.headers['authorization'];
    const token = authHeader && authHeader.split(' ')[1];
    if (!token) return res.status(401).json({ success: false, message: 'Token no proporcionado.' });
    try {
        req.user = jwt.verify(token, process.env.JWT_SECRET);
        next();
    } catch (err) {
        res.status(403).json({ success: false, message: 'Token inválido.' });
    }
};

// --- Rutas del Servicio de POS ---

// POST /test-connection - Endpoint para validar credenciales de conexión al POS.
// Este endpoint es llamado por el `restaurant-service`.
app.post('/test-connection', async (req, res) => {
    const { connectionData } = req.body;
    if (!connectionData) {
        return res.status(400).json({ success: false, message: 'Faltan datos de conexión.' });
    }
    
    let pool;
    try {
        pool = await getConnectedPool(connectionData);
        await pool.close(); // Cerramos la conexión inmediatamente si fue exitosa.
        res.status(200).json({ success: true, message: 'Conexión con SoftRestaurant exitosa.' });
    } catch (error) {
        if (pool) await pool.close();
        res.status(400).json({ success: false, message: error.message });
    }
});

// --- Endpoints de Consulta de Datos ---
// Estos endpoints obtienen la configuración del restaurante y luego ejecutan la consulta.

const dataQueryHandler = (query) => async (req, res) => {
    const { restaurantId } = req.params;
    
    let pool;
    try {
        // 1. Obtener datos de conexión desde el restaurant-service
        const restaurantServiceUrl = process.env.RESTAURANT_SERVICE_URL;
        const resp = await fetch(`${restaurantServiceUrl}/restaurants/${restaurantId}`, {
            headers: { 'Authorization': req.headers.authorization }
        });
        const restaurantData = await resp.json();
        if (!resp.ok || !restaurantData.success) {
            throw new Error('No se pudo obtener la información del restaurante o no está autorizado.');
        }

        const { connectionHost, connectionPort, connectionUser, connectionPassword, connectionDbName } = restaurantData.restaurant;
        const connectionConfig = { host: connectionHost, port: connectionPort, user: connectionUser, password: connectionPassword, database: connectionDbName };

        // 2. Conectar al POS del cliente
        pool = await getConnectedPool(connectionConfig);

        // 3. Ejecutar la consulta específica
        const result = await pool.request().query(query);
        await pool.close();
        
        res.status(200).json({ success: true, data: result.recordset });

    } catch (error) {
        if (pool) await pool.close();
        console.error(`[POS-Service] Error en la ruta ${req.path}:`, error);
        res.status(500).json({ success: false, message: error.message });
    }
};

// Se definen las rutas y las consultas SQL correspondientes
app.get('/query/:restaurantId/products', authenticateToken, dataQueryHandler('SELECT [id], [Code], [Name], [StartDate], [EndDate], [HasTransferredTax], [HasTransferredIEPS], [Complement] FROM [products] ORDER BY [id] ASC'));
app.get('/query/:restaurantId/cheques', authenticateToken, dataQueryHandler('SELECT [totalbebidas], [totalalimentos], [totalsindescuento], [efectivo], [tarjeta], [total], [totalarticulos], [estacion], [idturno], [tipodeservicio], [orden], [cambio], [impreso], [pagado], [mesa], [nopersonas], [cierre], [fecha], [numcheque], [folio] FROM [cheques] ORDER BY [fecha] DESC'));
app.get('/query/:restaurantId/bitacora', authenticateToken, dataQueryHandler('SELECT [fecha], [usuario], [evento], [valores], [estacion], [idempresa], [seriefolio], [numcheque], [usuariosolicita], [tipoalerta] FROM [bitacorasistema] ORDER BY [fecha] DESC'));
// ... Añadir aquí el resto de las rutas de consulta (cheqdet, chequespagos, etc.) ...


// --- Arranque del Servidor ---
const PORT = process.env.POS_SERVICE_PORT || 3004;
app.listen(PORT, () => {
    console.log(`🚀 POS-Service profesional escuchando en el puerto ${PORT}`);
});
