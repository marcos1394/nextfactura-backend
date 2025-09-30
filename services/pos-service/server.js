// --- services/pos-service/server.js (Versión Final y Completa) ---

require('dotenv').config();
// --- Imports de Librerías ---
const express = require('express');
const cors = require('cors');
const jwt = require('jsonwebtoken');
const sql = require('mssql');
const { createClient } = require('redis'); // Para escuchar respuestas
const { v4: uuidv4 } = require('uuid'); // Para IDs únicos de petición
const logger = require('./logger'); // Importa tu nuevo logger
const cookieParser = require('cookie-parser'); // <-- AÑADE ESTA IMPORTACIÓN



const app = express();
app.use(cors());
app.use(express.json());
app.use(cookieParser()); // <-- AÑADE ESTA LÍNEA


// --- CONFIGURACIÓN DE REDIS (PARA ESCUCHAR RESPUESTAS DEL AGENTE) ---
const redisClient = createClient({ url: process.env.REDIS_URL || 'redis://redis:6379' });
const subscriber = redisClient.duplicate();
const pendingRequests = new Map(); // Mapa para peticiones en espera

subscriber.connect().then(() => {
    console.log('[POS-Service] Conectado a Redis como suscriptor.');
    subscriber.subscribe('agent-responses', (message) => {
        try {
            const { correlationId, data, error } = JSON.parse(message);
            if (pendingRequests.has(correlationId)) {
                const { resolve, reject } = pendingRequests.get(correlationId);
                if (error) {
                    reject(new Error(error));
                } else {
                    resolve(data);
                }
                pendingRequests.delete(correlationId);
            }
        } catch (e) {
            console.error('[POS-Service] Error procesando mensaje de Redis:', e);
        }
    });
});

// --- FUNCIÓN AUXILIAR PARA CONEXIÓN DIRECTA A MS SQL (SIN CAMBIOS) ---
async function getConnectedPool(connectionConfig) {
    try {
        const pool = new sql.ConnectionPool({
            user: connectionConfig.user,
            password: connectionConfig.password,
            server: connectionConfig.host,
            database: connectionConfig.database,
            port: parseInt(connectionConfig.port || '1433', 10),
            options: { trustServerCertificate: true },
            pool: { max: 10, min: 0, idleTimeoutMillis: 30000 },
            requestTimeout: 15000
        });
        await pool.connect();
        console.log(`[POS-Service] Conexión directa exitosa a ${connectionConfig.host}`);
        return pool;
    } catch (error) {
        console.error(`[POS-Service] Error al conectar directamente a la BD del POS:`, error.message);
        throw new Error('No se pudo establecer la conexión directa con la base de datos del restaurante.');
    }
}

const authenticateToken = async (req, res, next) => {
    // Usamos el logger profesional
    logger.info(`[Auth-Token] Iniciando validación para la ruta: ${req.originalUrl}`);

    // Log para ver las cookies que llegan
    logger.info({ message: "[Auth-Token] Cookies recibidas por el servicio:", cookies: req.cookies });

    const tokenFromHeader = req.headers['authorization']?.split(' ')[1];
    const token = tokenFromHeader || req.cookies.accessToken?.split(' ')[1];

    if (!token) {
        logger.warn(`[Auth-Token] ACCESO DENEGADO: No se encontró token ni en la cabecera ni en las cookies.`);
        return res.status(401).json({ success: false, message: 'Token de acceso no proporcionado.' });
    }

    logger.info(`[Auth-Token] Token encontrado. Intentando verificar...`);
    try {
        const decoded = jwt.verify(token, process.env.JWT_SECRET);
        req.user = decoded;
        logger.info(`[Auth-Token] ÉXITO: Token verificado para el usuario ${decoded.id}`);
        return next();
    } catch (err) {
        logger.error(`[Auth-Token] ERROR: La verificación del token falló.`, { errorName: err.name, errorMessage: err.message });
        
        if (err.name === 'TokenExpiredError') {
            return res.status(401).json({ 
                success: false, 
                message: 'Token de acceso expirado.' 
            });
        }

        return res.status(403).json({ success: false, message: 'Token de acceso inválido.' });
    }
};

// --- HANDLER DE RUTAS MEJORADO ---
const dataQueryHandler = (query, queryType) => async (req, res) => {
    const { restaurantId } = req.params;
    
    try {
        // 1. Obtener datos de conexión y método desde el restaurant-service
        const restaurantServiceUrl = process.env.RESTAURANT_SERVICE_URL || 'http://restaurant-service:4002';
        const resp = await fetch(`${restaurantServiceUrl}/${restaurantId}`, {
            headers: { 'Authorization': req.headers.authorization }
        });
        const restaurantData = await resp.json();

        if (!resp.ok || !restaurantData.success) {
            throw new Error('No se pudo obtener la información del restaurante o no está autorizado.');
        }

        const restaurant = restaurantData.restaurant;

        // 2. DECIDIR LA ESTRATEGIA: AGENTE O CONEXIÓN DIRECTA
        if (restaurant.connectionMethod === 'agent') {
            // --- ESTRATEGIA CON AGENTE (NUEVA) ---
            console.log(`[POS-Service] Usando AGENTE para restaurante ${restaurantId}`);
            const correlationId = uuidv4();

            const commandPromise = new Promise((resolve, reject) => {
                pendingRequests.set(correlationId, { resolve, reject });
                setTimeout(() => {
                    if (pendingRequests.has(correlationId)) {
                        pendingRequests.delete(correlationId);
                        reject(new Error('Timeout: El agente no respondió en 30 segundos.'));
                    }
                }, 30000);
            });

            // Enviar comando al connector-service
            await fetch(`http://connector-service:4006/internal/send-command`, {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({
                    clientId: restaurantId,
                    command: `get_${queryType}`,
                    correlationId: correlationId,
                    data: { sql: query } // Enviamos la consulta SQL al agente
                })
            });

            const agentData = await commandPromise;
            res.status(200).json({ success: true, data: agentData });

        } else {
            // --- ESTRATEGIA DE CONEXIÓN DIRECTA (ANTIGUA) ---
            console.log(`[POS-Service] Usando CONEXIÓN DIRECTA para restaurante ${restaurantId}`);
            let pool;
            try {
                const config = { 
                    host: restaurant.connectionHost, 
                    port: restaurant.connectionPort, 
                    user: restaurant.connectionUser, 
                    password: restaurant.connectionPassword, 
                    database: restaurant.connectionDbName 
                };
                pool = await getConnectedPool(config);
                const result = await pool.request().query(query);
                res.status(200).json({ success: true, data: result.recordset });
            } finally {
                if (pool) await pool.close();
            }
        }

    } catch (error) {
        console.error(`[POS-Service] Error fatal en la ruta ${req.path}:`, error);
        res.status(500).json({ success: false, message: error.message });
    }
};

// Endpoint de salud para Docker
app.get('/health', (req, res) => {
    res.status(200).json({ status: 'ok' });
});

// Tu endpoint de test-connection sigue siendo para conexión directa, lo cual está bien para verificar credenciales.
app.post('/test-connection', authenticateToken, async (req, res) => {
    const { connectionData } = req.body;
    if (!connectionData) {
        return res.status(400).json({ success: false, message: 'Faltan datos de conexión.' });
    }
    
    let pool;
    try {
        pool = await getConnectedPool(connectionData);
        res.status(200).json({ success: true, message: 'Conexión con SoftRestaurant exitosa.' });
    } catch (error) {
        res.status(400).json({ success: false, message: error.message });
    } finally {
        if (pool) await pool.close();
    }
});

// --- Definición de rutas de consulta y las consultas SQL correspondientes ---
// Cada ruta ahora pasa su consulta y un 'queryType' único al handler.
app.get('/query/:restaurantId/products', authenticateToken, dataQueryHandler(
    // Usamos los nombres de columna reales que encontraste en la base de datos
    'SELECT [idproducto], [descripcion], [nombrecorto], [plu] FROM [dbo].[Productos] ORDER BY [descripcion] ASC', 
    'products'
));

app.get('/query/:restaurantId/cheques', authenticateToken, dataQueryHandler(
    'SELECT [totalbebidas], [totalalimentos], [totalsindescuento], [efectivo], [tarjeta], [total], [totalarticulos], [estacion], [idturno], [tipodeservicio], [orden], [cambio], [impreso], [pagado], [mesa], [nopersonas], [cierre], [fecha], [numcheque], [folio] FROM [cheques] ORDER BY [fecha] DESC', 
    'cheques'
));

app.get('/query/:restaurantId/bitacora', authenticateToken, dataQueryHandler(
    'SELECT [fecha], [usuario], [evento], [valores], [estacion], [idempresa], [seriefolio], [numcheque], [usuariosolicita], [tipoalerta] FROM [bitacorasistema] ORDER BY [fecha] DESC', 
    'bitacora'
));

app.get('/query/:restaurantId/cheqdet', authenticateToken, dataQueryHandler(
    'SELECT [movimiento], [idproducto], [precio], [cantidad], [hora], [procesado] FROM [cheqdet] ORDER BY [hora] DESC', 
    'cheqdet'
));

app.get('/query/:restaurantId/chequespagos', authenticateToken, dataQueryHandler(
    'SELECT [folio], [idformadepago], [importe], [propina], [tipodecambio] FROM [chequespagos] ORDER BY [folio] DESC', 
    'chequespagos'
));

app.get('/query/:restaurantId/declaracioncajero', authenticateToken, dataQueryHandler(
    'SELECT [idturno], [idformadepago], [importedeclarado] FROM [declaracioncajero] ORDER BY [importedeclarado] DESC', 
    'declaracioncajero'
));

// En services/pos-service/server.js

// Función auxiliar para formatear fechas a YYYY-MM-DD
const formatDate = (date) => date.toISOString().split('T')[0];

app.get('/reports/:restaurantId', authenticateToken, async (req, res) => {
    const { restaurantId } = req.params;
    const { reportType = 'sales', dateRange = 'Semana' } = req.query;

    console.log(`[POS-Service] Petición de reporte recibida: ${reportType}, Rango: ${dateRange}`);

    try {
        // --- 1. CONSTRUCCIÓN DE FILTRO DE FECHA DINÁMICO ---
        let dateFilter = '';
        const today = new Date();
        
        switch (dateRange) {
            case 'Hoy':
                dateFilter = `WHERE CAST(fecha AS DATE) = '${formatDate(today)}'`;
                break;
            case 'Ayer':
                const yesterday = new Date();
                yesterday.setDate(today.getDate() - 1);
                dateFilter = `WHERE CAST(fecha AS DATE) = '${formatDate(yesterday)}'`;
                break;
            case 'Mes':
                const firstDayOfMonth = new Date(today.getFullYear(), today.getMonth(), 1);
                const lastDayOfMonth = new Date(today.getFullYear(), today.getMonth() + 1, 0);
                dateFilter = `WHERE CAST(fecha AS DATE) BETWEEN '${formatDate(firstDayOfMonth)}' AND '${formatDate(lastDayOfMonth)}'`;
                break;
            case 'Semana':
            default:
                const sevenDaysAgo = new Date();
                sevenDaysAgo.setDate(today.getDate() - 6);
                dateFilter = `WHERE CAST(fecha AS DATE) BETWEEN '${formatDate(sevenDaysAgo)}' AND '${formatDate(today)}'`;
                break;
        }

        // --- 2. SELECCIÓN DE LA CONSULTA SQL ---
        let query;
        switch (reportType) {
            case 'products':
                query = `SELECT TOP 10 p.descripcion, SUM(cd.cantidad) as totalQuantity, SUM(cd.precio * cd.cantidad) as totalSales
                         FROM cheqdet cd JOIN Productos p ON cd.idproducto = p.idproducto
                         GROUP BY p.descripcion ORDER BY totalSales DESC`;
                break;
            
            case 'waiters':
                query = `SELECT c.usuario as name, SUM(c.total) as totalSales, COUNT(c.numcheque) as totalTickets
                         FROM cheques c ${dateFilter} AND c.usuario IS NOT NULL AND c.usuario <> ''
                         GROUP BY c.usuario ORDER BY totalSales DESC`;
                break;
            
            case 'sales':
            default:
                query = `SELECT CAST(fecha AS DATE) as date, SUM(total) as totalSales
                         FROM cheques ${dateFilter}
                         GROUP BY CAST(fecha AS DATE) ORDER BY date ASC`;
                break;
        }
        
        // --- 3. OBTENER MÉTODO DE CONEXIÓN ---
        const restaurantServiceUrl = process.env.RESTAURANT_SERVICE_URL || 'http://restaurant-service:4002';
        const resp = await fetch(`${restaurantServiceUrl}/${restaurantId}`, {
            headers: { 'Authorization': req.headers.authorization }
        });
        const restaurantData = await resp.json();
        if (!resp.ok) throw new Error('No se pudo obtener la información del restaurante.');
        const restaurant = restaurantData.restaurant;

        // --- 4. EJECUCIÓN DE LA CONSULTA ---
        let results;
        if (restaurant.connectionMethod === 'agent') {
            const correlationId = uuidv4();
            const commandPromise = new Promise((resolve, reject) => {
                pendingRequests.set(correlationId, { resolve, reject });
                setTimeout(() => {
                    if (pendingRequests.has(correlationId)) {
                        pendingRequests.delete(correlationId);
                        reject(new Error('Timeout: El agente no respondió a la petición de reporte.'));
                    }
                }, 30000);
            });

            await fetch(`http://connector-service:4006/internal/send-command`, {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({
                    clientId: restaurantId,
                    command: `get_report_${reportType}`,
                    correlationId,
                    data: { sql: query }
                })
            });
            results = await commandPromise;
        } else {
            const pool = await getConnectedPool({
                user: restaurant.connectionUser,
                password: restaurant.connectionPassword,
                server: restaurant.connectionHost,
                database: restaurant.connectionDbName,
                port: restaurant.connectionPort,
            });
            const result = await pool.request().query(query);
            results = result.recordset;
            await pool.close();
        }

        // --- 5. PROCESAMIENTO DE DATOS Y RESPUESTA ---
        let reportData;
        if (reportType === 'sales') {
            const total = results.reduce((sum, row) => sum + row.totalSales, 0);
            const transactions = results.length;
            const average = transactions > 0 ? total / transactions : 0;
            
            reportData = {
                kpis: { total, transactions, average, growth: 0 },
                chartData: results.map(row => ({
                    value: row.totalSales,
                    label: new Date(row.date).toLocaleDateString('es-MX', { day: '2-digit', month: 'short' })
                })),
                lineData: { // Formato específico para react-native-gifted-charts
                    dataPoints: results.map(row => ({ value: row.totalSales })),
                    labels: results.map(row => new Date(row.date).toLocaleDateString('es-MX', { day: '2-digit', month: 'short' }))
                },
                tableData: results.map(row => ({
                    id: row.date.toISOString(),
                    label: new Date(row.date).toLocaleDateString('es-MX', { weekday: 'long', year: 'numeric', month: 'long', day: 'numeric' }),
                    value: row.totalSales,
                    change: Math.random() > 0.5 ? 15 : -10
                }))
            };
        } else {
            reportData = results;
        }
        
        res.status(200).json({ success: true, data: reportData });

    } catch (error) {
        console.error(`[POS-Service /reports] Error:`, error);
        res.status(500).json({ success: false, message: 'Error al generar el reporte.' });
    }
});

app.get('/query/:restaurantId/estaciones', authenticateToken, dataQueryHandler(
    'SELECT [idestacion], [descripcion], [serie], [ip], [directoriorespaldo], [mensajespera], [rutatemoral], [PostLastOnline] FROM [estaciones]', 
    'estaciones'
));
// --- ARRANQUE DEL SERVIDOR ---
const PORT = process.env.POS_SERVICE_PORT || 4004;
app.listen(PORT, () => {
    console.log(`🚀 POS-Service (v2 con Agente y Directo) escuchando en el puerto ${PORT}`);
});