// --- services/pos-service/server.js (Versión Final y Completa) ---

require('dotenv').config();
// --- Imports de Librerías ---
const express = require('express');
const cors = require('cors');
const jwt = require('jsonwebtoken');
const sql = require('mssql');
const { createClient } = require('redis'); // Para escuchar respuestas
const { v4: uuidv4 } = require('uuid'); // Para IDs únicos de petición

const app = express();
app.use(cors());
app.use(express.json());

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

// --- MIDDLEWARE DE AUTENTICACIÓN (SIN CAMBIOS) ---
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

// --- HANDLER DE RUTAS MEJORADO ---
const dataQueryHandler = (query, queryType) => async (req, res) => {
    const { restaurantId } = req.params;
    
    try {
        // 1. Obtener datos de conexión y método desde el restaurant-service
        const restaurantServiceUrl = process.env.RESTAURANT_SERVICE_URL || 'http://restaurant-service:4002';
        const resp = await fetch(`${restaurantServiceUrl}/restaurants/${restaurantId}`, {
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
    'SELECT [id], [Code], [Name], [StartDate], [EndDate], [HasTransferredTax], [HasTransferredIEPS], [Complement] FROM [products] ORDER BY [id] ASC', 
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

app.get('/query/:restaurantId/estaciones', authenticateToken, dataQueryHandler(
    'SELECT [idestacion], [descripcion], [serie], [ip], [directoriorespaldo], [mensajespera], [rutatemoral], [PostLastOnline] FROM [estaciones]', 
    'estaciones'
));
// --- ARRANQUE DEL SERVIDOR ---
const PORT = process.env.POS_SERVICE_PORT || 4004;
app.listen(PORT, () => {
    console.log(`🚀 POS-Service (v2 con Agente y Directo) escuchando en el puerto ${PORT}`);
});