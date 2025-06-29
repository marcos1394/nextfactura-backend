// --- services/restaurant-service/server.js (Versión Profesional y de Producción) ---

// =================================================================
process.on('uncaughtException', (error, origin) => {
    console.error('<<<<< ¡ERROR FATAL INESPERADO! (UNCAUGHT EXCEPTION) >>>>>');
    console.error('Esto significa que una parte del código generó un error y no fue atrapado por un try/catch.');
    console.error('--- DETALLES DEL ERROR ---');
    console.error(error);
    console.error('\n--- ORIGEN DEL ERROR ---');
    console.error(origin);
    process.exit(1); // Es una buena práctica terminar el proceso después de un error así.
});

require('dotenv').config();

// --- Imports de Librerías ---
const express = require('express');
const cors = require('cors');
const { Sequelize, DataTypes, Op, UUIDV4 } = require('sequelize');
const jwt = require('jsonwebtoken');
const crypto = require('crypto');
const fetch = require('node-fetch');


const app = express();
app.use(cors());
app.use(express.json());
app.use(express.urlencoded({ extended: true }));

// --- Configuración de Cifrado ---
// ¡IMPORTANTE! Esta clave debe estar en tus variables de entorno y ser un string de 32 caracteres.
const ENCRYPTION_KEY = process.env.ENCRYPTION_KEY; 
const IV_LENGTH = 16; // For AES, this is always 16

if (!ENCRYPTION_KEY || ENCRYPTION_KEY.length !== 32) {
    throw new Error('La variable de entorno ENCRYPTION_KEY es requerida y debe tener 32 caracteres.');
}

function encrypt(text) {
    if (text === null || typeof text === 'undefined') {
        return null;
    }
    const iv = crypto.randomBytes(IV_LENGTH);
    const cipher = crypto.createCipheriv('aes-256-cbc', Buffer.from(ENCRYPTION_KEY), iv);
    let encrypted = cipher.update(text);
    encrypted = Buffer.concat([encrypted, cipher.final()]);
    return iv.toString('hex') + ':' + encrypted.toString('hex');
}

function decrypt(text) {
    if (text === null || typeof text === 'undefined') {
        return null;
    }
    const textParts = text.split(':');
    const iv = Buffer.from(textParts.shift(), 'hex');
    const encryptedText = Buffer.from(textParts.join(':'), 'hex');
    const decipher = crypto.createDecipheriv('aes-256-cbc', Buffer.from(ENCRYPTION_KEY), iv);
    let decrypted = decipher.update(encryptedText);
    decrypted = Buffer.concat([decrypted, decipher.final()]);
    return decrypted.toString();
}

const sequelize = new Sequelize(process.env.DATABASE_URL, {
    dialect: 'postgres',
    logging: false,
    dialectOptions: {
      ssl: { require: true, rejectUnauthorized: false }
    }
});
// --- Modelos de Datos con Cifrado Automático ---

const Restaurant = sequelize.define('Restaurant', {
    id: { type: DataTypes.UUID, defaultValue: UUIDV4, primaryKey: true },
    userId: { type: DataTypes.UUID, allowNull: false, index: true },
    name: { type: DataTypes.STRING, allowNull: false },
    address: { type: DataTypes.STRING },
    logoUrl: { type: DataTypes.STRING },
    connectionHost: { type: DataTypes.STRING },
    connectionPort: { type: DataTypes.STRING },
    connectionUser: { type: DataTypes.STRING },
    connectionPassword: {
        type: DataTypes.STRING,
        get() { return decrypt(this.getDataValue('connectionPassword')); },
        set(value) { this.setDataValue('connectionPassword', encrypt(value)); }
    },
    connectionDbName: { type: DataTypes.STRING },
    vpnUsername: { type: DataTypes.STRING },
    vpnPassword: {
        type: DataTypes.STRING,
        get() { return decrypt(this.getDataValue('vpnPassword')); },
        set(value) { this.setDataValue('vpnPassword', encrypt(value)); }
    }
}, { tableName: 'restaurants', timestamps: true, paranoid: true });

const FiscalData = sequelize.define('FiscalData', {
    id: { type: DataTypes.UUID, defaultValue: UUIDV4, primaryKey: true },
    restaurantId: { type: DataTypes.UUID, allowNull: false, references: { model: Restaurant, key: 'id' } },
    rfc: { type: DataTypes.STRING, allowNull: false },
    fiscalAddress: { type: DataTypes.STRING, allowNull: false },
    csdPassword: {
        type: DataTypes.STRING,
        get() { return decrypt(this.getDataValue('csdPassword')); },
        set(value) { this.setDataValue('csdPassword', encrypt(value)); }
    },
    csdCertificateUrl: { type: DataTypes.STRING },
    csdKeyUrl: { type: DataTypes.STRING }
}, { tableName: 'fiscal_data', timestamps: true, paranoid: true });

// LÓGICA CORREGIDA: Un portal pertenece a UN restaurante.
const PortalConfig = sequelize.define('PortalConfig', {
    id: { type: DataTypes.UUID, defaultValue: UUIDV4, primaryKey: true },
    restaurantId: { type: DataTypes.UUID, allowNull: false, unique: true, references: { model: Restaurant, key: 'id' } },
    portalName: { type: DataTypes.STRING, allowNull: false },
    portalLogoUrl: { type: DataTypes.STRING },
    customDomain: { type: DataTypes.STRING, unique: true, allowNull: true },
    primaryColor: { type: DataTypes.STRING, defaultValue: '#3B82F6' },
    secondaryColor: { type: DataTypes.STRING, defaultValue: '#6B7280' }
}, { tableName: 'portal_configs', timestamps: true });

// Relaciones
Restaurant.hasOne(FiscalData, { foreignKey: 'restaurantId', onDelete: 'CASCADE' });
FiscalData.belongsTo(Restaurant, { foreignKey: 'restaurantId' });
Restaurant.hasOne(PortalConfig, { foreignKey: 'restaurantId', onDelete: 'CASCADE' });
PortalConfig.belongsTo(Restaurant, { foreignKey: 'restaurantId' });



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


app.post('/test-crash', (req, res) => {
    console.log('[SMOKE TEST] >>> Petición recibida en /test-crash');
    console.log('[SMOKE TEST] >>> Cuerpo de la petición:', req.body);
    res.status(200).json({
        success: true,
        message: '¡ÉXITO! Si ves esto, el servidor base y los middlewares funcionan.',
        received_body: req.body
    });
});

// --- Rutas del Servicio de Restaurantes ---
app.get('/health', (req, res) => {
  res.status(200).json({ status: 'ok' });
});



// POST /restaurants - Crear un nuevo restaurante y sus datos fiscales
app.post('/restaurants', authenticateToken, async (req, res) => {
    const { restaurantData, fiscalData } = req.body;
    const userId = req.user.id;
    
    if (!restaurantData || !fiscalData || !restaurantData.name || !fiscalData.rfc || !fiscalData.fiscalAddress) {
        return res.status(400).json({ success: false, message: 'Faltan datos requeridos del restaurante o fiscales.' });
    }

    const transaction = await sequelize.transaction();
    try {
        const newRestaurant = await Restaurant.create({ ...restaurantData, userId }, { transaction });
        const newFiscalData = await FiscalData.create({ ...fiscalData, restaurantId: newRestaurant.id }, { transaction });
        
        await transaction.commit();
        res.status(201).json({ success: true, restaurant: newRestaurant, fiscalData: newFiscalData });
    } catch (error) {
        await transaction.rollback();
        console.error('[Restaurant-Service /restaurants] Error:', error);
        res.status(500).json({ success: false, message: 'Error al crear el restaurante.' });
    }
});

// GET /restaurants - Obtener todos los restaurantes de un usuario
app.get('/restaurants', authenticateToken, async (req, res) => {
    const userId = req.user.id;
    try {
        const restaurants = await Restaurant.findAll({ 
            where: { userId },
            include: [{ model: FiscalData, attributes: { exclude: ['csdPassword'] } }]
        });
        res.status(200).json({ success: true, restaurants });
    } catch (error) {
        console.error('[Restaurant-Service /restaurants] Error:', error);
        res.status(500).json({ success: false, message: 'Error al obtener los restaurantes.' });
    }
});

// GET /restaurants/:id - Obtener un restaurante específico
app.get('/restaurants/:id', authenticateToken, async (req, res) => {
    const { id } = req.params;
    const userId = req.user.id;
    try {
        const restaurant = await Restaurant.findOne({
            where: { id, userId }, // Asegura que el usuario sea el propietario
            include: [FiscalData]
        });
        if (!restaurant) return res.status(404).json({ success: false, message: 'Restaurante no encontrado o no autorizado.' });
        res.status(200).json({ success: true, restaurant });
    } catch (error) {
        console.error(`[Restaurant-Service /restaurants/${id}] Error:`, error);
        res.status(500).json({ success: false, message: 'Error al obtener el restaurante.' });
    }
});


// PUT /restaurants/:id - Actualizar un restaurante y sus datos fiscales
app.put('/restaurants/:id', authenticateToken, async (req, res) => {
    const { id } = req.params;
    const { restaurantData, fiscalData } = req.body;
    const userId = req.user.id;

    const transaction = await sequelize.transaction();
    try {
        const restaurant = await Restaurant.findOne({ where: { id, userId }, transaction });
        if (!restaurant) {
            await transaction.rollback();
            return res.status(404).json({ success: false, message: 'Restaurante no encontrado o no autorizado.' });
        }

        if (restaurantData) await restaurant.update(restaurantData, { transaction });
        
        if (fiscalData) {
            const fiscal = await FiscalData.findOne({ where: { restaurantId: id }, transaction });
            if (fiscal) {
                await fiscal.update(fiscalData, { transaction });
            } else {
                await FiscalData.create({ ...fiscalData, restaurantId: id }, { transaction });
            }
        }
        
        await transaction.commit();
        const updatedRestaurant = await Restaurant.findByPk(id, { include: [FiscalData] });
        res.status(200).json({ success: true, restaurant: updatedRestaurant });
    } catch (error) {
        await transaction.rollback();
        console.error(`[Restaurant-Service /restaurants/${id}] Error:`, error);
        res.status(500).json({ success: false, message: 'Error al actualizar el restaurante.' });
    }
});

// DELETE /restaurants/:id - Borrado lógico de un restaurante
app.delete('/restaurants/:id', authenticateToken, async (req, res) => {
    const { id } = req.params;
    const userId = req.user.id;

    try {
        const restaurant = await Restaurant.findOne({ where: { id, userId } });
        if (!restaurant) {
            return res.status(404).json({ success: false, message: 'Restaurante no encontrado o no autorizado.' });
        }
        // Sequelize `destroy` con `paranoid: true` hará un borrado lógico
        await restaurant.destroy();
        res.status(200).json({ success: true, message: 'Restaurante desactivado exitosamente.' });
    } catch (error) {
        console.error(`[Restaurant-Service /restaurants/${id}] Error:`, error);
        res.status(500).json({ success: false, message: 'Error al desactivar el restaurante.' });
    }
});

// --- NUEVO: Endpoint para probar la conexión al POS ---
// Este endpoint delega la responsabilidad de la prueba al futuro `pos-service`.
// Endpoint REAL para probar la conexión al POS
app.post('/restaurants/:id/test-connection', authenticateToken, async (req, res) => {
    const { id } = req.params;
    const userId = req.user.id;

    try {
        const restaurant = await Restaurant.findOne({ where: { id, userId } });
        if (!restaurant) return res.status(404).json({ success: false, message: 'Restaurante no encontrado o no autorizado.' });

        const connectionData = {
            host: restaurant.connectionHost,
            port: restaurant.connectionPort,
            user: restaurant.connectionUser,
            password: restaurant.connectionPassword, // El getter lo descifra automáticamente
            database: restaurant.connectionDbName,
        };
        if (Object.values(connectionData).some(v => !v)) {
            return res.status(400).json({ success: false, message: 'Los datos de conexión del restaurante están incompletos.' });
        }
        
        // Llamada HTTP real al servicio de POS
        const posServiceUrl = process.env.POS_SERVICE_URL;
        if (!posServiceUrl) throw new Error("POS_SERVICE_URL no está configurada.");

        const response = await fetch(`${posServiceUrl}/test-connection`, {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ connectionData })
        });

        const result = await response.json();
        if (!response.ok) throw new Error(result.message || 'Error en el servicio de POS.');

        res.status(200).json(result);

    } catch (error) {
        console.error(`[Restaurant-Service /test-connection] Error:`, error);
        res.status(500).json({ success: false, message: error.message || 'Error al probar la conexión.' });
    }
});


// --- Rutas del Servicio de Portal ---

// Rutas de Portal, ahora anidadas bajo un restaurante
app.put('/restaurants/:restaurantId/portal', authenticateToken, async (req, res) => {
    const { restaurantId } = req.params;
    const userId = req.user.id;
    const portalData = req.body;

    try {
        const restaurant = await Restaurant.findOne({ where: { id: restaurantId, userId } });
        if (!restaurant) return res.status(404).json({ success: false, message: 'Restaurante no encontrado o no autorizado.' });

        const [portalConfig, created] = await PortalConfig.findOrCreate({
            where: { restaurantId },
            defaults: { ...portalData, restaurantId }
        });

        if (!created) {
            await portalConfig.update(portalData);
        }

        // Llamada por Webhook al servicio de infraestructura si se configura un dominio
        if (portalData.customDomain && process.env.INFRA_SERVICE_URL) {
            console.log(`[Restaurant-Service] Notificando al servicio de infraestructura sobre el dominio: ${portalData.customDomain}`);
            fetch(`${process.env.INFRA_SERVICE_URL}/configure-domain`, {
                method: 'POST',
                headers: { 'Content-Type': 'application/json', 'X-Internal-Secret': process.env.INTERNAL_SECRET },
                body: JSON.stringify({ domain: portalData.customDomain })
            }).catch(err => console.error("Error al notificar al servicio de infraestructura:", err));
        }

        res.status(200).json({ success: true, portalConfig });
    } catch (error) {
        if (error.name === 'SequelizeUniqueConstraintError') {
            return res.status(409).json({ success: false, message: `El dominio personalizado "${portalData.customDomain}" ya está en uso.` });
        }
        console.error(`[Restaurant-Service /portal/PUT] Error para restaurantId ${restaurantId}:`, error);
        res.status(500).json({ success: false, message: 'Error al guardar la configuración del portal.' });
    }
});

app.get('/restaurants/:restaurantId/portal', authenticateToken, async (req, res) => {
    const { restaurantId } = req.params;
    const userId = req.user.id;
    try {
        const restaurant = await Restaurant.findOne({ where: { id: restaurantId, userId } });
        if (!restaurant) return res.status(404).json({ success: false, message: 'Restaurante no encontrado o no autorizado.' });

        const portalConfig = await PortalConfig.findOne({ where: { restaurantId } });
        if (!portalConfig) return res.status(404).json({ success: false, message: 'No se ha configurado un portal para este restaurante.' });
        
        res.status(200).json({ success: true, portalConfig });
    } catch (error) {
        console.error(`[Restaurant-Service /portal/GET] Error para restaurantId ${restaurantId}:`, error);
        res.status(500).json({ success: false, message: 'Error al obtener la configuración del portal.' });
    }
});


// --- Arranque del Servidor ---
const PORT = process.env.RESTAURANT_SERVICE_PORT || 3002;
const startServer = async () => {
    try {
        await sequelize.authenticate();
        console.log('[Restaurant-Service] Conexión con la BD establecida.');
        await sequelize.sync({ alter: true });
        console.log('[Restaurant-Service] Modelos sincronizados.');
        app.listen(PORT, () => {
            console.log(`🚀 Restaurant-Service profesional escuchando en el puerto ${PORT}`);
        });
    } catch (error) {
        console.error('[Restaurant-Service] Error catastrófico al iniciar:', error);
        process.exit(1);
    }
};

startServer();
