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
const logger = require('./logger'); // Importa tu nuevo logger
// --- Imports de Librerías ---
const express = require('express');
const cors = require('cors');
const { Sequelize, DataTypes, Op, UUIDV4 } = require('sequelize');
const jwt = require('jsonwebtoken');
const crypto = require('crypto');
const fetch = require('node-fetch');
const path = require('path'); // Módulo nativo de Node para manejar rutas de archivos
const fs = require('fs');     // Módulo nativo de Node para manejar el sistema de archivos
const multer = require('multer');

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

// 1. Crear la carpeta 'uploads' si no existe
const uploadsDir = path.join(__dirname, 'uploads');
if (!fs.existsSync(uploadsDir)) {
    fs.mkdirSync(uploadsDir);
}


// 2. Servir los archivos de la carpeta 'uploads' como archivos estáticos
// Esto hace que se pueda acceder a ellos desde una URL pública
app.use('/uploads', express.static(uploadsDir));

// 3. Configurar Multer para guardar los archivos en el disco
const storage = multer.diskStorage({
    destination: function (req, file, cb) {
        cb(null, 'uploads/'); // Guardar en la carpeta 'uploads'
    },
    filename: function (req, file, cb) {
        // Generar un nombre único para evitar colisiones
        const uniqueSuffix = Date.now() + '-' + Math.round(Math.random() * 1E9);
        cb(null, file.fieldname + '-' + uniqueSuffix + path.extname(file.originalname));
    }
});
const upload = multer({ storage: storage });

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

// --- Conexión a Base de Datos ---
const sequelize = new Sequelize(process.env.DATABASE_URL, {
    dialect: 'postgres',
    logging: false,
    // Elimina dialectOptions si no usas SSL
});

// --- Modelos de Datos ---

// AÑADIDO: Se define el modelo User para establecer la relación
const User = sequelize.define('User', {
    id: { type: DataTypes.UUID, primaryKey: true },
}, { tableName: 'users', timestamps: false }); // No necesita todos los campos, solo el id

const Restaurant = sequelize.define('Restaurant', {
    id: { type: DataTypes.UUID, defaultValue: UUIDV4, primaryKey: true },
    userId: { type: DataTypes.UUID, allowNull: false },
    name: { type: DataTypes.STRING, allowNull: false },
    address: { type: DataTypes.STRING },
    logoUrl: { type: DataTypes.STRING },
    connectionHost: { type: DataTypes.STRING },
    connectionPort: { type: DataTypes.STRING },
    connectionUser: { type: DataTypes.STRING },
    connectionPassword: {
        type: DataTypes.STRING,
        // get() { return decrypt(this.getDataValue('connectionPassword')); },
        // set(value) { this.setDataValue('connectionPassword', encrypt(value)); }
    },
    connectionDbName: { type: DataTypes.STRING },
    vpnUsername: { type: DataTypes.STRING },
    vpnPassword: {
        type: DataTypes.STRING,
        // get() { return decrypt(this.getDataValue('vpnPassword')); },
        // set(value) { this.setDataValue('vpnPassword', encrypt(value)); }
    }
}, { tableName: 'restaurants', timestamps: true, paranoid: true });

const FiscalData = sequelize.define('FiscalData', {
    id: { type: DataTypes.UUID, defaultValue: UUIDV4, primaryKey: true },
    restaurantId: { type: DataTypes.UUID, allowNull: false },
    rfc: { type: DataTypes.STRING, allowNull: false },
    fiscalAddress: { type: DataTypes.STRING, allowNull: false },
    csdPassword: {
        type: DataTypes.STRING,
        // get() { return decrypt(this.getDataValue('csdPassword')); },
        // set(value) { this.setDataValue('csdPassword', encrypt(value)); }
    },
    csdCertificateUrl: { type: DataTypes.STRING },
    csdKeyUrl: { type: DataTypes.STRING }
}, { tableName: 'fiscal_data', timestamps: true, paranoid: true });

const PortalConfig = sequelize.define('PortalConfig', {
    id: { type: DataTypes.UUID, defaultValue: UUIDV4, primaryKey: true },
    restaurantId: { type: DataTypes.UUID, allowNull: false, unique: true },
    portalName: { type: DataTypes.STRING, allowNull: false },
    portalLogoUrl: { type: DataTypes.STRING },
    customDomain: { type: DataTypes.STRING, unique: true, allowNull: true },
    primaryColor: { type: DataTypes.STRING, defaultValue: '#3B82F6' },
    secondaryColor: { type: DataTypes.STRING, defaultValue: '#6B7280' }
}, { tableName: 'portal_configs', timestamps: true });

// --- Definición de Relaciones ---
// Un Restaurante pertenece a un Usuario
User.hasMany(Restaurant, { foreignKey: 'userId' });
Restaurant.belongsTo(User, { foreignKey: 'userId' });

// Un Restaurante tiene un solo dato fiscal
Restaurant.hasOne(FiscalData, { foreignKey: 'restaurantId', onDelete: 'CASCADE' });
FiscalData.belongsTo(Restaurant, { foreignKey: 'restaurantId' });

// Un Restaurante tiene una sola configuración de portal
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

// --- (en restaurant-service/server.js) ---

// POST / - Crear un nuevo restaurante (CON VALIDACIÓN DE PLAN)
// --- Endpoint de Creación de Restaurante (VERSIÓN COMPLETA) ---
app.post('/',
    authenticateToken,
    upload.fields([
        { name: 'logo', maxCount: 1 },
        { name: 'csdCertificate', maxCount: 1 },
        { name: 'csdKey', maxCount: 1 }
    ]),
    async (req, res) => {
        
    // --- 1. VALIDACIÓN DE PLAN ---
    try {
        const paymentServiceUrl = process.env.PAYMENT_SERVICE_URL;
        if (!paymentServiceUrl) throw new Error("La URL del servicio de pagos no está configurada.");

        const planCheckResponse = await fetch(`${paymentServiceUrl}/subscription-check`, {
            headers: { 'Authorization': req.headers.authorization }
        });
        const planCheckData = await planCheckResponse.json();
        
        if (!planCheckResponse.ok || !planCheckData.canCreate) {
            return res.status(403).json({ success: false, message: planCheckData.reason || "No tienes permiso para crear un restaurante." });
        }
    } catch (error) {
        console.error('[Restaurant-Service] Error al validar plan:', error);
        return res.status(500).json({ success: false, message: 'No se pudo verificar tu plan de suscripción.' });
    }

    // --- 2. PROCESAR DATOS Y ARCHIVOS ---
    // En una petición form-data, los datos de texto vienen en req.body
    const { restaurantData, fiscalData } = req.body;
    const userId = req.user.id;

    if (!restaurantData || !fiscalData) {
        return res.status(400).json({ success: false, message: 'Faltan los objetos restaurantData o fiscalData.' });
    }
    
    // Construir URLs para los archivos subidos
    const getFileUrl = (fieldName) => {
        if (req.files && req.files[fieldName]) {
            const filename = req.files[fieldName][0].filename;
            return `${process.env.BASE_URL}/uploads/${filename}`;
        }
        return null;
    };

    const logoUrl = getFileUrl('logo');
    const csdCertificateUrl = getFileUrl('csdCertificate');
    const csdKeyUrl = getFileUrl('csdKey');
    
    const transaction = await sequelize.transaction();
    try {
        const parsedRestaurantData = JSON.parse(restaurantData);
        const parsedFiscalData = JSON.parse(fiscalData);
        
        // --- 3. CREAR EN BASE DE DATOS CON URLs ---
        const newRestaurant = await Restaurant.create({ 
            ...parsedRestaurantData, 
            userId,
            logoUrl
        }, { transaction });

        const newFiscalData = await FiscalData.create({ 
            ...parsedFiscalData, 
            restaurantId: newRestaurant.id,
            csdCertificateUrl,
            csdKeyUrl
        }, { transaction });
        
        await transaction.commit();
        res.status(201).json({ success: true, restaurant: newRestaurant, fiscalData: newFiscalData });

    } catch (error) {
        await transaction.rollback();
        console.error('[Restaurant-Service /] Error:', error);
        res.status(500).json({ success: false, message: 'Error al crear el restaurante.' });
    }
});



// GET /restaurants - Obtener todos los restaurantes de un usuario
app.get('/', authenticateToken, async (req, res) => {
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
app.get('/:id', authenticateToken, async (req, res) => {
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
app.put('/:id', authenticateToken, async (req, res) => {
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
app.delete('/:id', authenticateToken, async (req, res) => {
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
app.post('/:id/test-connection', authenticateToken, async (req, res) => {
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


// --- Arranque del Servidor (Versión Robusta) ---
const PORT = process.env.RESTAURANT_SERVICE_PORT || 4002;
// Reemplaza la función startServer en cada servicio con esta versión

const startServer = async () => {
    try {
        // 1. Solo verifica que la conexión a la base de datos funciona.
        await sequelize.authenticate();
        console.log(`[Service] Conexión con la base de datos establecida exitosamente.`);

        // 2. La sincronización de modelos se ha eliminado.
        // El servicio ahora asume que las tablas ya existen y están correctas.
        
        // 3. Inicia el servidor Express para escuchar peticiones.
        app.listen(PORT, () => {
            logger.info(`🚀 Service escuchando en el puerto ${PORT}`);
        });
    } catch (error) {
       logger.error('Error catastrófico al iniciar', { 
    service: 'restaurant-service', // Identifica el servicio
    error: error.message, 
    stack: error.stack 
});
    }
};

startServer();