// --- SERVER.JS CORREGIDO PARA MICROSERVICIO RESTAURANT ---

const express = require('express');
const cors = require('cors');
const bodyParser = require('body-parser');
const jwt = require('jsonwebtoken'); // ⚠️ FALTABA ESTE IMPORT
const fs = require('fs').promises; // ⚠️ FALTABA ESTE IMPORT
const path = require('path'); // ⚠️ FALTABA ESTE IMPORT
require('dotenv').config();

// Importar el módulo de archivos seguros
const { 
    secureUpload, 
    servePublicFile, 
    servePrivateFile, 
    createSecureDirectories,
    deleteRestaurantFiles 
} = require('./secure-file-handler');

const redis = require('redis');
const logger = require('./logger');
const { Sequelize, DataTypes, Op, UUIDV4 } = require('sequelize');

// Importar el módulo de cPanel para subdominios
const { createCpanelSubdomain } = require('./cpanelApi');

const app = express();

// --- MIDDLEWARE CORS MÁS ESPECÍFICO ---
app.use(cors({
    origin: process.env.ALLOWED_ORIGINS ? process.env.ALLOWED_ORIGINS.split(',') : '*',
    credentials: true,
    methods: ['GET', 'POST', 'PUT', 'DELETE', 'OPTIONS'],
    allowedHeaders: ['Content-Type', 'Authorization']
}));

app.use(bodyParser.json({ limit: '10mb' })); // Aumentar límite para archivos
app.use(bodyParser.urlencoded({ extended: true, limit: '10mb' }));

// --- CONEXIÓN A REDIS ---
const redisClient = redis.createClient({
    url: process.env.REDIS_URL || 'redis://localhost:6379'
});

redisClient.on('error', err => console.error('[Redis] Client Error', err));

// Conectar a Redis con manejo de errores
redisClient.connect().catch(err => {
    console.error('[Redis] No se pudo conectar a Redis. Las funciones de logout no estarán disponibles.', err);
});

// --- CONEXIÓN A BASE DE DATOS ---
const sequelize = new Sequelize(process.env.DATABASE_URL, {
    dialect: 'postgres',
    logging: false,
    dialectOptions: {
        ssl: process.env.NODE_ENV === 'production' ? { 
            require: true, 
            rejectUnauthorized: false 
        } : false
    },
    pool: {
        max: 5,
        min: 0,
        acquire: 30000,
        idle: 10000
    }
});

// --- MODELOS DE DATOS ---
const User = sequelize.define('User', {
    id: { type: DataTypes.UUID, defaultValue: UUIDV4, primaryKey: true },
    name: { type: DataTypes.STRING, allowNull: true },
    email: { type: DataTypes.STRING, allowNull: false, unique: true, validate: { isEmail: true } },
    password: { type: DataTypes.STRING, allowNull: false },
    restaurantName: { type: DataTypes.STRING, allowNull: true },
    phoneNumber: { type: DataTypes.STRING, allowNull: true },
    role: { type: DataTypes.STRING, defaultValue: 'RestaurantOwners' },
    passwordResetToken: { type: DataTypes.STRING, allowNull: true },
    passwordResetExpires: { type: DataTypes.DATE, allowNull: true },
    twoFactorSecret: { type: DataTypes.STRING, allowNull: true },
    isTwoFactorEnabled: { type: DataTypes.BOOLEAN, defaultValue: false },
    isEmailVerified: { type: DataTypes.BOOLEAN, defaultValue: false },
    emailVerificationToken: { type: DataTypes.STRING, allowNull: true },
    magicLinkToken: { type: DataTypes.STRING, allowNull: true },
    magicLinkExpires: { type: DataTypes.DATE, allowNull: true }
}, { 
    tableName: 'users', 
    timestamps: true 
});

const Restaurant = sequelize.define('Restaurant', {
    id: { type: DataTypes.UUID, defaultValue: DataTypes.UUIDV4, primaryKey: true },
    userId: { type: DataTypes.UUID, allowNull: false },
    name: { type: DataTypes.STRING, allowNull: false },
    address: { type: DataTypes.STRING },
    logoUrl: { type: DataTypes.STRING },
    subdomain: { type: DataTypes.STRING, unique: true }, // ⚠️ AÑADIDO CAMPO FALTANTE
    subdomainUrl: { type: DataTypes.STRING }, // ⚠️ AÑADIDO CAMPO FALTANTE
    connectionHost: { type: DataTypes.STRING },
    connectionPort: { type: DataTypes.STRING },
    connectionUser: { type: DataTypes.STRING },
    connectionPassword: { type: DataTypes.STRING },
    connectionDbName: { type: DataTypes.STRING },
    vpnUsername: { type: DataTypes.STRING },
    vpnPassword: { type: DataTypes.STRING }
}, {
    tableName: 'restaurants',
    timestamps: true,
    paranoid: true
});

const FiscalData = sequelize.define('FiscalData', {
    id: { type: DataTypes.UUID, defaultValue: DataTypes.UUIDV4, primaryKey: true },
    restaurantId: { type: DataTypes.UUID, allowNull: false },
    rfc: { type: DataTypes.STRING },
    businessName: { type: DataTypes.STRING },
    fiscalRegime: { type: DataTypes.STRING },
    csdCertificateUrl: { type: DataTypes.STRING },
    csdKeyUrl: { type: DataTypes.STRING },
    csdPassword: { type: DataTypes.STRING }
}, {
    tableName: 'fiscal_data',
    timestamps: true
});

const Role = sequelize.define('Role', {
    name: { type: DataTypes.STRING, allowNull: false, unique: true }
}, { timestamps: false });

const Permission = sequelize.define('Permission', {
    name: { type: DataTypes.STRING, allowNull: false, unique: true },
    description: { type: DataTypes.STRING }
}, { timestamps: false });

const AuditLog = sequelize.define('AuditLog', {
    id: { type: DataTypes.UUID, defaultValue: UUIDV4, primaryKey: true },
    userId: { type: DataTypes.UUID, allowNull: true },
    action: { type: DataTypes.STRING, allowNull: false },
    ipAddress: { type: DataTypes.STRING },
    userAgent: { type: DataTypes.STRING },
    details: { type: DataTypes.TEXT }
});

const Plan = sequelize.define('Plan', {
    id: { type: DataTypes.UUID, defaultValue: UUIDV4, primaryKey: true },
    name: { type: DataTypes.STRING, allowNull: false, unique: true },
    price: { type: DataTypes.FLOAT, allowNull: false },
    features: { type: DataTypes.JSONB, allowNull: true },
    mercadopagoId: { type: DataTypes.STRING, allowNull: true },
    isActive: { type: DataTypes.BOOLEAN, defaultValue: true }
}, { tableName: 'plans', timestamps: true });

const PlanPurchase = sequelize.define('PlanPurchase', {
    id: { type: DataTypes.INTEGER, primaryKey: true, autoIncrement: true },
    userId: { type: DataTypes.UUID, allowNull: false },
    planId: { type: DataTypes.UUID, allowNull: false },
    origin: { type: DataTypes.STRING, allowNull: false },
    status: { type: DataTypes.STRING, defaultValue: 'pending', allowNull: false },
    price: { type: DataTypes.FLOAT, allowNull: false },
    purchaseDate: { type: DataTypes.DATE },
    expirationDate: { type: DataTypes.DATE },
    paymentId: { type: DataTypes.STRING, allowNull: true, unique: true },
    paymentProvider: { type: DataTypes.STRING, defaultValue: 'mercadopago' },
    preferenceId: { type: DataTypes.STRING, allowNull: true }
}, { tableName: 'plan_purchases', timestamps: true });

// --- RELACIONES ---
User.hasMany(Restaurant, { foreignKey: 'userId' });
Restaurant.belongsTo(User, { foreignKey: 'userId' });
Restaurant.hasOne(FiscalData, { foreignKey: 'restaurantId' });
FiscalData.belongsTo(Restaurant, { foreignKey: 'restaurantId' });

// --- MIDDLEWARE DE AUTENTICACIÓN MEJORADO ---
const authenticateToken = async (req, res, next) => {
    try {
        const authHeader = req.headers['authorization'];
        const token = authHeader && authHeader.split(' ')[1];
        
        if (!token) {
            return res.status(401).json({ 
                success: false, 
                message: 'Acceso denegado. Token no proporcionado.' 
            });
        }

        // Verificar token JWT
        const decoded = jwt.verify(token, process.env.JWT_SECRET, { ignoreExpiration: false });

        // Verificar lista negra de Redis si está disponible
        if (redisClient.isOpen) {
            try {
                const isBlacklisted = await redisClient.get(`blacklist:${decoded.jti}`);
                if (isBlacklisted) {
                    return res.status(401).json({ 
                        success: false, 
                        message: 'Token revocado. Por favor, inicia sesión de nuevo.' 
                    });
                }
            } catch (redisError) {
                console.error('[Auth] Error checking Redis blacklist:', redisError);
                // Continuar sin verificación de Redis
            }
        }

        // Verificar que el usuario existe
        const user = await User.findByPk(decoded.id);
        if (!user) {
            return res.status(401).json({ 
                success: false, 
                message: 'Usuario no encontrado.' 
            });
        }

        req.user = decoded;
        next();
    } catch (err) {
        console.error('[Auth] Token verification error:', err);
        
        if (err.name === 'TokenExpiredError') {
            return res.status(401).json({ 
                success: false, 
                message: 'Token expirado. Por favor, inicia sesión de nuevo.' 
            });
        } else if (err.name === 'JsonWebTokenError') {
            return res.status(401).json({ 
                success: false, 
                message: 'Token inválido.' 
            });
        }
        
        return res.status(403).json({ 
            success: false, 
            message: 'Token inválido o expirado.' 
        });
    }
};

// --- FUNCIONES AUXILIARES ---
const buildSecureFileUrl = (filename, isPublic = true, restaurantId = null) => {
    if (!filename) return null;
    
    const baseUrl = process.env.BASE_URL || 'http://localhost:4002';
    
    if (isPublic) {
        return `${baseUrl}/public/${filename}`;
    } else {
        return `${baseUrl}/restaurants/${restaurantId}/private/${filename}`;
    }
};

const generateSubdomainName = (restaurantName, restaurantId) => {
    let subdomain = restaurantName
        .toLowerCase()
        .normalize('NFD')
        .replace(/[\u0300-\u036f]/g, '')
        .replace(/[^a-z0-9]/g, '-')
        .replace(/-+/g, '-')
        .replace(/^-|-$/g, '')
        .substring(0, 20);
    
    if (subdomain.length < 3) {
        subdomain = `restaurant-${restaurantId.substring(0, 8)}`;
    }
    
    if (/^\d/.test(subdomain)) {
        subdomain = `r-${subdomain}`;
    }
    
    return subdomain;
};

// Inicializar directorios seguros
createSecureDirectories().catch(console.error);

// --- RUTAS DE ARCHIVOS ---
app.get('/public/:filename', servePublicFile);
app.get('/restaurants/:restaurantId/private/:filename', authenticateToken, servePrivateFile);

// --- ENDPOINT: CREAR RESTAURANTE (CORREGIDO) ---
app.post('/',
    authenticateToken,
    secureUpload.fields([
        { name: 'logo', maxCount: 1 },
        { name: 'csdCertificate', maxCount: 1 },
        { name: 'csdKey', maxCount: 1 }
    ]),
    async (req, res) => {
        const transaction = await sequelize.transaction();
        
        try {
            const { restaurantData, fiscalData } = req.body;
            const userId = req.user.id;

            if (!restaurantData || !fiscalData) {
                await transaction.rollback();
                return res.status(400).json({ 
                    success: false, 
                    message: 'Faltan los objetos restaurantData o fiscalData.' 
                });
            }
            
            const parsedRestaurantData = typeof restaurantData === 'string' 
                ? JSON.parse(restaurantData) 
                : restaurantData;
            const parsedFiscalData = typeof fiscalData === 'string' 
                ? JSON.parse(fiscalData) 
                : fiscalData;
            
            if (!parsedRestaurantData.name || parsedRestaurantData.name.trim().length === 0) {
                await transaction.rollback();
                return res.status(400).json({ 
                    success: false, 
                    message: 'El nombre del restaurante es requerido.' 
                });
            }

            // --- CAMBIO 1: Añadir validación para fiscalAddress ---
            if (!parsedFiscalData.fiscalAddress || parsedFiscalData.fiscalAddress.trim().length === 0) {
                await transaction.rollback();
                return res.status(400).json({
                    success: false,
                    message: 'La dirección fiscal (fiscalAddress) es requerida.'
                });
            }

            // Crear restaurante
            const newRestaurant = await Restaurant.create({ 
                ...parsedRestaurantData, 
                userId
            }, { transaction });
            
            const restaurantId = newRestaurant.id;

            // --- CAMBIO 2: SECCIÓN DE SUBDOMINIO COMENTADA (Temporalmente deshabilitada) ---
            /* let subdomain = null;
            let subdomainUrl = null;
            
            try {
                subdomain = generateSubdomainName(parsedRestaurantData.name, restaurantId);
                const subdomainCreated = await createCpanelSubdomain(subdomain);
                
                if (subdomainCreated) {
                    const rootDomain = process.env.ROOT_DOMAIN || 'nextfactura.com.mx';
                    subdomainUrl = `https://${subdomain}.${rootDomain}`;
                    await newRestaurant.update({ subdomain, subdomainUrl }, { transaction });
                }
            } catch (subdomainError) {
                // Ya no lanzamos un error, solo lo registramos por si se quiere revisar después.
                console.error('[Restaurant-Service] Omitiendo error de subdominio (deshabilitado temporalmente):', subdomainError.message);
            }
            */

            // Procesar archivos
            const logoFile = req.files?.logo?.[0];
            const csdCertificateFile = req.files?.csdCertificate?.[0];
            const csdKeyFile = req.files?.csdKey?.[0];

            const logoUrl = logoFile ? buildSecureFileUrl(logoFile.filename, true) : null;
            const csdCertificateUrl = csdCertificateFile ? buildSecureFileUrl(csdCertificateFile.filename, false, restaurantId) : null;
            const csdKeyUrl = csdKeyFile ? buildSecureFileUrl(csdKeyFile.filename, false, restaurantId) : null;
            
            if (logoUrl) {
                await newRestaurant.update({ logoUrl }, { transaction });
            }

            // Crear datos fiscales (el operador '...' ya incluye fiscalAddress si viene en el objeto)
            const newFiscalData = await FiscalData.create({ 
                ...parsedFiscalData, 
                restaurantId,
                csdCertificateUrl,
                csdKeyUrl
            }, { transaction });
            
            await transaction.commit();
            
            // Respuesta segura
            const safeRestaurant = newRestaurant.toJSON();
            const safeFiscalData = newFiscalData.toJSON();
            delete safeFiscalData.csdPassword;
            
            res.status(201).json({ 
                success: true, 
                restaurant: safeRestaurant, 
                fiscalData: safeFiscalData,
                // Mensaje informativo sobre el subdominio
                subdomain: { name: null, url: null, created: false, message: "La creación de subdominios está deshabilitada temporalmente." }
            });

        } catch (error) {
            await transaction.rollback();
            
            // Limpiar archivos en caso de error
            if (req.files) {
                for (const field in req.files) {
                    for (const file of req.files[field]) {
                        try {
                            await fs.unlink(file.path);
                        } catch (unlinkError) {
                            console.error('Error eliminando archivo:', unlinkError);
                        }
                    }
                }
            }
            
            console.error('[Restaurant-Service POST /] Error:', error);
            res.status(500).json({ 
                success: false, 
                message: error.message || 'Error al crear el restaurante.' 
            });
        }
    }
);

// --- ENDPOINT: ACTUALIZAR RESTAURANTE ---
app.put('/:id', 
    authenticateToken,
    secureUpload.fields([
        { name: 'logo', maxCount: 1 },
        { name: 'csdCertificate', maxCount: 1 },
        { name: 'csdKey', maxCount: 1 }
    ]),
    async (req, res) => {
        const { id } = req.params;
        const userId = req.user.id;
        const transaction = await sequelize.transaction();

        try {
            const restaurant = await Restaurant.findOne({ 
                where: { id, userId }, 
                transaction 
            });
            
            if (!restaurant) {
                await transaction.rollback();
                return res.status(404).json({ 
                    success: false, 
                    message: 'Restaurante no encontrado o no autorizado.' 
                });
            }

            // Procesar datos
            let restaurantData = req.body.restaurantData;
            let fiscalData = req.body.fiscalData;
            
            if (typeof restaurantData === 'string') {
                restaurantData = JSON.parse(restaurantData);
            }
            if (typeof fiscalData === 'string') {
                fiscalData = JSON.parse(fiscalData);
            }

            const updates = { ...restaurantData };
            
            // Manejar archivos nuevos
            if (req.files?.logo) {
                if (restaurant.logoUrl) {
                    const oldFilename = path.basename(restaurant.logoUrl);
                    const oldPath = path.join(__dirname, 'secure_uploads', 'public', oldFilename);
                    fs.unlink(oldPath).catch(console.error);
                }
                updates.logoUrl = buildSecureFileUrl(req.files.logo[0].filename, true);
            }

            // Manejar subdominio
            if (restaurantData.name && 
                restaurantData.name !== restaurant.name && 
                !restaurant.subdomain) {
                
                try {
                    const newSubdomain = generateSubdomainName(restaurantData.name, id);
                    const subdomainCreated = await createCpanelSubdomain(newSubdomain);
                    
                    if (subdomainCreated) {
                        const rootDomain = process.env.ROOT_DOMAIN || 'nextfactura.com.mx';
                        updates.subdomain = newSubdomain;
                        updates.subdomainUrl = `https://${newSubdomain}.${rootDomain}`;
                    }
                } catch (subdomainError) {
                    console.error('[Restaurant-Service] Error al crear subdominio durante actualización:', subdomainError);
                }
            }

            await restaurant.update(updates, { transaction });
            
            // Actualizar datos fiscales
            if (fiscalData) {
                const fiscal = await FiscalData.findOne({ 
                    where: { restaurantId: id }, 
                    transaction 
                });
                
                const fiscalUpdates = { ...fiscalData };
                
                if (req.files?.csdCertificate) {
                    if (fiscal?.csdCertificateUrl) {
                        const oldFilename = path.basename(fiscal.csdCertificateUrl);
                        const oldPath = path.join(__dirname, 'secure_uploads', 'private', oldFilename);
                        fs.unlink(oldPath).catch(console.error);
                    }
                    fiscalUpdates.csdCertificateUrl = buildSecureFileUrl(
                        req.files.csdCertificate[0].filename, false, id
                    );
                }
                
                if (req.files?.csdKey) {
                    if (fiscal?.csdKeyUrl) {
                        const oldFilename = path.basename(fiscal.csdKeyUrl);
                        const oldPath = path.join(__dirname, 'secure_uploads', 'private', oldFilename);
                        fs.unlink(oldPath).catch(console.error);
                    }
                    fiscalUpdates.csdKeyUrl = buildSecureFileUrl(
                        req.files.csdKey[0].filename, false, id
                    );
                }
                
                if (fiscal) {
                    await fiscal.update(fiscalUpdates, { transaction });
                } else {
                    await FiscalData.create({ 
                        ...fiscalUpdates, 
                        restaurantId: id 
                    }, { transaction });
                }
            }
            
            await transaction.commit();
            
            // Obtener datos actualizados
            const updatedRestaurant = await Restaurant.findByPk(id, { 
                include: [{
                    model: FiscalData,
                    attributes: { exclude: ['csdPassword'] }
                }]
            });
            
            res.status(200).json({ 
                success: true, 
                restaurant: updatedRestaurant 
            });
            
        } catch (error) {
            await transaction.rollback();
            
            if (req.files) {
                Object.values(req.files).flat().forEach(async (file) => {
                    try {
                        await fs.unlink(file.path);
                    } catch (unlinkError) {
                        console.error('Error eliminando archivo:', unlinkError);
                    }
                });
            }
            
            console.error(`[Restaurant-Service PUT /${id}] Error:`, error);
            res.status(500).json({ 
                success: false, 
                message: error.message || 'Error al actualizar el restaurante.' 
            });
        }
    }
);

// --- ENDPOINT: ELIMINAR RESTAURANTE ---
app.delete('/:id', authenticateToken, async (req, res) => {
    const { id } = req.params;
    const userId = req.user.id;

    try {
        const restaurant = await Restaurant.findOne({ where: { id, userId } });
        
        if (!restaurant) {
            return res.status(404).json({ 
                success: false, 
                message: 'Restaurante no encontrado o no autorizado.' 
            });
        }
        
        await deleteRestaurantFiles(id);
        
        if (restaurant.subdomain) {
            console.log(`[Restaurant-Service] NOTA: El subdominio ${restaurant.subdomain} del restaurante ${id} debe ser eliminado manualmente de cPanel`);
        }
        
        await restaurant.destroy();
        
        res.status(200).json({ 
            success: true, 
            message: 'Restaurante desactivado exitosamente.' 
        });
        
    } catch (error) {
        console.error(`[Restaurant-Service DELETE /${id}] Error:`, error);
        res.status(500).json({ 
            success: false, 
            message: 'Error al desactivar el restaurante.' 
        });
    }
});

// --- ENDPOINT: OBTENER RESTAURANTES ---
app.get('/', authenticateToken, async (req, res) => {
    const userId = req.user.id;
    
    try {
        const restaurants = await Restaurant.findAll({ 
            where: { userId },
            include: [{ 
                model: FiscalData, 
                attributes: { exclude: ['csdPassword'] }
            }]
        });
        
        res.status(200).json({ success: true, restaurants });
    } catch (error) {
        console.error('[Restaurant-Service GET /] Error:', error);
        res.status(500).json({ 
            success: false, 
            message: 'Error al obtener los restaurantes.' 
        });
    }
});

// --- ENDPOINT: OBTENER UN RESTAURANTE ---
app.get('/:id', authenticateToken, async (req, res) => {
    const { id } = req.params;
    const userId = req.user.id;
    
    try {
        const restaurant = await Restaurant.findOne({
            where: { id, userId },
            include: [{
                model: FiscalData,
                attributes: { exclude: ['csdPassword'] }
            }]
        });
        
        if (!restaurant) {
            return res.status(404).json({ 
                success: false, 
                message: 'Restaurante no encontrado o no autorizado.' 
            });
        }
        
        res.status(200).json({ success: true, restaurant });
    } catch (error) {
        console.error(`[Restaurant-Service GET /${id}] Error:`, error);
        res.status(500).json({ 
            success: false, 
            message: 'Error al obtener el restaurante.' 
        });
    }
});

// --- ENDPOINT: VERIFICAR DISPONIBILIDAD DE SUBDOMINIO ---
app.get('/subdomain/check/:name', authenticateToken, async (req, res) => {
    const { name } = req.params;
    
    try {
        const normalizedName = generateSubdomainName(name, 'temp');
        
        const existingRestaurant = await Restaurant.findOne({
            where: { subdomain: normalizedName }
        });
        
        const isAvailable = !existingRestaurant;
        
        res.status(200).json({
            success: true,
            subdomain: normalizedName,
            available: isAvailable,
            url: isAvailable ? `https://${normalizedName}.${process.env.ROOT_DOMAIN || 'nextfactura.com.mx'}` : null
        });
        
    } catch (error) {
        console.error('[Restaurant-Service GET /subdomain/check] Error:', error);
        res.status(500).json({
            success: false,
            message: 'Error al verificar disponibilidad del subdominio.'
        });
    }
});

// --- MIDDLEWARE DE ERROR GLOBAL ---
app.use((err, req, res, next) => {
    console.error('Error no manejado:', err);
    res.status(500).json({
        success: false,
        message: 'Error interno del servidor'
    });
});

// --- ARRANQUE DEL SERVIDOR ---
const PORT = process.env.RESTAURANT_SERVICE_PORT || 4002;

const startServer = async () => {
    try {
        await sequelize.authenticate();
        console.log(`[Restaurant-Service] Conexión con la base de datos establecida exitosamente.`);
        
        app.listen(PORT, '0.0.0.0', () => { // ⚠️ ESCUCHAR EN TODAS LAS INTERFACES
            console.log(`🚀 Restaurant Service escuchando en el puerto ${PORT}`);
            logger.info(`🚀 Restaurant Service escuchando en el puerto ${PORT}`);
        });
    } catch (error) {
        logger.error('Error catastrófico al iniciar Restaurant Service', { 
            service: 'restaurant-service',
            error: error.message, 
            stack: error.stack 
        });
        process.exit(1);
    }
};

// Manejar señales de terminación
process.on('SIGTERM', async () => {
    console.log('SIGTERM recibido, cerrando servidor...');
    await sequelize.close();
    await redisClient.quit();
    process.exit(0);
});

process.on('SIGINT', async () => {
    console.log('SIGINT recibido, cerrando servidor...');
    await sequelize.close();
    await redisClient.quit();
    process.exit(0);
});

startServer();