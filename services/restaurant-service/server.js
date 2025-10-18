// --- SERVER.JS CORREGIDO PARA MICROSERVICIO RESTAURANT ---

const express = require('express');
const cors = require('cors');
const bodyParser = require('body-parser');
const jwt = require('jsonwebtoken'); // ⚠️ FALTABA ESTE IMPORT
const fs = require('fs').promises; // ⚠️ FALTABA ESTE IMPORT
const path = require('path'); // ⚠️ FALTABA ESTE IMPORT
require('dotenv').config();
const { v4: uuidv4 } = require('uuid'); // <-- AÑADE ESTA LÍNEA
const pendingRequests = new Map(); // <-- AÑADE ESTA LÍNEA
const cookieParser = require('cookie-parser'); // <-- AÑADE ESTA IMPORTACIÓN
const semver = require('semver'); // La librería que acabamos de instalar


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
app.use(cookieParser()); // <-- AÑADE ESTA LÍNEA
// --- CONEXIÓN A REDIS ---
const redisClient = redis.createClient({
    url: process.env.REDIS_URL || 'redis://localhost:6379'
});

redisClient.on('error', err => console.error('[Redis] Client Error', err));
const subscriber = redisClient.duplicate(); // Cliente duplicado para suscripciones
// El "radioescucha": se suscribe al canal de respuestas.
subscriber.connect().then(() => {
    console.log('[Restaurant-Service] Conectado a Redis como suscriptor.');
    subscriber.subscribe('agent-responses', (message) => {
        try {
            const { correlationId, data, error } = JSON.parse(message);

            // Si tenemos una petición esperando por este ID, la resolvemos
            if (pendingRequests.has(correlationId)) {
                const { resolve, reject } = pendingRequests.get(correlationId);
                if (error) {
                    reject(new Error(error));
                } else {
                    resolve(data);
                }
                // Limpiamos la petición de la "sala de espera"
                pendingRequests.delete(correlationId);
            }
        } catch (e) {
            console.error('[Restaurant-Service] Error procesando mensaje de Redis:', e);
        }
    });
}).catch(err => console.error('[Restaurant-Service] No se pudo conectar a Redis como suscriptor.', err));

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
    subdomain: { type: DataTypes.STRING, unique: true },
    subdomainUrl: { type: DataTypes.STRING },
    // --- NUEVO: Clave única para la autenticación del agente ---
    agentKey: {
        type: DataTypes.UUID,
        defaultValue: DataTypes.UUIDV4, // Se genera una clave única automáticamente
        allowNull: false,
        unique: true
    },
    connectionMethod: {
        type: DataTypes.STRING,
        allowNull: false,
        defaultValue: 'direct', // Por defecto, los restaurantes usan conexión directa
        validate: {
            isIn: [['direct', 'agent']] // Solo permite estos dos valores
        }
    },
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
     // --- CAMPO AÑADIDO ---
    fiscalAddress: { 
        type: DataTypes.STRING,
        allowNull: false // Se establece como no nulo para coincidir con la BD
    },
    csdKeyUrl: { type: DataTypes.STRING },
    csdPassword: { type: DataTypes.STRING }
}, {
    tableName: 'fiscal_data',
    timestamps: true
});

const PortalConfig = sequelize.define('PortalConfig', {
    id: { type: DataTypes.UUID, defaultValue: UUIDV4, primaryKey: true },
    restaurantId: { type: DataTypes.UUID, allowNull: false, unique: true },
    
    // --- CAMPOS CORREGIDOS Y AÑADIDOS ---
    portalName: {
        type: DataTypes.STRING,
        allowNull: false
    },
    // Usamos 'field' para mapear el nombre del código (logoUrl) al nombre de la columna (portalLogoUrl)
    logoUrl: {
        type: DataTypes.STRING,
        field: 'portalLogoUrl' 
    },
    customDomain: {
        type: DataTypes.STRING,
        unique: true
    },
    primaryColor: {
        type: DataTypes.STRING
    },
    secondaryColor: {
        type: DataTypes.STRING
    }
}, {
    tableName: 'portal_configs',
    timestamps: true
});

const FiscalRegime = sequelize.define('FiscalRegime', {
    code: { type: DataTypes.STRING, primaryKey: true, allowNull: false },
    description: { type: DataTypes.TEXT, allowNull: false },
    person_type: { type: DataTypes.CHAR(1), allowNull: false } // 'F' o 'M'
}, { tableName: 'fiscal_regimes' });

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
// --- RELACIONES ---
//...
Restaurant.hasOne(PortalConfig, { foreignKey: 'restaurantId', onDelete: 'CASCADE' });
PortalConfig.belongsTo(Restaurant, { foreignKey: 'restaurantId' });
//...

const authenticateToken = async (req, res, next) => {
    // Usamos el logger profesional
    logger.info(`[Rest-Token] Iniciando validación para la ruta: ${req.originalUrl}`);

    // Log para ver las cookies que llegan
    logger.info({ message: "[Rest-Token] Cookies recibidas por el servicio:", cookies: req.cookies });

    const tokenFromHeader = req.headers['authorization']?.split(' ')[1];
    const token = tokenFromHeader || req.cookies.accessToken?.split(' ')[1];

    if (!token) {
        logger.warn(`[Rest-Token] ACCESO DENEGADO: No se encontró token ni en la cabecera ni en las cookies.`);
        return res.status(401).json({ success: false, message: 'Token de acceso no proporcionado.' });
    }

    logger.info(`[Rest-Token] Token encontrado. Intentando verificar...`);
    try {
        const decoded = jwt.verify(token, process.env.JWT_SECRET);
        req.user = decoded;
        logger.info(`[Rest-Token] ÉXITO: Token verificado para el usuario ${decoded.id}`);
        return next();
    } catch (err) {
        logger.error(`[Rest-Token] ERROR: La verificación del token falló.`, { errorName: err.name, errorMessage: err.message });
        
        if (err.name === 'TokenExpiredError') {
            return res.status(401).json({ 
                success: false, 
                message: 'Token de acceso expirado.' 
            });
        }

        return res.status(403).json({ success: false, message: 'Token de acceso inválido.' });
    }
};

// Middleware de autenticación interna
const authenticateService = (req, res, next) => {
    const secretKey = req.headers['x-internal-secret'];
    if (!secretKey || secretKey !== process.env.INTERNAL_SECRET_KEY) {
        return res.status(403).json({ success: false, message: 'Acceso no autorizado.' });
    }
    next();
};

// --- FUNCIÓN AUXILIAR CORREGIDA ---
async function getFileAsBase64(fileUrl) {
    try {
        const filename = path.basename(fileUrl);
        const subfolder = fileUrl.includes('/private/') ? 'private' : 'public';

        // La ruta correcta DENTRO del contenedor
        const fullPath = path.join('/app/secure_uploads', subfolder, filename);

        console.log(`[Service] Leyendo archivo local desde la ruta correcta: ${fullPath}`);
        const fileBuffer = await fs.readFile(fullPath);
        return fileBuffer.toString('base64');

    } catch (error) {
        console.error(`[Service] Error al leer el archivo local: ${fileUrl}`, error);
        throw new Error(`No se pudo leer el archivo: ${path.basename(fileUrl)}`);
    }
}

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

            // --- INICIO DE LA LÓGICA DE SUBDOMINIO (NUEVA) ---
            let subdomain = null;
            let subdomainUrl = null;
            let subdomainCreated = false;
            let subdomainMessage = "El subdominio se ha generado.";
            
            try {
                // 1. Usamos la función que ya tenías para limpiar el nombre
                subdomain = generateSubdomainName(parsedRestaurantData.name, restaurantId);
                
                // 2. Verificamos que no exista ya en la base de datos
                const existing = await Restaurant.findOne({ where: { subdomain } });
                if (existing) {
                    throw new Error(`El subdominio '${subdomain}' ya está en uso.`);
                }
                
                // 3. Obtenemos el dominio raíz desde las variables de entorno
                const rootDomain = process.env.ROOT_DOMAIN || 'nextmanager.com.mx';
                
                // 4. Construimos la URL
                subdomainUrl = `https://${subdomain}.${rootDomain}`;
                
                // 5. Guardamos la URL en la base de datos
                await newRestaurant.update({ subdomain, subdomainUrl }, { transaction });
                subdomainCreated = true;
                
            } catch (subdomainError) {
                subdomainMessage = `Error al crear el subdominio: ${subdomainError.message}`;
                logger.error('[Restaurant-Service] Error al generar el subdominio:', subdomainError.message);
                // No detenemos la creación del restaurante, solo registramos el fallo.
            }
            // --- FIN DE LA LÓGICA DE SUBDOMINIO ---

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

            // Crear datos fiscales
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
                // Devolvemos el resultado de la operación del subdominio
                subdomain: { 
                    name: subdomain, 
                    url: subdomainUrl, 
                    created: subdomainCreated, 
                    message: subdomainMessage 
                }
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
            
            logger.error('[Restaurant-Service POST /] Error:', error);
            res.status(500).json({ 
                success: false, 
                message: error.message || 'Error al crear el restaurante.' 
            });
        }
    }
);

// En services/restaurant-service/server.js

// GET /catalogs/fiscal-regimes - Devuelve la lista de regímenes fiscales
app.get('/catalogs/fiscal-regimes', authenticateToken, async (req, res) => {
    try {
        // El query param 'type' permitirá al frontend filtrar (ej. /catalogs/fiscal-regimes?type=F)
        const { type } = req.query;
        let whereClause = {};

        if (type === 'F' || type === 'M') {
            whereClause.person_type = type;
        }

        const regimes = await FiscalRegime.findAll({
            where: whereClause,
            order: [['description', 'ASC']]
        });

        res.status(200).json({ success: true, regimes });
    } catch (error) {
        logger.error('[Restaurant-Service /catalogs/fiscal-regimes] Error:', error);
        res.status(500).json({ success: false, message: 'Error al obtener el catálogo.' });
    }
});

// Endpoint para redirigir a la última versión del instalador
app.get('/public/latest-installer', async (req, res) => {
    const publicDir = path.join(__dirname, 'secure_uploads', 'public');
    const filePrefix = 'NextFactura-Connector-';
    const fileSuffix = '.msi';

    try {
        const allFiles = await fs.readdir(publicDir);

        // 1. Filtramos solo los archivos que nos interesan
        const installerFiles = allFiles.filter(file => 
            file.startsWith(filePrefix) && file.endsWith(fileSuffix)
        );

        if (installerFiles.length === 0) {
            return res.status(404).json({ success: false, message: 'No se encontró ningún instalador.' });
        }

        // 2. Extraemos las versiones usando semver
        const versions = installerFiles.map(file => {
            const versionString = file.substring(filePrefix.length, file.length - fileSuffix.length);
            return semver.valid(semver.coerce(versionString)); // Limpia y valida la versión
        }).filter(Boolean); // Filtra cualquier versión nula o inválida

        if (versions.length === 0) {
            return res.status(404).json({ success: false, message: 'No se encontraron versiones válidas.' });
        }

        // 3. Ordenamos las versiones (la más alta primero)
        versions.sort(semver.rcompare);
        const latestVersion = versions[0];

        // 4. Construimos el nombre del archivo final
        const latestFilename = `${filePrefix}${latestVersion}${fileSuffix}`;

        // 5. Redirigimos al usuario al endpoint de descarga que ya tienes
        res.redirect(302, `/api/restaurants/public/${latestFilename}`);
        
    } catch (error) {
        logger.error('[Restaurant-Service /latest-installer] Error:', error);
        res.status(500).json({ success: false, message: 'Error al buscar el último instalador.' });
    }
});

// Endpoint interno para que otros servicios obtengan datos de un restaurante
app.get('/internal/data/:restaurantId', authenticateService, async (req, res) => {
    try {
        const restaurant = await Restaurant.findByPk(req.params.restaurantId);
        if (!restaurant) {
            return res.status(404).json({ success: false, message: 'Restaurante no encontrado.' });
        }
        res.status(200).json({ success: true, restaurant });
    } catch (error) {
        res.status(500).json({ success: false, message: 'Error interno.' });
    }
});

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


// Endpoint para verificar la disponibilidad de un subdominio
app.get('/subdomain/check', authenticateToken, async (req, res) => {
    const { name } = req.query;

    // 1. Validar la entrada
    if (!name || name.trim().length < 3) {
        return res.status(400).json({ 
            success: false, 
            available: false,
            message: "El nombre del subdominio debe tener al menos 3 caracteres." 
        });
    }

    // 2. Validar el formato (solo letras minúsculas, números y guiones)
    const subdomainRegex = /^[a-z0-9]+(?:-[a-z0-9]+)*$/;
    if (!subdomainRegex.test(name)) {
        return res.status(400).json({
            success: false,
            available: false,
            message: "Formato inválido. Solo se permiten letras, números y guiones."
        });
    }

    try {
        // 3. Buscar en la base de datos si ya existe
        const existing = await Restaurant.findOne({
            where: {
                subdomain: name
            }
        });

        // 4. Enviar la respuesta de disponibilidad
        if (existing) {
            res.status(200).json({ success: true, available: false, message: "Este subdominio ya está en uso." });
        } else {
            res.status(200).json({ success: true, available: true });
        }

    } catch (error) {
        logger.error('[Restaurant-Service /subdomain/check] Error:', error);
        res.status(500).json({ success: false, available: false, message: 'Error interno del servidor.' });
    }
});

// En services/restaurant-service/server.js

// --- NUEVO ENDPOINT PÚBLICO PARA DATOS DEL PORTAL ---
// No lleva 'authenticateToken' porque es para clientes finales.
app.get('/public/data/:restaurantId', async (req, res) => {
    try {
        const { restaurantId } = req.params;
        const restaurant = await Restaurant.findByPk(restaurantId, {
            include: [{
                model: PortalConfig,
                attributes: ['portalName', 'logoUrl', 'primaryColor']
            }]
        });

        if (!restaurant) {
            return res.status(404).json({ success: false, message: 'Restaurante no encontrado.' });
        }
        
        // Devolvemos el objeto completo del restaurante con sus datos de portal anidados
        res.status(200).json({ success: true, restaurant });

    } catch (error) {
        console.error(`[Service /public/data] Error:`, error);
        res.status(500).json({ success: false, message: 'Error al obtener datos del restaurante.' });
    }
});

// --- NUEVO ENDPOINT: Descarga Segura del Conector ---
// Este endpoint es llamado por el FRONTEND de un usuario logueado.
app.get('/connector/download', authenticateToken, async (req, res) => {
    try {
        const userId = req.user.id;

        // 1. VERIFICAR LA SUSCRIPCIÓN ACTIVA DEL USUARIO
        // Asumiendo que tienes un modelo PlanPurchase
        const activeSubscription = await PlanPurchase.findOne({
            where: { userId: userId, status: 'active' }
        });

        if (!activeSubscription) {
            return res.status(403).json({ 
                success: false, 
                message: 'Acceso denegado. Se requiere un plan activo para descargar el conector.' 
            });
        }

        // 2. SERVIR EL ARCHIVO DE FORMA SEGURA
        // La ruta donde moviste el instalador en el servidor.
        const filePath = '/downloads/NextFactura Connector 1.0.0.msi';        
        console.log(`[Service] Usuario ${userId} ha iniciado la descarga del conector.`);
        
        // El método res.download() de Express envía el archivo al navegador.
        res.download(filePath);

    } catch (error) {
        console.error('[Service /connector/download] Error:', error);
        res.status(500).json({ success: false, message: 'No se pudo procesar la descarga.' });
    }
});

// --- NUEVO ENDPOINT: Validación Interna de Clave de Agente ---
// Este endpoint es llamado SOLAMENTE por el connector-service.
app.post('/internal/validate-agent-key', async (req, res) => {
    const { agentKey } = req.body;

    if (!agentKey) {
        return res.status(400).json({ success: false, message: 'Falta agentKey.' });
    }

    try {
        // Buscamos un restaurante que tenga esa clave de agente
        const restaurant = await Restaurant.findOne({
            where: { agentKey: agentKey },
            attributes: ['id', 'name'] // Solo devolvemos los datos necesarios
        });

        if (restaurant) {
            // La clave es válida, devolvemos el ID del restaurante
            console.log(`[Service] Clave de agente validada para restaurante: ${restaurant.name}`);
            res.status(200).json({ success: true, restaurantId: restaurant.id });
        } else {
            // La clave no corresponde a ningún restaurante
            console.warn(`[Service] Intento de conexión con clave de agente inválida: ${agentKey}`);
            res.status(404).json({ success: false, message: 'Clave de agente no encontrada.' });
        }
    } catch (error) {
        console.error('[Service] Error validando clave de agente:', error);
        res.status(500).json({ success: false, message: 'Error interno del servidor.' });
    }
});

// --- ENDPOINTS PÚBLICOS PARA EL PORTAL DE AUTOFACTURACIÓN ---

// 1. OBTENER DATOS DE BRANDING POR SUBDOMINIO
// =======================================================
// EN services/restaurant-service/server.js

app.get('/portal-branding/:subdomain', async (req, res) => {
    try {
        const { subdomain } = req.params;

        const restaurant = await Restaurant.findOne({
            where: { subdomain: subdomain },
            // Usamos 'include' para traer los datos de la tabla relacionada 'portal_configs'
            include: [{
                model: PortalConfig,
                // Pedimos los campos que ahora existen en nuestro modelo PortalConfig
                attributes: ['portalName', 'logoUrl', 'primaryColor'] 
            }],
            // De la tabla 'restaurants' solo necesitamos el ID
            attributes: ['id'] 
        });

        if (!restaurant || !restaurant.PortalConfig) {
            return res.status(404).json({ success: false, message: 'Restaurante o configuración de portal no encontrados.' });
        }

        // Los datos ahora vienen anidados en el objeto PortalConfig
        const brandingData = {
            restaurantId: restaurant.id,
            name: restaurant.PortalConfig.portalName, // Usamos el nombre del portal
            logoUrl: restaurant.PortalConfig.logoUrl, // Sequelize maneja el mapeo de 'portalLogoUrl'
            primaryColor: restaurant.PortalConfig.primaryColor || '#005DAB'
        };
        
        res.status(200).json({ success: true, branding: brandingData });

    } catch (error) {
        console.error(`[Service /portal-branding] Error:`, error);
        res.status(500).json({ success: false, message: 'Error al obtener la información del portal.' });
    }
});


// En services/restaurant-service/server.js

app.post('/portal/:restaurantId/search-ticket', async (req, res) => {
    const { restaurantId } = req.params;
    const { ticketNumber } = req.body;

    if (!ticketNumber) {
        return res.status(400).json({ success: false, message: 'El número de ticket es requerido.' });
    }

    try {
        // Obtenemos el restaurante y sus datos de conexión de una sola vez.
        const restaurant = await Restaurant.findByPk(restaurantId);
        if (!restaurant) {
            return res.status(404).json({ success: false, message: 'Restaurante no configurado.' });
        }
        
        // Creamos la consulta SQL para buscar el ticket
        const query = `SELECT TOP 1 total, fecha FROM cheques WHERE numcheque = '${ticketNumber.replace(/'/g, "''")}' AND pagado = 1`;
        let ticketData;

        // Decidimos la estrategia (Agente o Directa)
        if (restaurant.connectionMethod === 'agent') {
            const correlationId = uuidv4();
            const commandPromise = new Promise((resolve, reject) => {
                pendingRequests.set(correlationId, { resolve, reject });
                setTimeout(() => {
                    if (pendingRequests.has(correlationId)) {
                        pendingRequests.delete(correlationId);
                        reject(new Error('Timeout: El agente del restaurante no respondió a tiempo.'));
                    }
                }, 30000); // Timeout de 30 segundos
            });

            // Enviamos el comando al connector-service
            await fetch(`http://connector-service:4006/internal/send-command`, {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({
                    clientId: restaurantId,
                    command: 'search_ticket',
                    correlationId: correlationId,
                    data: { sql: query }
                })
            });

            const agentResponse = await commandPromise;
            ticketData = agentResponse[0]; // El agente devuelve un array
        } else {
            // Usamos los datos de conexión del objeto 'restaurant' para la conexión directa
            const pool = await getConnectedPool({
                user: restaurant.connectionUser, 
                password: restaurant.connectionPassword,
                server: restaurant.connectionHost, 
                database: restaurant.connectionDbName,
                port: restaurant.connectionPort,
            });
            const result = await pool.request().query(query);
            ticketData = result.recordset[0];
            await pool.close();
        }

        if (!ticketData) {
            return res.status(404).json({ success: false, message: 'Ticket no encontrado, ya facturado o inválido.' });
        }

        res.status(200).json({
            success: true,
            ticket: { id: ticketNumber, amount: ticketData.total, date: ticketData.fecha }
        });

    } catch (error) {
        console.error(`[Service /search-ticket] Error:`, error);
        res.status(500).json({ success: false, message: error.message || 'Error al buscar el ticket.' });
    }
});


// 3. GENERAR LA FACTURA FINAL
// En services/restaurant-service/server.js

// 3. GENERAR LA FACTURA FINAL
// =======================================================
// En services/restaurant-service/server.js

// --- ENDPOINT FINAL Y COMPLETO ---
// En services/restaurant-service/server.js
app.post('/portal/:restaurantId/generate-invoice', async (req, res) => {
   const { restaurantId } = req.params;
    const { ticket, fiscalData: clientFiscalData } = req.body;
    const logPrefix = `[Service /generate-invoice]`; // Prefijo para todos los logs

    logger.info(`${logPrefix} Petición recibida para ticket ${ticket?.id} del restaurante ${restaurantId}`);

    if (!ticket || !clientFiscalData) {
        logger.warn(`${logPrefix} Petición inválida: Faltan datos del ticket o fiscales.`);
        return res.status(400).json({ success: false, message: 'Faltan datos del ticket o fiscales.' });
    }

    try {
        // --- 1. Obtener datos del Restaurante ---
        logger.info(`${logPrefix} Paso 1: Obteniendo datos del restaurante desde la BD.`);
        const restaurant = await Restaurant.findByPk(restaurantId, { include: [FiscalData] });
        if (!restaurant || !restaurant.FiscalDatum) {
            logger.error(`${logPrefix} Restaurante o sus datos fiscales no encontrados en la BD. ID: ${restaurantId}`);
            return res.status(404).json({ success: false, message: 'Datos fiscales del restaurante no encontrados.' });
        }
        logger.info(`${logPrefix} Restaurante "${restaurant.name}" encontrado. Método de conexión: ${restaurant.connectionMethod}.`);

        // --- 2. Obtener detalles completos del Ticket ---
        const detailsQuery = `SELECT cd.cantidad, cd.precio, p.descripcion FROM cheqdet cd JOIN Productos p ON cd.idproducto = p.idproducto WHERE cd.movimiento = '${ticket.id.replace(/'/g, "''")}'`;
        let ticketDetails;

        if (restaurant.connectionMethod === 'agent') {
            console.log(`[Service] Usando AGENTE para obtener detalles del ticket.`);
            const correlationId = uuidv4();
            const commandPromise = new Promise((resolve, reject) => {
                pendingRequests.set(correlationId, { resolve, reject });
                setTimeout(() => {
                    if (pendingRequests.has(correlationId)) {
                        pendingRequests.delete(correlationId);
                        reject(new Error('Timeout: El agente no respondió para obtener los detalles del ticket.'));
                    }
                }, 30000);
            });

            await fetch(`http://connector-service:4006/internal/send-command`, {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({
                    clientId: restaurantId,
                    command: 'get_ticket_details',
                    correlationId: correlationId,
                    data: { sql: detailsQuery }
                })
            });
            ticketDetails = await commandPromise;
        } else {
            console.log(`[Service] Usando CONEXIÓN DIRECTA para obtener detalles del ticket.`);
            const pool = await getConnectedPool({
                user: restaurant.connectionUser,
                password: restaurant.connectionPassword,
                server: restaurant.connectionHost,
                database: restaurant.connectionDbName,
                port: restaurant.connectionPort,
            });
            const result = await pool.request().query(detailsQuery);
            ticketDetails = result.recordset;
            await pool.close();
        }

        if (!ticketDetails || ticketDetails.length === 0) {
            return res.status(404).json({ success: false, message: 'No se encontraron los productos del ticket.' });
        }

        console.log(`[Service] Empaquetando y enviando datos al pac-service para timbrado.`);
        const certBase64 = await getFileAsBase64(restaurant.FiscalDatum.csdCertificateUrl);
        const keyBase64 = await getFileAsBase64(restaurant.FiscalDatum.csdKeyUrl);
        
        const pacServiceUrl = process.env.PAC_SERVICE_URL || 'http://pac-service:4005';
        
        const pacResponse = await fetch(`${pacServiceUrl}/stamp`, {
           method: 'POST',
           headers: { 
               'Content-Type': 'application/json',
               'X-Internal-Secret': process.env.INTERNAL_SECRET_KEY 
            },
           body: JSON.stringify({ 
               ticket: ticket,
               ticketDetails: ticketDetails, 
               clientFiscalData: clientFiscalData, 
               restaurantFiscalData: {
                   ...restaurant.FiscalDatum.toJSON(),
                   userId: restaurant.userId,
                   id: restaurant.id
               },
               csd: {
                   certBase64,
                   keyBase64,
                   password: restaurant.FiscalDatum.csdPassword
               }
            })
        });

        const invoiceResult = await pacResponse.json();
        if (!pacResponse.ok) {
            throw new Error(invoiceResult.message || 'El servicio de timbrado no pudo generar la factura.');
        }

        console.log(`[Service] Factura con UUID ${invoiceResult.uuid} generada exitosamente.`);
        const notificationServiceUrl = process.env.NOTIFICATION_SERVICE_URL || 'http://notification-service:4007';
        await fetch(`${notificationServiceUrl}/send-invoice`, {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({
                recipientEmail: clientFiscalData.email,
                pdfBase64: invoiceResult.pdf,
                xmlBase64: invoiceResult.xml,
                clientName: clientFiscalData.razonSocial,
                restaurantName: restaurant.name
            })
        });
        
        res.status(200).json({
            success: true,
            message: `Factura generada y enviada a ${clientFiscalData.email}.`,
            invoiceId: invoiceResult.uuid
        });

    } catch (error) {
        console.error(`[Service /generate-invoice] Error:`, error);
        res.status(500).json({ success: false, message: error.message || 'Error al generar la factura.' });
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