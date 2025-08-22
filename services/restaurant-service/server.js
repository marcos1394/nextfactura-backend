// --- ACTUALIZACIÓN DEL SERVER.JS CON MANEJO SEGURO DE ARCHIVOS Y SUBDOMINIOS ---

// Importar el módulo de archivos seguros
const { 
    secureUpload, 
    servePublicFile, 
    servePrivateFile, 
    createSecureDirectories,
    deleteRestaurantFiles 
} = require('./secure-file-handler');
const express = require('express');
const cors = require('cors');
const bodyParser = require('body-parser');
require('dotenv').config();


const redis = require('redis'); // <-- Asegúrate de que esta línea esté
const logger = require('./logger'); // Importa tu nuevo logger
const { Sequelize, DataTypes, Op, UUIDV4 } = require('sequelize');




// Importar el módulo de cPanel para subdominios
const { createCpanelSubdomain } = require('./cpanelApi');
const app = express();
app.use(cors());
app.use(bodyParser.json());
// --- INICIA BLOQUE NUEVO: Conexión a Redis ---
const redisClient = redis.createClient({
    url: process.env.REDIS_URL
});

redisClient.on('error', err => console.error('[Redis] Client Error', err));
// Conectamos una sola vez al iniciar el servidor
redisClient.connect().catch(err => {
    console.error('[Redis] No se pudo conectar a Redis. Las funciones de logout no estarán disponibles.', err);
});

// --- Conexión a Base de Datos ---
const sequelize = new Sequelize(process.env.DATABASE_URL, {
    dialect: 'postgres',
    logging: false, // Desactivar logs de SQL en producción
    dialectOptions: {
      ssl: { 
          require: false, 
          rejectUnauthorized: false // Requerido para Render
        }
    }
});


// --- Modelo de Datos: User (Expandido para características profesionales) ---
const User = sequelize.define('User', {
    id: { type: DataTypes.UUID, defaultValue: UUIDV4, primaryKey: true },
    name: { type: DataTypes.STRING, allowNull: true },
    email: { type: DataTypes.STRING, allowNull: false, unique: true, validate: { isEmail: true } },
    password: { type: DataTypes.STRING, allowNull: false },
    restaurantName: { type: DataTypes.STRING, allowNull: true },
    phoneNumber: { type: DataTypes.STRING, allowNull: true },
    role: { type: DataTypes.STRING, defaultValue: 'RestaurantOwners' },
    // Campos para restablecimiento de contraseña
    passwordResetToken: { type: DataTypes.STRING, allowNull: true },
    passwordResetExpires: { type: DataTypes.DATE, allowNull: true },
    // Campos para 2FA
    twoFactorSecret: { type: DataTypes.STRING, allowNull: true },
    isTwoFactorEnabled: { type: DataTypes.BOOLEAN, defaultValue: false },
    // Para Verificación de Correo Electrónico
    isEmailVerified: {
        type: DataTypes.BOOLEAN,
        defaultValue: false
    },
    emailVerificationToken: {
        type: DataTypes.STRING,
        allowNull: true
    },

    // Para Magic Links
    magicLinkToken: {
        type: DataTypes.STRING,
        allowNull: true
    },
    magicLinkExpires: {
        type: DataTypes.DATE,
        allowNull: true
    }
}, { 
    tableName: 'users', 
    timestamps: true 
});

const Restaurant = sequelize.define('Restaurant', {
  id: {
    type: DataTypes.UUID,
    defaultValue: DataTypes.UUIDV4,
    primaryKey: true,
  },
  userId: {
    type: DataTypes.UUID,
    allowNull: false,
  },
  name: {
    type: DataTypes.STRING,
    allowNull: false,
  },
  address: {
    type: DataTypes.STRING,
  },
  logoUrl: {
    type: DataTypes.STRING,
  },
  connectionHost: { type: DataTypes.STRING },
  connectionPort: { type: DataTypes.STRING },
  connectionUser: { type: DataTypes.STRING },
  connectionPassword: { type: DataTypes.STRING },
  connectionDbName: { type: DataTypes.STRING },
  vpnUsername: { type: DataTypes.STRING },
  vpnPassword: { type: DataTypes.STRING },
}, {
  tableName: 'restaurants',
  timestamps: true,
  paranoid: true, // Habilita soft delete (usa la columna deletedAt)
});

// Modelo de Datos Fiscales
const FiscalData = sequelize.define('FiscalData', {
  id: {
    type: DataTypes.UUID,
    defaultValue: DataTypes.UUIDV4,
    primaryKey: true,
  },
  restaurantId: {
    type: DataTypes.UUID,
    allowNull: false,
  },
  rfc: { type: DataTypes.STRING },
  businessName: { type: DataTypes.STRING },
  fiscalRegime: { type: DataTypes.STRING },
  csdCertificateUrl: { type: DataTypes.STRING },
  csdKeyUrl: { type: DataTypes.STRING },
  csdPassword: { type: DataTypes.STRING },
}, {
  tableName: 'fiscal_data',
  timestamps: true,
});





const Role = sequelize.define('Role', {
    name: {
        type: DataTypes.STRING,
        allowNull: false,
        unique: true
    }
}, { timestamps: false });

const Permission = sequelize.define('Permission', {
    name: {
        type: DataTypes.STRING,
        allowNull: false,
        unique: true
    },
    description: {
        type: DataTypes.STRING
    }
}, { timestamps: false });

const AuditLog = sequelize.define('AuditLog', {
    id: { type: DataTypes.UUID, defaultValue: UUIDV4, primaryKey: true },
    userId: { type: DataTypes.UUID, allowNull: true },
    action: { type: DataTypes.STRING, allowNull: false }, // ej: 'LOGIN_SUCCESS', 'PASSWORD_RESET_REQUEST'
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

// --- 3. Definición de Relaciones (Asociaciones) ---
Restaurant.hasOne(FiscalData, { foreignKey: 'restaurantId' });
FiscalData.belongsTo(Restaurant, { foreignKey: 'restaurantId' });


const authenticateToken = async (req, res, next) => {
    const authHeader = req.headers['authorization'];
    const token = authHeader && authHeader.split(' ')[1];
    if (!token) return res.status(401).json({ success: false, message: 'Acceso denegado. Token no proporcionado.' });

    try {
        const decoded = jwt.verify(token, process.env.JWT_SECRET, { ignoreExpiration: false });

        // Si Redis está conectado, revisa la lista negra
        if (redisClient.isOpen) {
            const isBlacklisted = await redisClient.get(`blacklist:${decoded.jti}`);
            if (isBlacklisted) {
                return res.status(401).json({ success: false, message: 'Token revocado. Por favor, inicia sesión de nuevo.' });
            }
        }

        req.user = decoded;
        next();
    } catch (err) {
        return res.status(403).json({ success: false, message: 'Token inválido o expirado.' });
    }
};

// Inicializar directorios seguros al arrancar
createSecureDirectories().catch(console.error);

// ELIMINAR estas líneas inseguras:
// app.use('/uploads', express.static(uploadsDir));
// const upload = multer({ storage: storage });

// REEMPLAZAR con rutas seguras:

// Servir archivos públicos (solo logos) de forma segura
app.get('/public/:filename', servePublicFile);

// Servir archivos privados (certificados CSD) solo al dueño
app.get('/restaurants/:restaurantId/private/:filename', authenticateToken, servePrivateFile);

// Función auxiliar para construir URLs seguras
const buildSecureFileUrl = (filename, isPublic = true, restaurantId = null) => {
    if (!filename) return null;
    
    const baseUrl = process.env.BASE_URL || 'http://localhost:4002';
    
    if (isPublic) {
        return `${baseUrl}/public/${filename}`;
    } else {
        return `${baseUrl}/restaurants/${restaurantId}/private/${filename}`;
    }
};

// Función auxiliar para generar nombre de subdominio válido
const generateSubdomainName = (restaurantName, restaurantId) => {
    // Normalizar el nombre del restaurante
    let subdomain = restaurantName
        .toLowerCase()
        .normalize('NFD')
        .replace(/[\u0300-\u036f]/g, '') // Remover acentos
        .replace(/[^a-z0-9]/g, '-') // Reemplazar caracteres especiales con guiones
        .replace(/-+/g, '-') // Reemplazar múltiples guiones consecutivos con uno solo
        .replace(/^-|-$/g, '') // Remover guiones al inicio y final
        .substring(0, 20); // Limitar longitud
    
    // Si queda muy corto o vacío, usar el ID del restaurante
    if (subdomain.length < 3) {
        subdomain = `restaurant-${restaurantId}`;
    }
    
    // Asegurar que no empiece con número (algunos servidores no lo permiten)
    if (/^\d/.test(subdomain)) {
        subdomain = `r-${subdomain}`;
    }
    
    return subdomain;
};

// [POST] Crear un nuevo restaurante
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
            // 1. Validación de Plan (sin cambios)
            // ... (tu lógica de validación de plan)

            // 2. Procesar datos del body
            const { restaurantData, fiscalData } = req.body;
            const userId = req.user.id;

            if (!restaurantData || !fiscalData) {
                return res.status(400).json({ success: false, message: 'Faltan los objetos restaurantData o fiscalData.' });
            }
            
            const parsedRestaurantData = JSON.parse(restaurantData);
            const parsedFiscalData = JSON.parse(fiscalData);
            
            if (!parsedRestaurantData.name || parsedRestaurantData.name.trim().length === 0) {
                return res.status(400).json({ success: false, message: 'El nombre del restaurante es requerido.' });
            }

            // 3. Crear restaurante en la BD para obtener ID
            const newRestaurant = await Restaurant.create({ 
                ...parsedRestaurantData, 
                userId
            }, { transaction });
            const restaurantId = newRestaurant.id;

            // 4. Crear subdominio (con manejo de errores)
            let subdomain = null;
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
                console.error('[Restaurant-Service] Error al crear subdominio:', subdomainError);
                // La operación continúa aunque el subdominio falle
            }
            
            // 5. Construir URLs seguras y actualizar registros
            const logoFile = req.files?.logo?.[0];
            const csdCertificateFile = req.files?.csdCertificate?.[0];
            const csdKeyFile = req.files?.csdKey?.[0];

            const logoUrl = logoFile ? buildSecureFileUrl(logoFile.filename, true) : null;
            const csdCertificateUrl = csdCertificateFile ? buildSecureFileUrl(csdCertificateFile.filename, false, restaurantId) : null;
            const csdKeyUrl = csdKeyFile ? buildSecureFileUrl(csdKeyFile.filename, false, restaurantId) : null;
            
            if (logoUrl) {
                await newRestaurant.update({ logoUrl }, { transaction });
            }

            const newFiscalData = await FiscalData.create({ 
                ...parsedFiscalData, 
                restaurantId,
                csdCertificateUrl,
                csdKeyUrl
            }, { transaction });
            
            await transaction.commit();
            
            // 6. Enviar respuesta segura
            const safeRestaurant = newRestaurant.toJSON();
            const safeFiscalData = newFiscalData.toJSON();
            delete safeFiscalData.csdPassword;
            
            res.status(201).json({ 
                success: true, 
                restaurant: safeRestaurant, 
                fiscalData: safeFiscalData,
                subdomain: { name: subdomain, url: subdomainUrl, created: !!subdomainUrl }
            });

        } catch (error) {
            await transaction.rollback();
            // Limpiar archivos subidos en caso de error
            if (req.files) {
                for (const field in req.files) {
                    req.files[field].forEach(file => {
                        fs.unlink(file.path).catch(console.error);
                    });
                }
            }
            console.error('[Restaurant-Service /] Error:', error);
            res.status(500).json({ success: false, message: error.message || 'Error al crear el restaurante.' });
        }
    }
);

// [PUT] Actualizar un restaurante existente
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

        // Procesar datos de texto
        let restaurantData = req.body.restaurantData;
        let fiscalData = req.body.fiscalData;
        
        if (typeof restaurantData === 'string') {
            restaurantData = JSON.parse(restaurantData);
        }
        if (typeof fiscalData === 'string') {
            fiscalData = JSON.parse(fiscalData);
        }

        // Manejar archivos nuevos
        const updates = { ...restaurantData };
        
        if (req.files?.logo) {
            // Eliminar logo anterior si existe
            if (restaurant.logoUrl) {
                const oldFilename = path.basename(restaurant.logoUrl);
                const oldPath = path.join(__dirname, 'secure_uploads', 'public', oldFilename);
                fs.unlink(oldPath).catch(console.error);
            }
            
            updates.logoUrl = buildSecureFileUrl(req.files.logo[0].filename, true);
        }

        // --- MANEJO DE ACTUALIZACIÓN DE SUBDOMINIO ---
        // Si se cambió el nombre del restaurante y no tiene subdominio, crear uno nuevo
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
                    
                    console.log(`[Restaurant-Service] Subdominio creado para restaurante existente: ${updates.subdomainUrl}`);
                }
                
            } catch (subdomainError) {
                console.error('[Restaurant-Service] Error al crear subdominio durante actualización:', subdomainError);
                // Continuar sin subdominio en caso de error
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
                // Eliminar certificado anterior
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
                // Eliminar llave anterior
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
        
        // Obtener datos actualizados sin información sensible
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
        
        // Limpiar archivos subidos en caso de error
        if (req.files) {
            Object.values(req.files).flat().forEach(file => {
                fs.unlink(file.path).catch(console.error);
            });
        }
        
        console.error(`[Restaurant-Service PUT /${id}] Error:`, error);
        res.status(500).json({ 
            success: false, 
            message: error.message || 'Error al actualizar el restaurante.' 
        });
    }
});

// --- ENDPOINT ACTUALIZADO PARA ELIMINAR RESTAURANTE ---
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
        
        // Eliminar archivos antes del borrado lógico
        await deleteRestaurantFiles(id);
        
        // NOTA: Aquí podrías agregar lógica para eliminar el subdominio de cPanel
        // si decides implementar esa funcionalidad
        if (restaurant.subdomain) {
            console.log(`[Restaurant-Service] NOTA: El subdominio ${restaurant.subdomain} del restaurante ${id} debe ser eliminado manualmente de cPanel`);
            // Implementar deleteSubdomain si es necesario
        }
        
        // Sequelize `destroy` con `paranoid: true` hará un borrado lógico
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

// --- ENDPOINT PARA OBTENER RESTAURANTES (ACTUALIZADO) ---
app.get('/', authenticateToken, async (req, res) => {
    const userId = req.user.id;
    try {
        const restaurants = await Restaurant.findAll({ 
            where: { userId },
            include: [{ 
                model: FiscalData, 
                attributes: { exclude: ['csdPassword'] } // Excluir campos sensibles
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

// --- ENDPOINT PARA OBTENER UN RESTAURANTE (ACTUALIZADO) ---
app.get('/:id', authenticateToken, async (req, res) => {
    const { id } = req.params;
    const userId = req.user.id;
    
    try {
        const restaurant = await Restaurant.findOne({
            where: { id, userId },
            include: [{
                model: FiscalData,
                attributes: { exclude: ['csdPassword'] } // Excluir campos sensibles
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

// --- ENDPOINT ADICIONAL PARA VERIFICAR DISPONIBILIDAD DE SUBDOMINIO ---
app.get('/subdomain/check/:name', authenticateToken, async (req, res) => {
    const { name } = req.params;
    
    try {
        // Normalizar el nombre propuesto
        const normalizedName = generateSubdomainName(name, 'temp');
        
        // Verificar si ya existe en la base de datos
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

// --- ARRANQUE DEL SERVIDOR (VERSIÓN ROBUSTA) ---
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