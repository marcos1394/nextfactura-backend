// --- services/auth-service/server.js (Versión Profesional y Completa) ---

// Carga las variables de entorno para este servicio
require('dotenv').config();
const logger = require('./logger'); // Importa tu nuevo logger

// --- Imports de Librerías ---
const express = require('express');
const bodyParser = require('body-parser');
const cors = require('cors');
const { Sequelize, DataTypes, Op, UUIDV4 } = require('sequelize');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const crypto = require('crypto'); // Para generar tokens seguros de un solo uso
const { Resend } = require('resend'); // Para enviar correos transaccionales
const { authenticator } = require('otplib'); // Para generar y verificar códigos 2FA
const qrcode = require('qrcode'); // Para generar códigos QR para 2FA
const passport = require('passport');
const GoogleStrategy = require('passport-google-oauth20').Strategy;
const redis = require('redis'); // <-- Asegúrate de que esta línea esté


const app = express();
app.use(cors());
app.use(bodyParser.json());
//app.use(passport.initialize());


// --- Inicialización de Servicios Externos ---
// Solo inicializa Resend si la API KEY está presente
const resend = process.env.RESEND_API_KEY ? new Resend(process.env.RESEND_API_KEY) : null;

// --- INICIA BLOQUE NUEVO: Conexión a Redis ---
const redisClient = redis.createClient({
    url: process.env.REDIS_URL
});

redisClient.on('error', err => console.error('[Redis] Client Error', err));


// Conectamos una sola vez al iniciar el servidor
redisClient.connect().catch(err => {
    console.error('[Redis] No se pudo conectar a Redis. Las funciones de logout no estarán disponibles.', err);
});

passport.use(new GoogleStrategy({
    clientID: process.env.GOOGLE_CLIENT_ID,
    clientSecret: process.env.GOOGLE_CLIENT_SECRET,
    callbackURL: "/auth/google/callback" // El Gateway redirigirá a esta ruta interna
  },
  async (accessToken, refreshToken, profile, done) => {
    try {
        const [user, created] = await User.findOrCreate({
            where: { email: profile.emails[0].value },
            defaults: {
                name: profile.displayName,
                isEmailVerified: true // El email de Google ya está verificado
            }
        });
        return done(null, user);
    } catch (error) {
        return done(error, null);
    }
  }
));

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
    features: { type: DataTypes.JSONB, allowNull: true }, // Ej: {"reports": true, "users": 5}
    mercadopagoId: { type: DataTypes.STRING, allowNull: true }, // ID del plan en Mercado Pago si se usan suscripciones
    isActive: { type: DataTypes.BOOLEAN, defaultValue: true }
}, { tableName: 'plans', timestamps: true });


const PlanPurchase = sequelize.define('PlanPurchase', {
    id: { type: DataTypes.INTEGER, primaryKey: true, autoIncrement: true },
    userId: { type: DataTypes.UUID, allowNull: false },
    planId: { type: DataTypes.UUID, allowNull: false },
    origin: { type: DataTypes.STRING, allowNull: false },
    status: { type: DataTypes.STRING, allowNull: false, defaultValue: 'pending' },
    price: { type: DataTypes.DOUBLE, allowNull: false },
    purchaseDate: { type: DataTypes.DATE },
    expirationDate: { type: DataTypes.DATE },
    paymentId: { type: DataTypes.STRING, unique: true },
    paymentProvider: { type: DataTypes.STRING, defaultValue: 'mercadopago' },
    preferenceId: { type: DataTypes.STRING }
}, { 
    tableName: 'plan_purchases', 
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



// --- Definición de Relaciones ---
User.belongsToMany(Role, { through: 'UserRoles' });
Role.belongsToMany(User, { through: 'UserRoles' });

Role.belongsToMany(Permission, { through: 'RolePermissions' });
Permission.belongsToMany(Role, { through: 'RolePermissions' });

// --- INICIO: RELACIONES NUEVAS ---
// Un usuario puede tener muchas compras de planes.
User.hasMany(PlanPurchase, { foreignKey: 'userId' });
PlanPurchase.belongsTo(User, { foreignKey: 'userId' });

// Un usuario puede tener muchos restaurantes.
User.hasMany(Restaurant, { foreignKey: 'userId' });
Restaurant.belongsTo(User, { foreignKey: 'userId' });

// --- RELACIÓN FALTANTE AÑADIDA ---
Plan.hasMany(PlanPurchase, { foreignKey: 'planId' });
PlanPurchase.belongsTo(Plan, { foreignKey: 'planId' });

// --- Funciones Auxiliares ---
async function sendEmail(to, subject, html) {
    if (!resend) {
        console.warn(`[Email] RESEND_API_KEY no configurada. Saltando envío de correo a ${to}`);
        return;
    }
    try {
        await resend.emails.send({
            from: `NextManager <${process.env.EMAIL_FROM || 'onboarding@resend.dev'}>`,
            to,
            subject,
            html,
        });
        console.log(`[Email] Correo enviado exitosamente a ${to}`);
    } catch (error) {
        console.error(`[Email] Error al enviar correo a ${to}:`, error.message);
    }
}

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
// --- Middleware de Auditoría ---
const auditTrail = (action) => async (req, res, next) => {
    // Se ejecuta después de que la ruta principal ha terminado
    res.on('finish', () => {
        AuditLog.create({
            action: action,
            userId: req.user ? req.user.id : null,
            ipAddress: req.ip,
            userAgent: req.get('User-Agent'),
            details: `Status: ${res.statusCode}`
        }).catch(err => console.error("Error en AuditLog:", err));
    });
    next();
};

// --- Rutas del Servicio de Autenticación ---

app.post('/test-crash', (req, res) => {
    console.log('[SMOKE TEST] >>> Petición recibida en /test-crash');
    console.log('[SMOKE TEST] >>> Cuerpo de la petición:', req.body);
    res.status(200).json({
        success: true,
        message: '¡ÉXITO! Si ves esto, el servidor base y los middlewares funcionan.',
        received_body: req.body
    });
});

// POST /register
app.post('/register', async (req, res) => {
    const { name, email, password, restaurantName } = req.body;
    if (!email || !password) return res.status(400).json({ success: false, message: 'Email y contraseña son requeridos.' });
    
    try {
        const hashedPassword = await bcrypt.hash(password, 10);
        const user = await User.create({ name, email: email.toLowerCase(), password: hashedPassword, restaurantName });
        
        const welcomeHtml = `<h1>¡Bienvenido a NextManager, ${name || 'usuario'}!</h1><p>Tu cuenta ha sido creada exitosamente. Ya puedes iniciar sesión.</p>`;
        sendEmail(user.email, '¡Bienvenido a NextManager!', welcomeHtml).catch(console.error);

        res.status(201).json({ success: true, message: 'Usuario registrado con éxito.', userId: user.id });
    } catch (error) {
        if (error.name === 'SequelizeUniqueConstraintError') {
            return res.status(409).json({ success: false, message: 'El correo electrónico ya está en uso.' });
        }
        console.error('[Auth-Service /register] Error:', error);
        res.status(500).json({ success: false, message: 'Error interno al registrar el usuario.' });
    }
});

app.get('/health', (req, res) => {
  res.status(200).json({ status: 'ok' });
});


// auth-service/server.js
// POST /login (Versión con Logs Detallados y Medición de Rendimiento)
app.post('/login', async (req, res) => {
    // Log para confirmar que la petición LLEGÓ al endpoint.
    console.log(`[Auth-Service /login] Petición recibida para el email: ${req.body.email}`);
    
    const { email, password } = req.body;
    
    try {
        // --- 1. Búsqueda del Usuario ---
        console.log(`[Auth-Service /login] Paso 1: Buscando usuario en la base de datos...`);
        console.time('DB_USER_LOOKUP'); // Inicia el cronómetro
        const user = await User.findOne({ where: { email: email.toLowerCase() } });
        console.timeEnd('DB_USER_LOOKUP'); // Detiene y muestra el tiempo

        if (!user) {
            console.warn(`[Auth-Service /login] ADVERTENCIA: Usuario no encontrado con el email: ${email}`);
            return res.status(401).json({ success: false, message: 'Credenciales inválidas.' });
        }
        console.log(`[Auth-Service /login] ÉXITO: Usuario encontrado con ID: ${user.id}`);

        // --- 1.5. Comparación de Contraseña (la operación más lenta) ---
        console.log(`[Auth-Service /login] Paso 1.5: Comparando contraseña con bcrypt...`);
        console.time('BCRYPT_COMPARE'); // Inicia el cronómetro
        const isMatch = await bcrypt.compare(password, user.password);
        console.timeEnd('BCRYPT_COMPARE'); // Detiene y muestra el tiempo

        if (!isMatch) {
            console.warn(`[Auth-Service /login] ADVERTENCIA: Contraseña incorrecta para el usuario: ${email}`);
            return res.status(401).json({ success: false, message: 'Credenciales inválidas.' });
        }
        console.log(`[Auth-Service /login] ÉXITO: La contraseña coincide.`);

        // --- Chequeo de 2FA ---
        if (user.isTwoFactorEnabled) {
            console.log(`[Auth-Service /login] INFO: 2FA está activado. Solicitando código.`);
            return res.status(200).json({ 
                success: true, 
                twoFactorRequired: true, 
                message: "Por favor, ingresa tu código de autenticación." 
            });
        }
        
        // --- 2. Búsqueda de Suscripción ---
        console.log(`[Auth-Service /login] Paso 2: Verificando suscripción activa...`);
        const activeSubscription = await PlanPurchase.findOne({
            where: { 
                userId: user.id,
                status: 'active'
            }
        });
        console.log(`[Auth-Service /login] INFO: ¿Tiene plan activo? ${!!activeSubscription}`);

        // --- 3. Conteo de Restaurantes ---
        console.log(`[Auth-Service /login] Paso 3: Contando restaurantes...`);
        const restaurantCount = await Restaurant.count({
            where: { userId: user.id }
        });
        console.log(`[Auth-Service /login] INFO: Número de restaurantes: ${restaurantCount}`);
        
        const userStatus = {
            hasPlan: !!activeSubscription,
            hasRestaurant: restaurantCount > 0
        };

        // --- 4. Generación del Token ---
        console.log(`[Auth-Service /login] Paso 4: Generando token JWT...`);
        const jti = crypto.randomUUID();
        const tokenPayload = { id: user.id, email: user.email, role: user.role, jti: jti };
        const token = jwt.sign(tokenPayload, process.env.JWT_SECRET, { expiresIn: process.env.JWT_EXPIRES_IN || '7d' });
        
        const userResponse = user.toJSON();
        delete userResponse.password;
        
        console.log(`[Auth-Service /login] ÉXITO FINAL: Enviando respuesta con token y estado del usuario.`);
        res.json({ 
            success: true, 
            token: `Bearer ${token}`, 
            user: userResponse,
            status: userStatus
        });

    } catch (error) {
        // Log para cualquier error inesperado en el proceso.
        console.error(`[Auth-Service /login] ERROR CATASTRÓFICO durante el login para ${email}:`, error);
        res.status(500).json({ success: false, message: 'Error interno del servidor.' });
    }
});

// GET /me
app.get('/me', authenticateToken, async (req, res) => {
    try {
        const user = await User.findByPk(req.user.id, {
            attributes: { exclude: ['password', 'passwordResetToken', 'passwordResetExpires', 'twoFactorSecret'] }
        });
        if (!user) return res.status(404).json({ success: false, message: 'Usuario no encontrado.' });
        res.json({ success: true, user });
    } catch (error) {
        console.error('[Auth-Service /me] Error:', error);
        res.status(500).json({ success: false, message: 'Error interno del servidor.' });
    }
});

// --- Rutas de Gestión de Contraseña ---

// POST /password/change - Para usuarios logueados que quieren cambiar su contraseña
app.post('/password/change', authenticateToken, async (req, res) => {
    const { currentPassword, newPassword } = req.body;
    if (!currentPassword || !newPassword) return res.status(400).json({ success: false, message: 'La contraseña actual y la nueva son requeridas.' });
    
    try {
        const user = await User.findByPk(req.user.id);
        if (!await bcrypt.compare(currentPassword, user.password)) {
            return res.status(401).json({ success: false, message: 'La contraseña actual es incorrecta.' });
        }
        user.password = await bcrypt.hash(newPassword, 10);
        await user.save();
        res.status(200).json({ success: true, message: 'Contraseña actualizada exitosamente.' });
    } catch (error) {
        console.error('[Auth-Service /password/change] Error:', error);
        res.status(500).json({ success: false, message: 'Error interno al cambiar la contraseña.' });
    }
});


// POST /password/forgot
app.post('/password/forgot', async (req, res) => {
    const { email } = req.body;
    try {
        const user = await User.findOne({ where: { email: email.toLowerCase() } });
        if (user) {
            const resetToken = crypto.randomBytes(32).toString('hex');
            console.log('--- TOKEN DE RESETEO PARA PRUEBAS ---:', resetToken);

            user.passwordResetToken = crypto.createHash('sha256').update(resetToken).digest('hex');
            user.passwordResetExpires = Date.now() + 10 * 60 * 1000; // 10 minutos de validez
            await user.save();
            const resetUrl = `${process.env.CLIENT_URL_PROD}/reset-password?token=${resetToken}`;
            const emailHtml = `<h1>Restablecimiento de Contraseña</h1><p>Recibiste este correo porque solicitaste restablecer tu contraseña. Haz clic en el siguiente enlace para continuar:</p><a href="${resetUrl}" style="color: blue;">${resetUrl}</a><p>Si no solicitaste esto, ignora este correo. El enlace expira en 10 minutos.</p>`;
            sendEmail(user.email, 'Restablecimiento de Contraseña para NextManager', emailHtml).catch(console.error);
        }
        // Siempre devolvemos el mismo mensaje para no revelar si un email existe o no
        res.status(200).json({ success: true, message: 'Si tu correo está registrado, recibirás un enlace para restablecer tu contraseña.' });
    } catch (error) {
        console.error('[Auth-Service /password/forgot] Error:', error);
        res.status(500).json({ success: false, message: 'Error interno del servidor.' });
    }
});

// POST /password/reset
app.post('/password/reset', async (req, res) => {
    const { token, password } = req.body;
    if (!token || !password) return res.status(400).json({ success: false, message: 'El token y la nueva contraseña son requeridos.' });
    
    const hashedToken = crypto.createHash('sha256').update(token).digest('hex');
    try {
        const user = await User.findOne({ 
            where: { 
                passwordResetToken: hashedToken,
                passwordResetExpires: { [Op.gt]: Date.now() } 
            } 
        });
        if (!user) return res.status(400).json({ success: false, message: 'El token es inválido o ha expirado.' });

        user.password = await bcrypt.hash(password, 10);
        user.passwordResetToken = null;
        user.passwordResetExpires = null;
        await user.save();
        res.status(200).json({ success: true, message: 'Tu contraseña ha sido restablecida exitosamente.' });
    } catch (error) {
        console.error('[Auth-Service /password/reset] Error:', error);
        res.status(500).json({ success: false, message: 'Error interno del servidor.' });
    }
});

// --- Rutas para Social Login ---
// GET /auth/google - Redirige al usuario a Google para autenticarse
app.get('/auth/google', passport.authenticate('google', { scope: ['profile', 'email'] }));

// GET /auth/google/callback - Google redirige aquí después de la autenticación
app.get('/auth/google/callback', passport.authenticate('google', { session: false, failureRedirect: '/login/failed' }),
  (req, res) => {
    // Si la autenticación es exitosa, req.user contiene el usuario de la base de datos
    const tokenPayload = { id: req.user.id, email: req.user.email, role: req.user.role };
    const token = jwt.sign(tokenPayload, process.env.JWT_SECRET, { expiresIn: '7d' });
    // Redirige al frontend con el token
    res.redirect(`${process.env.CLIENT_URL_PROD}/auth/success?token=${token}`);
  }
);


// --- Rutas de Autenticación de Dos Factores (2FA) ---

// POST /2fa/setup
app.post('/2fa/setup', authenticateToken, async (req, res) => {
    try {
        const user = await User.findByPk(req.user.id);
        const secret = authenticator.generateSecret();
        user.twoFactorSecret = secret; // Guardamos el secreto temporalmente
        await user.save();
        const otpAuthUrl = authenticator.keyuri(user.email, 'NextManager', secret);
        const qrCodeDataUrl = await qrcode.toDataURL(otpAuthUrl);
        res.json({ success: true, qrCodeDataUrl, secret });
    } catch (error) {
        console.error('[Auth-Service /2fa/setup] Error:', error);
        res.status(500).json({ success: false, message: 'Error al iniciar la configuración de 2FA.' });
    }
});

// POST /2fa/verify
app.post('/2fa/verify', authenticateToken, async (req, res) => {
    const { token } = req.body;
    try {
        const user = await User.findByPk(req.user.id);
        if (!user || !user.twoFactorSecret) return res.status(400).json({ success: false, message: 'La configuración de 2FA no se ha iniciado.' });
        
        if (!authenticator.verify({ token, secret: user.twoFactorSecret })) {
            return res.status(400).json({ success: false, message: 'Código de verificación inválido.' });
        }
        user.isTwoFactorEnabled = true;
        await user.save();
        res.json({ success: true, message: 'La autenticación de dos factores ha sido activada.' });
    } catch (error) {
        console.error('[Auth-Service /2fa/verify] Error:', error);
        res.status(500).json({ success: false, message: 'Error al verificar el código.' });
    }
});

// POST /2fa/validate
app.post('/2fa/validate', async (req, res) => {
    const { email, token } = req.body;
    try {
        const user = await User.findOne({ where: { email: email.toLowerCase() } });
        if (!user || !user.isTwoFactorEnabled) return res.status(401).json({ success: false, message: '2FA no está habilitado para este usuario.' });
        
        if (!authenticator.verify({ token, secret: user.twoFactorSecret })) {
            return res.status(401).json({ success: false, message: 'Código de autenticación inválido.' });
        }
        const tokenPayload = { id: user.id, email: user.email, role: user.role };
        const sessionToken = jwt.sign(tokenPayload, process.env.JWT_SECRET, { expiresIn: process.env.JWT_EXPIRES_IN || '7d' });
        res.json({ success: true, token: `Bearer ${sessionToken}` });
    } catch (error) {
        console.error('[Auth-Service /2fa/validate] Error:', error);
        res.status(500).json({ success: false, message: 'Error interno del servidor.' });
    }
});

// --- ENDPOINT FINAL: OBTENER TODOS LOS DATOS DE LA CUENTA ---
app.get('/account-details', authenticateToken, async (req, res) => {
    try {
        const userId = req.user.id;
        console.log(`[Auth-Service /account-details] Buscando datos completos para el usuario: ${userId}`);

        // 1. Buscamos los datos principales en paralelo para mayor eficiencia
        const [user, activeSubscription, restaurants] = await Promise.all([
            User.findByPk(userId, {
                attributes: { exclude: ['password', 'passwordResetToken', 'passwordResetExpires', 'twoFactorSecret', 'emailVerificationToken', 'magicLinkToken', 'magicLinkExpires'] }
            }),
            PlanPurchase.findOne({ where: { userId: userId, status: 'active' } }),
            Restaurant.findAll({ 
                where: { userId: userId },
                attributes: ['id', 'name', 'status', 'agentKey'] 
            })
        ]);

        if (!user) {
            return res.status(404).json({ success: false, message: 'Usuario no encontrado.' });
        }

        // 2. Buscamos los datos fiscales del primer restaurante (si existe)
        let fiscalData = null;
        if (restaurants && restaurants.length > 0) {
            const primaryRestaurantId = restaurants[0].id;
            fiscalData = await FiscalData.findOne({ where: { restaurantId: primaryRestaurantId } });
        }

        // 3. Construimos el objeto de respuesta final y completo
        const accountData = {
            profile: {
                name: user.name,
                email: user.email,
                avatarUrl: user.avatarUrl || `https://ui-avatars.com/api/?name=${encodeURIComponent(user.name)}&background=random`,
                memberSince: user.createdAt,
            },
            billing: {
                rfc: fiscalData ? fiscalData.rfc : 'No disponible',
                fiscalAddress: fiscalData ? fiscalData.fiscalAddress : 'No disponible',
                paymentMethod: activeSubscription ? activeSubscription.paymentMethod : 'No disponible',
                nextBillingDate: activeSubscription ? activeSubscription.nextBillingDate : 'No disponible',
            },
            plan: {
                name: activeSubscription ? activeSubscription.planName : 'Sin Plan Activo',
                price: activeSubscription ? activeSubscription.price : 0,
                period: activeSubscription ? activeSubscription.period : 'N/A',
                usagePercentage: activeSubscription ? activeSubscription.usagePercentage : 0, // Ejemplo
            },
            restaurants: restaurants || []
        };

        res.json({ success: true, data: accountData });

    } catch (error) {
        console.error('[Auth-Service /account-details] Error:', error);
        res.status(500).json({ success: false, message: 'Error interno del servidor al obtener los datos de la cuenta.' });
    }
});


// --- Endpoint de Logout ---
app.post('/logout', authenticateToken, async (req, res) => {
    try {
        const jti = req.user.jti; 
        const exp = req.user.exp;
        const remainingTime = exp - Math.floor(Date.now() / 1000);

        if (redisClient.isOpen && remainingTime > 0) {
            await redisClient.set(`blacklist:${jti}`, 'revoked', { 'EX': remainingTime });
        }

        res.status(200).json({ success: true, message: 'Sesión cerrada exitosamente.' });
    } catch (error) {
        console.error('[Auth-Service /logout] Error:', error);
        res.status(500).json({ success: false, message: 'Error al cerrar la sesión.' });
    }
});

// --- ARRANQUE DEL SERVIDOR (VERSIÓN ROBUSTA) ---
const PORT = process.env.AUTH_SERVICE_PORT || 3001;
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
    service: 'auth-service', // Identifica el servicio
    error: error.message, 
    stack: error.stack 
});
    }
};

startServer();