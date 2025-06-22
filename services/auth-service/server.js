// --- services/auth-service/server.js (Versión Profesional y Completa) ---

// Carga las variables de entorno para este servicio
require('dotenv').config();

// --- Imports de Librerías ---
const express = require('express');
const bodyParser = require('body-parser');
const cors = require('cors');
const { Sequelize, DataTypes, Op, UUIDV4 } = require('sequelize');
const bcrypt = require('bcryptjs');
const jwt = 'jsonwebtoken';
const crypto = require('crypto'); // Para generar tokens seguros de un solo uso
const { Resend } = require('resend'); // Para enviar correos transaccionales
const { authenticator } = require('otplib'); // Para generar y verificar códigos 2FA
const qrcode = require('qrcode'); // Para generar códigos QR para 2FA

const app = express();
app.use(cors());
app.use(bodyParser.json());

// --- Inicialización de Servicios Externos ---
// Solo inicializa Resend si la API KEY está presente
const resend = process.env.RESEND_API_KEY ? new Resend(process.env.RESEND_API_KEY) : null;

// --- Conexión a Base de Datos ---
const sequelize = new Sequelize(process.env.DATABASE_URL, {
    dialect: 'postgres',
    logging: false, // Desactivar logs de SQL en producción
    dialectOptions: {
      ssl: { 
          require: true, 
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
    isTwoFactorEnabled: { type: DataTypes.BOOLEAN, defaultValue: false }
}, { 
    tableName: 'users', 
    timestamps: true 
});

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

// --- Middleware de Autenticación ---
const authenticateToken = (req, res, next) => {
    const authHeader = req.headers['authorization'];
    const token = authHeader && authHeader.split(' ')[1];
    if (!token) return res.status(401).json({ success: false, message: 'Acceso denegado. Token no proporcionado.' });
    
    jwt.verify(token, process.env.JWT_SECRET, (err, userPayload) => {
        if (err) return res.status(403).json({ success: false, message: 'Token inválido o expirado.' });
        req.user = userPayload;
        next();
    });
};

// --- Rutas del Servicio de Autenticación ---

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

// POST /login
app.post('/login', async (req, res) => {
    const { email, password } = req.body;
    try {
        const user = await User.findOne({ where: { email: email.toLowerCase() } });
        if (!user || !await bcrypt.compare(password, user.password)) {
            return res.status(401).json({ success: false, message: 'Credenciales inválidas.' });
        }
        if (user.isTwoFactorEnabled) {
            return res.status(200).json({ success: true, twoFactorRequired: true, message: "Por favor, ingresa tu código de autenticación." });
        }
        const tokenPayload = { id: user.id, email: user.email, role: user.role };
        const token = jwt.sign(tokenPayload, process.env.JWT_SECRET, { expiresIn: process.env.JWT_EXPIRES_IN || '7d' });
        res.json({ success: true, token: `Bearer ${token}` });
    } catch (error) {
        console.error('[Auth-Service /login] Error:', error);
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

// --- Arranque del Servidor ---
const PORT = process.env.AUTH_SERVICE_PORT || 3001;
const startServer = async () => {
    try {
        await sequelize.authenticate();
        console.log('[Auth-Service] Conexión con la base de datos establecida exitosamente.');
        await sequelize.sync({ alter: true }); 
        console.log('[Auth-Service] Modelos sincronizados con la base de datos.');
        app.listen(PORT, () => {
            console.log(`🚀 Auth-Service profesional escuchando en el puerto ${PORT}`);
        });
    } catch (error) {
        console.error('[Auth-Service] Error catastrófico al iniciar:', error);
        process.exit(1);
    }
};

startServer();
