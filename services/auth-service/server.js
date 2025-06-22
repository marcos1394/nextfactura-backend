// --- services/auth-service/server.js (Versión Profesional y Completa) ---

// Carga las variables de entorno para este servicio
require('dotenv').config();

// --- Imports de Librerías ---
const express = require('express');
const bodyParser = require('body-parser');
const cors = require('cors');
const { Sequelize, DataTypes, UUIDV4 } = require('sequelize');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');

const app = express();
app.use(cors());
app.use(bodyParser.json());

// --- Conexión a Base de Datos ---
// Este servicio se conecta a la misma base de datos de Render que los demás.
// Es responsable de gestionar su propia tabla ('users').
const sequelize = new Sequelize(process.env.DATABASE_URL, {
    dialect: 'postgres',
    logging: false, // Desactivar logs de SQL en producción para un mejor rendimiento
    dialectOptions: {
      ssl: { 
          require: true, 
          rejectUnauthorized: false // Requerido para conexiones a BD en la nube como Render
        }
    }
});

// --- Modelo de Datos: User (Propiedad exclusiva de este servicio) ---
const User = sequelize.define('User', {
    id: { 
        type: DataTypes.UUID, 
        defaultValue: UUIDV4, // ID universal único, mejor para sistemas distribuidos
        primaryKey: true 
    },
    name: { 
        type: DataTypes.STRING,
        allowNull: true
    },
    email: { 
        type: DataTypes.STRING, 
        allowNull: false, 
        unique: true, // Asegura que no haya emails duplicados
        validate: { isEmail: true } 
    },
    password: { // Contraseña siempre hasheada
        type: DataTypes.STRING, 
        allowNull: false 
    },
    restaurantName: { 
        type: DataTypes.STRING, 
        allowNull: true 
    },
    phoneNumber: { 
        type: DataTypes.STRING, 
        allowNull: true 
    },
    role: { 
        type: DataTypes.STRING, 
        defaultValue: 'RestaurantOwners' // Rol por defecto para nuevos usuarios
    },
}, { 
    tableName: 'users', 
    timestamps: true // Habilita createdAt y updatedAt
});

// --- Middleware de Autenticación ---
// Este "guardia" verifica el token JWT en las rutas que lo requieren.
const authenticateToken = (req, res, next) => {
    const authHeader = req.headers['authorization'];
    const token = authHeader && authHeader.split(' ')[1]; // Formato: "Bearer TOKEN"

    if (!token) {
        return res.status(401).json({ success: false, message: 'Acceso denegado. Token no proporcionado.' });
    }

    jwt.verify(token, process.env.JWT_SECRET, (err, userPayload) => {
        if (err) {
            return res.status(403).json({ success: false, message: 'Token inválido o expirado.' });
        }
        req.user = userPayload; // Adjunta el payload del token (id, email, role) a la petición
        next();
    });
};

// --- Rutas del Servicio de Autenticación ---
// Nótese que las rutas no llevan el prefijo '/api/auth'. El Gateway se encarga de eso.

// POST /register - Crea una nueva cuenta de usuario
app.post('/register', async (req, res) => {
    const { name, email, password, restaurantName } = req.body;
    if (!email || !password) {
        return res.status(400).json({ success: false, message: 'Email y contraseña son requeridos.' });
    }
    try {
        const hashedPassword = await bcrypt.hash(password, 10);
        const user = await User.create({ name, email: email.toLowerCase(), password: hashedPassword, restaurantName });
        // Devuelve una respuesta limpia sin datos sensibles
        res.status(201).json({ success: true, message: 'Usuario registrado con éxito.', userId: user.id });
    } catch (error) {
        if (error.name === 'SequelizeUniqueConstraintError') {
            return res.status(409).json({ success: false, message: 'El correo electrónico ya está en uso.' });
        }
        console.error('[Auth-Service /register] Error:', error);
        res.status(500).json({ success: false, message: 'Error interno al registrar el usuario.' });
    }
});

// POST /login - Autentica un usuario y devuelve un token JWT
app.post('/login', async (req, res) => {
    const { email, password } = req.body;
    try {
        const user = await User.findOne({ where: { email: email.toLowerCase() } });
        if (!user || !await bcrypt.compare(password, user.password)) {
            return res.status(401).json({ success: false, message: 'Credenciales inválidas.' });
        }
        const tokenPayload = { id: user.id, email: user.email, role: user.role };
        const token = jwt.sign(tokenPayload, process.env.JWT_SECRET, { expiresIn: process.env.JWT_EXPIRES_IN || '7d' });
        res.json({ success: true, token: `Bearer ${token}` });
    } catch (error) {
        console.error('[Auth-Service /login] Error:', error);
        res.status(500).json({ success: false, message: 'Error interno del servidor.' });
    }
});

// GET /me - Devuelve el perfil del usuario actualmente autenticado (ruta protegida)
app.get('/me', authenticateToken, async (req, res) => {
    try {
        const user = await User.findByPk(req.user.id, {
            attributes: { exclude: ['password'] } // NUNCA devolver la contraseña, ni siquiera hasheada
        });
        if (!user) {
            return res.status(404).json({ success: false, message: 'Usuario no encontrado.' });
        }
        res.json({ success: true, user });
    } catch (error) {
        console.error('[Auth-Service /me] Error:', error);
        res.status(500).json({ success: false, message: 'Error interno del servidor.' });
    }
});

// GET /users/status - Una ruta de ejemplo que usaría el prefijo /api/users del Gateway
// Aquí podrías añadir lógica sobre el estado del usuario (ej. si ha completado su perfil)
app.get('/status', authenticateToken, (req, res) => {
    // Esta es una ruta simple que demuestra que el enrutamiento a /api/users funciona
    // y que la autenticación es validada.
    res.json({ success: true, message: `El estado para el usuario ${req.user.email} está OK.` });
});


// GET /health - Endpoint de estado para monitoreo
app.get('/health', (req, res) => {
    res.status(200).json({ status: 'ok', message: 'Auth-Service is running' });
});


// --- Arranque del Servidor ---
const PORT = process.env.AUTH_SERVICE_PORT || 3001;
const startServer = async () => {
    try {
        // Autentica la conexión con la base de datos
        await sequelize.authenticate();
        console.log('[Auth-Service] Conexión con la base de datos establecida exitosamente.');
        
        // Sincroniza el modelo User, creando la tabla si no existe
        await sequelize.sync({ alter: true }); 
        console.log('[Auth-Service] Tabla "users" sincronizada con el modelo.');
        
        app.listen(PORT, () => {
            console.log(`🚀 Auth-Service profesional escuchando en el puerto ${PORT}`);
        });
    } catch (error) {
        console.error('[Auth-Service] Error catastrófico al iniciar:', error);
        process.exit(1); // Si no puede conectar a la DB, el servicio no debe correr.
    }
};

startServer();
