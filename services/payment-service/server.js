// --- services/payment-service/server.js (Versión Profesional y Completa) ---

require('dotenv').config();

// --- Imports de Librerías ---
const express = require('express');
const bodyParser = require('body-parser');
const cors = require('cors');
const { Sequelize, DataTypes, UUIDV4 } = require('sequelize');
const { MercadoPagoConfig, Preference, Payment } = require('mercadopago');
const jwt = require('jsonwebtoken');
const cron = require('node-cron');


const app = express();
// Usamos express.json() y express.urlencoded() ya que bodyParser está deprecado en Express > 4.16
app.use(cors());
app.use(express.json());
app.use(express.urlencoded({ extended: true }));

// --- Inicialización de Servicios Externos ---
const mpClient = new MercadoPagoConfig({ accessToken: process.env.MP_ACCESS_TOKEN });
const payment = new Payment(mpClient);
const preference = new Preference(mpClient);
const resend = new (require('resend').Resend)(process.env.RESEND_API_KEY);

// --- Nuevas Funciones Auxiliares ---

/**
 * Envía correos electrónicos usando Resend.
 * @param {string} to - Email del destinatario.
 * @param {string} subject - Asunto del correo.
 * @param {string} html - Contenido HTML del correo.
 */
async function sendEmail(to, subject, html) {
    if (!process.env.RESEND_API_KEY) {
        console.warn(`[Email] RESEND_API_KEY no configurada. Simulación de correo para ${to}:`);
        console.log(`Asunto: ${subject}`);
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

/**
 * Crea los planes por defecto en la base de datos si no existen.
 * Esta función se llama al iniciar el servidor.
 */
async function seedPlans() {
    const plansToSeed = [
        {
            name: 'Básico',
            price: 199.00,
            features: { reports: true, users: 1, pos_sync: true },
            isActive: true
        },
        {
            name: 'Profesional',
            price: 399.00,
            features: { reports: true, users: 5, pos_sync: true, custom_branding: true },
            isActive: true
        },
        {
            name: 'Corporativo',
            price: 799.00,
            features: { reports: true, users: 'unlimited', pos_sync: true, custom_branding: true, api_access: true },
            isActive: true
        }
    ];

    try {
        for (const planData of plansToSeed) {
            const [plan, created] = await Plan.findOrCreate({
                where: { name: planData.name },
                defaults: planData
            });
            if (created) {
                console.log(`[Seed] Plan "${plan.name}" creado.`);
            }
        }
        console.log('[Seed] Verificación de planes completada.');
    } catch (error) {
        console.error('[Seed] Error al crear los planes por defecto:', error);
    }
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
}, { tableName: 'users', timestamps: false });

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


// --- Definición de Relaciones ---
Plan.hasMany(PlanPurchase, { foreignKey: 'planId' });
PlanPurchase.belongsTo(Plan, { foreignKey: 'planId' });

// Una Compra de Plan pertenece a un Usuario
User.hasMany(PlanPurchase, { foreignKey: 'userId' });
PlanPurchase.belongsTo(User, { foreignKey: 'userId' });
// --- Middleware de Autenticación ---
// Extrae el ID de usuario del token JWT que el Gateway debe reenviar.
const authenticateToken = (req, res, next) => {
    const authHeader = req.headers['authorization'];
    const token = authHeader && authHeader.split(' ')[1];
    if (!token) return res.status(401).json({ success: false, message: 'Acceso denegado. Token no proporcionado.' });
    
    try {
        const decoded = jwt.verify(token, process.env.JWT_SECRET);
        req.user = decoded; // Adjunta { id, email, role } a la petición
        next();
    } catch (err) {
        return res.status(403).json({ success: false, message: 'Token inválido o expirado.' });
    }
};


app.get('/health', (req, res) => {
  res.status(200).json({ status: 'ok' });
});



// --- Rutas del Servicio de Pagos ---

// --- (en payment-service/server.js) ---

// GET /subscription-check - Endpoint INTERNO para que otros servicios validen un plan.
app.get('/subscription-check', authenticateToken, async (req, res) => {
    try {
        const activePurchase = await PlanPurchase.findOne({
            where: {
                userId: req.user.id,
                status: 'active',
                expirationDate: { [Op.gt]: new Date() } // Op.gt es "greater than"
            }
        });

        if (!activePurchase) {
            // El usuario no tiene un plan activo o está expirado.
            return res.status(403).json({ 
                success: false, 
                canCreate: false, 
                reason: 'No tienes una suscripción activa.' 
            });
        }

        // Aquí puedes añadir lógica más compleja si quieres (ej. contar restaurantes)
        // Por ahora, si tiene un plan activo, puede crear.
        res.status(200).json({ success: true, canCreate: true });

    } catch (error) {
        console.error('[Payment-Service /subscription-check] Error:', error);
        res.status(500).json({ success: false, canCreate: false, reason: 'Error interno al verificar la suscripción.' });
    }
});


// GET /plans - Endpoint público para listar los planes disponibles
app.get('/plans', async (req, res) => {
    try {
        const plans = await Plan.findAll({ where: { isActive: true } });
        res.status(200).json({ success: true, plans });
    } catch (error) {
        console.error('[Payment-Service /plans] Error:', error);
        res.status(500).json({ success: false, message: 'Error al obtener los planes.' });
    }
});

// POST /create-preference - Ruta protegida para crear una preferencia de pago
app.post('/create-preference', authenticateToken, async (req, res) => {
    const { planId, origin } = req.body;
    const userId = req.user.id;

    if (!planId) return res.status(400).json({ success: false, message: 'Se requiere el ID del plan.' });

    try {
        const plan = await Plan.findByPk(planId);
        if (!plan) return res.status(404).json({ success: false, message: 'Plan no encontrado.' });

        // DESPUÉS:
const purchase = await PlanPurchase.create({
    userId,
    planId,
    price: plan.price,
    status: 'pending_preference',
    origin: origin // <--- ¡Añade esta línea!
});

        const preferenceData = {
            items: [{
                id: plan.id,
                title: `Plan ${plan.name} - NextManager`,
                quantity: 1,
                unit_price: plan.price,
                currency_id: 'MXN'
            }],
            payer: {
                email: req.user.email // El email viene en el token JWT
            },
            back_urls: {
                success: `${process.env.CLIENT_URL_PROD}/payment/success`,
                failure: `${process.env.CLIENT_URL_PROD}/payment/failure`,
                pending: `${process.env.CLIENT_URL_PROD}/payment/pending`
            },
            auto_return: 'approved',
            notification_url: `${process.env.API_GATEWAY_URL}/api/payment/webhook/mercadopago`,
            external_reference: purchase.id.toString(), // Usamos el ID de la compra para identificarla en el webhook
        };

        const result = await preference.create({ body: preferenceData });
        
        purchase.preferenceId = result.id;
        await purchase.save();

        res.status(201).json({ success: true, init_point: result.init_point, preferenceId: result.id });
    } catch (error) {
        console.error('[Payment-Service /create-preference] Error:', error);
        res.status(500).json({ success: false, message: 'Error al crear la preferencia de pago.' });
    }
});

// POST /webhook/mercadopago - Endpoint público para recibir notificaciones de Mercado Pago
app.post('/webhook/mercadopago', async (req, res) => {
    const { type, data } = req.body;

    if (type === 'payment') {
        try {
            const paymentDetails = await payment.get({ id: data.id });
            const purchaseId = parseInt(paymentDetails.external_reference, 10);
            
            const purchase = await PlanPurchase.findByPk(purchaseId);
            if (!purchase) {
                console.warn(`[Webhook] Compra con ID ${purchaseId} no encontrada.`);
                return res.sendStatus(200);
            }

            if (paymentDetails.status === 'approved' && purchase.status !== 'active') {
                purchase.status = 'active';
                purchase.paymentId = paymentDetails.id.toString();
                purchase.purchaseDate = new Date();
                // Asumimos planes de 1 año para este ejemplo
                const expiration = new Date();
                expiration.setFullYear(expiration.getFullYear() + 1);
                purchase.expirationDate = expiration;
                await purchase.save();
                console.log(`[Webhook] Compra ${purchase.id} para usuario ${purchase.userId} activada exitosamente.`);
                // --- NUEVO: Enviar correo de confirmación ---
                const planDetails = await Plan.findByPk(purchase.planId);
                const userEmail = paymentDetails.payer.email;
                if (userEmail && planDetails) {
                    const emailHtml = `<h1>¡Gracias por tu compra!</h1>
                                     <p>Tu plan <strong>${planDetails.name}</strong> ha sido activado.</p>
                                     <p>Estará vigente hasta el: ${purchase.expirationDate.toLocaleDateString('es-MX')}.</p>`;
                    sendEmail(userEmail, 'Confirmación de tu plan en NextManager', emailHtml);
                }
            } else {
                console.log(`[Webhook] Estado de pago no aprobado (${paymentDetails.status}) para compra ${purchase.id}.`);
            }
        } catch (error) {
            console.error('[Webhook] Error procesando notificación:', error);
            return res.sendStatus(500); // Devuelve error para que MP reintente
        }
    }
    res.sendStatus(200); // Responde a MP que la notificación fue recibida
});

// GET /status - Ruta protegida para que un usuario vea su plan actual
app.get('/status', authenticateToken, async (req, res) => {
    try {
        const activePurchase = await PlanPurchase.findOne({
            where: {
                userId: req.user.id,
                status: 'active',
                expirationDate: { [Op.gt]: new Date() } // Solo planes activos y no expirados
            },
            include: Plan, // Incluye los detalles del plan
            order: [['purchaseDate', 'DESC']] // El más reciente
        });

        if (!activePurchase) {
            return res.status(200).json({ success: true, hasActivePlan: false, plan: null });
        }
        res.status(200).json({ success: true, hasActivePlan: true, purchase: activePurchase });
    } catch (error) {
        console.error('[Payment-Service /status] Error:', error);
        res.status(500).json({ success: false, message: 'Error al obtener el estado del plan.' });
    }
});

// --- Nuevos Endpoints ---

/**
 * Middleware para proteger rutas de administración.
 * Verifica que el rol en el token JWT sea 'Admin'.
 */
const authenticateAdmin = (req, res, next) => {
    if (req.user && req.user.role === 'Admin') {
        next();
    } else {
        res.status(403).json({ success: false, message: 'Acceso denegado. Se requiere rol de administrador.' });
    }
};

// GET /history - Ruta protegida para que un usuario vea su historial de compras
app.get('/history', authenticateToken, async (req, res) => {
    try {
        const purchases = await PlanPurchase.findAll({
            where: { userId: req.user.id },
            include: {
                model: Plan,
                attributes: ['name', 'features']
            },
            order: [['purchaseDate', 'DESC']]
        });
        res.status(200).json({ success: true, history: purchases });
    } catch (error) {
        console.error('[Payment-Service /history] Error:', error);
        res.status(500).json({ success: false, message: 'Error al obtener el historial de compras.' });
    }
});


// --- Rutas de Administración ---

// POST /admin/plans - Crea un nuevo plan
app.post('/admin/plans', authenticateToken, authenticateAdmin, async (req, res) => {
    const { name, price, features, isActive } = req.body;
    try {
        const newPlan = await Plan.create({ name, price, features, isActive });
        res.status(201).json({ success: true, plan: newPlan });
    } catch (error) {
        console.error('[Payment-Service /admin/plans] Error:', error);
        res.status(500).json({ success: false, message: 'Error al crear el plan.' });
    }
});

// PUT /admin/plans/:id - Actualiza un plan existente
app.put('/admin/plans/:id', authenticateToken, authenticateAdmin, async (req, res) => {
    const { id } = req.params;
    const { name, price, features, isActive } = req.body;
    try {
        const plan = await Plan.findByPk(id);
        if (!plan) return res.status(404).json({ success: false, message: 'Plan no encontrado.' });

        plan.name = name ?? plan.name;
        plan.price = price ?? plan.price;
        plan.features = features ?? plan.features;
        plan.isActive = isActive ?? plan.isActive;
        
        await plan.save();
        res.status(200).json({ success: true, plan });
    } catch (error) {
        console.error('[Payment-Service /admin/plans/:id] Error:', error);
        res.status(500).json({ success: false, message: 'Error al actualizar el plan.' });
    }
});

// GET /admin/purchases - Permite a un admin buscar compras por email de usuario
app.get('/admin/purchases', authenticateToken, authenticateAdmin, async (req, res) => {
    const { userEmail } = req.query;
    if (!userEmail) return res.status(400).json({ success: false, message: 'Se requiere el parámetro "userEmail".' });
    
    // NOTA: Este endpoint requiere comunicación entre servicios o acceso a la tabla Users.
    // Por ahora, asumimos que el frontend proporciona el `userId` después de buscarlo en el `auth-service`.
    // La implementación ideal usaría gRPC o una llamada HTTP interna al `auth-service`.
    // Versión simplificada:
    const { userId } = req.query;
    if (!userId) return res.status(400).json({ success: false, message: 'Se requiere el parámetro "userId".' });

    try {
        const purchases = await PlanPurchase.findAll({ where: { userId } });
        res.status(200).json({ success: true, purchases });
    } catch (error) {
        console.error('[Payment-Service /admin/purchases] Error:', error);
        res.status(500).json({ success: false, message: 'Error al buscar las compras.' });
    }
});


// --- Arranque del Servidor (Versión Robusta) ---
const PORT = process.env.PAYMENT_SERVICE_PORT || 4003;
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
            console.log(`🚀 Service escuchando en el puerto ${PORT}`);
        });
    } catch (error) {
        console.error(`[Service] Error catastrófico al iniciar:`, error);
        process.exit(1);
    }
};

startServer();