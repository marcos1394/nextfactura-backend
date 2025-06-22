// --- services/payment-service/server.js (Versión Profesional y Completa) ---

require('dotenv').config();

// --- Imports de Librerías ---
const express = require('express');
const bodyParser = require('body-parser');
const cors = require('cors');
const { Sequelize, DataTypes, UUIDV4 } = require('sequelize');
const { MercadoPagoConfig, Preference, Payment } = require('mercadopago');
const jwt = require('jsonwebtoken');

const app = express();
// Usamos express.json() y express.urlencoded() ya que bodyParser está deprecado en Express > 4.16
app.use(cors());
app.use(express.json());
app.use(express.urlencoded({ extended: true }));

// --- Inicialización de Servicios Externos ---
const mpClient = new MercadoPagoConfig({ accessToken: process.env.MP_ACCESS_TOKEN });
const payment = new Payment(mpClient);
const preference = new Preference(mpClient);

// --- Conexión a Base de Datos ---
const sequelize = new Sequelize(process.env.DATABASE_URL, {
    dialect: 'postgres',
    logging: false,
    dialectOptions: {
      ssl: { require: true, rejectUnauthorized: false }
    }
});

// --- Modelos de Datos (Propiedad de este servicio) ---

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
    userId: { type: DataTypes.UUID, allowNull: false }, // FK al ID del User en auth-service
    planId: { type: DataTypes.UUID, allowNull: false, references: { model: Plan, key: 'id' } },
    status: { type: DataTypes.STRING, defaultValue: 'pending', allowNull: false }, // pending, processing, active, failed, cancelled
    price: { type: DataTypes.FLOAT, allowNull: false },
    purchaseDate: { type: DataTypes.DATE },
    expirationDate: { type: DataTypes.DATE },
    paymentId: { type: DataTypes.STRING, allowNull: true, unique: true }, // ID del pago en Mercado Pago
    paymentProvider: { type: DataTypes.STRING, defaultValue: 'mercadopago' },
    preferenceId: { type: DataTypes.STRING, allowNull: true }
}, { tableName: 'plan_purchases', timestamps: true });

Plan.hasMany(PlanPurchase, { foreignKey: 'planId' });
PlanPurchase.belongsTo(Plan, { foreignKey: 'planId' });


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


// --- Rutas del Servicio de Pagos ---

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
    const { planId } = req.body;
    const userId = req.user.id;

    if (!planId) return res.status(400).json({ success: false, message: 'Se requiere el ID del plan.' });

    try {
        const plan = await Plan.findByPk(planId);
        if (!plan) return res.status(404).json({ success: false, message: 'Plan no encontrado.' });

        const purchase = await PlanPurchase.create({
            userId,
            planId,
            price: plan.price,
            status: 'pending_preference'
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


// --- Arranque del Servidor ---
const PORT = process.env.PAYMENT_SERVICE_PORT || 3003;
const startServer = async () => {
    try {
        await sequelize.authenticate();
        console.log('[Payment-Service] Conexión con la BD establecida.');
        await sequelize.sync({ alter: true });
        console.log('[Payment-Service] Modelos sincronizados.');
        // TODO: Crear planes por defecto si no existen
        app.listen(PORT, () => {
            console.log(`🚀 Payment-Service profesional escuchando en el puerto ${PORT}`);
        });
    } catch (error) {
        console.error('[Payment-Service] Error catastrófico al iniciar:', error);
        process.exit(1);
    }
};

startServer();
