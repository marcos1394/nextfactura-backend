// --- services/restaurant-service/server.js (Versión Profesional y Completa) ---

require('dotenv').config();

// --- Imports de Librerías ---
const express = require('express');
const cors = require('cors');
const { Sequelize, DataTypes, Op, UUIDV4 } = require('sequelize');
const jwt = require('jsonwebtoken');

const app = express();
app.use(cors());
app.use(express.json());
app.use(express.urlencoded({ extended: true }));


// --- Conexión a Base de Datos ---
const sequelize = new Sequelize(process.env.DATABASE_URL, {
    dialect: 'postgres',
    logging: false,
    dialectOptions: {
      ssl: { require: true, rejectUnauthorized: false }
    }
});

// --- Modelos de Datos (Propiedad de este servicio) ---
// NOTA: Se añade `paranoid: true` para habilitar el borrado lógico (soft deletes)

const Restaurant = sequelize.define('Restaurant', {
    id: { type: DataTypes.UUID, defaultValue: UUIDV4, primaryKey: true },
    userId: { type: DataTypes.UUID, allowNull: false, index: true },
    name: { type: DataTypes.STRING, allowNull: false },
    address: { type: DataTypes.STRING },
    logoUrl: { type: DataTypes.STRING },
    // Datos de conexión al POS
    connectionHost: { type: DataTypes.STRING },
    connectionPort: { type: DataTypes.STRING },
    connectionUser: { type: DataTypes.STRING },
    connectionPassword: { type: DataTypes.STRING }, // En producción, esto debería cifrarse.
    connectionDbName: { type: DataTypes.STRING },
    // Datos de conexión VPN
    vpnUsername: { type: DataTypes.STRING },
    vpnPassword: { type: DataTypes.STRING } // En producción, esto debería cifrarse.
}, { tableName: 'restaurants', timestamps: true, paranoid: true }); // Habilitado Soft Delete

const FiscalData = sequelize.define('FiscalData', {
    id: { type: DataTypes.UUID, defaultValue: UUIDV4, primaryKey: true },
    restaurantId: { type: DataTypes.UUID, allowNull: false, references: { model: Restaurant, key: 'id' } },
    rfc: { type: DataTypes.STRING, allowNull: false },
    fiscalAddress: { type: DataTypes.STRING, allowNull: false },
    csdPassword: { type: DataTypes.STRING }, // Cifrar en producción
    csdCertificateUrl: { type: DataTypes.STRING },
    csdKeyUrl: { type: DataTypes.STRING }
}, { tableName: 'fiscal_data', timestamps: true, paranoid: true }); // Habilitado Soft Delete

const PortalConfig = sequelize.define('PortalConfig', {
    id: { type: DataTypes.UUID, defaultValue: UUIDV4, primaryKey: true },
    userId: { type: DataTypes.UUID, allowNull: false, unique: true }, // Un solo portal por usuario
    portalName: { type: DataTypes.STRING, allowNull: false },
    portalLogoUrl: { type: DataTypes.STRING },
    customDomain: { type: DataTypes.STRING, unique: true, allowNull: true },
    primaryColor: { type: DataTypes.STRING, defaultValue: '#3B82F6' },
    secondaryColor: { type: DataTypes.STRING, defaultValue: '#6B7280' }
}, { tableName: 'portal_configs', timestamps: true });

// Relaciones
Restaurant.hasOne(FiscalData, { foreignKey: 'restaurantId', onDelete: 'CASCADE' });
FiscalData.belongsTo(Restaurant, { foreignKey: 'restaurantId' });


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

// --- Rutas del Servicio de Restaurantes ---

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
app.post('/restaurants/:id/test-connection', authenticateToken, async (req, res) => {
    const { id } = req.params;
    const userId = req.user.id;

    try {
        const restaurant = await Restaurant.findOne({ where: { id, userId } });
        if (!restaurant) {
            return res.status(404).json({ success: false, message: 'Restaurante no encontrado o no autorizado.' });
        }

        const { connectionHost, connectionPort, connectionUser, connectionPassword, connectionDbName } = restaurant;
        if (!connectionHost || !connectionUser || !connectionPassword || !connectionDbName) {
            return res.status(400).json({ success: false, message: 'Los datos de conexión del restaurante están incompletos.' });
        }
        
        // **PATRÓN DE MICROSERVICIOS: Comunicación Inter-Servicios**
        // Este servicio no se conecta directamente. Llama al servicio especializado.
        // En una implementación real, se usaría un cliente HTTP como Axios o Fetch.
        // const posServiceUrl = process.env.POS_SERVICE_URL;
        // const response = await fetch(`${posServiceUrl}/test-connection`, {
        //     method: 'POST',
        //     headers: { 'Content-Type': 'application/json' },
        //     body: JSON.stringify({ connectionData: restaurant })
        // });
        // const result = await response.json();
        // if (!response.ok) throw new Error(result.message);
        
        // **Simulación para desarrollo:**
        console.log(`[Restaurant-Service] SIMULANDO llamada al pos-service para probar conexión de: ${restaurant.name}`);
        const mockResult = { success: true, message: 'Conexión con SoftRestaurant exitosa (Simulado).' };

        res.status(200).json(mockResult);

    } catch (error) {
        console.error(`[Restaurant-Service /test-connection] Error:`, error);
        res.status(500).json({ success: false, message: error.message || 'Error al probar la conexión.' });
    }
});


// --- Rutas del Servicio de Portal ---

// PUT /portal - Crear o actualizar la configuración del portal de un usuario (Upsert)
app.put('/portal', authenticateToken, async (req, res) => {
    const userId = req.user.id;
    const { portalName, portalLogoUrl, customDomain, primaryColor, secondaryColor } = req.body;

    try {
        const [portalConfig, created] = await PortalConfig.findOrCreate({
            where: { userId },
            defaults: { portalName, portalLogoUrl, customDomain, primaryColor, secondaryColor }
        });

        if (!created) {
            await portalConfig.update({ portalName, portalLogoUrl, customDomain, primaryColor, secondaryColor });
        }
        
        // **PATRÓN DE MICROSERVICIOS: Arquitectura Orientada a Eventos**
        // Si se configuró un dominio personalizado, este es el momento de notificar a otros servicios.
        if (customDomain) {
            console.log(`[Restaurant-Service] EVENTO: 'portal.domain.configured' emitido para ${customDomain}.`);
            // En una implementación real, aquí se publicaría un mensaje a un broker (RabbitMQ, Kafka)
            // o se llamaría a un webhook de un servicio de infraestructura para que
            // se encargue de la configuración del DNS (ej. crear un registro CNAME).
        }

        res.status(200).json({ success: true, portalConfig });
    } catch (error) {
        if (error.name === 'SequelizeUniqueConstraintError') {
            return res.status(409).json({ success: false, message: `El dominio personalizado "${customDomain}" ya está en uso.` });
        }
        console.error('[Restaurant-Service /portal] Error:', error);
        res.status(500).json({ success: false, message: 'Error al guardar la configuración del portal.' });
    }
});

// GET /portal - Obtener la configuración del portal del usuario autenticado
app.get('/portal', authenticateToken, async (req, res) => {
    const userId = req.user.id;
    try {
        const portalConfig = await PortalConfig.findOne({ where: { userId } });
        if (!portalConfig) return res.status(404).json({ success: false, message: 'No se ha configurado un portal para este usuario.' });
        res.status(200).json({ success: true, portalConfig });
    } catch (error) {
        console.error('[Restaurant-Service /portal] Error:', error);
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
