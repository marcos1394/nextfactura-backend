// --- services/pac-service/server.js (Versión Profesional y Completa) ---

require('dotenv').config();

// --- Imports de Librerías ---
const express = require('express');
const cors = require('cors');
const { Sequelize, DataTypes, UUIDV4 } = require('sequelize');
const jwt = require('jsonwebtoken');
const fetch = require('node-fetch');

const app = express();
app.use(cors());
app.use(express.json());

// --- Conexión a Base de Datos ---
const sequelize = new Sequelize(process.env.DATABASE_URL, {
    dialect: 'postgres',
    logging: false,
    dialectOptions: {
      ssl: { require: true, rejectUnauthorized: false }
    }
});

// --- Modelo de Datos (Propiedad de este servicio) ---
const Cfdi = sequelize.define('Cfdi', {
    uuid: { type: DataTypes.UUID, primaryKey: true },
    restaurantId: { type: DataTypes.UUID, allowNull: false, index: true },
    userId: { type: DataTypes.UUID, allowNull: false, index: true },
    status: { type: DataTypes.STRING, defaultValue: 'Vigente' }, // Vigente, Cancelado, EnProceso
    xmlBase64: { type: DataTypes.TEXT, allowNull: false },
    pdfBase64: { type: DataTypes.TEXT },
    cancellationDetails: { type: DataTypes.JSONB }
}, { tableName: 'cfdis', timestamps: true });


// --- Cliente de API para Prodigia (Patrón Profesional) ---
// Centraliza la lógica de comunicación con el PAC.
class ProdigiaClient {
    constructor(contrato, usuario, password) {
        this.baseURL = process.env.PRODIGIA_API_URL || 'https://timbrado.pade.mx/servicio/rest/timbrado40';
        this.authHeader = 'Basic ' + Buffer.from(`${usuario}:${password}`).toString('base64');
        this.contrato = contrato;
    }

    async _request(endpoint, method = 'POST', body = null) {
        const url = `${this.baseURL}${endpoint}`;
        const options = {
            method,
            headers: {
                'Authorization': this.authHeader,
                'Content-Type': 'application/json'
            }
        };
        if (body) {
            options.body = JSON.stringify(body);
        }

        console.log(`[ProdigiaClient] Requesting: ${method} ${url}`);
        const response = await fetch(url, options);
        const data = await response.json();

        if (!response.ok) {
            console.error('[ProdigiaClient] Error Response:', data);
            throw new Error(data.mensaje || 'Error en la comunicación con el PAC.');
        }
        
        console.log('[ProdigiaClient] Response OK');
        return data;
    }

    async timbrar(xmlBase64, certBase64, keyBase64, keyPass, esPrueba = false) {
        const body = {
            contrato: this.contrato,
            xmlBase64,
            certBase64,
            keyBase64,
            keyPass,
            prueba: esPrueba,
            opciones: ["GENERAR_PDF"] // Solicitamos el PDF por defecto
        };
        return this._request('/timbrarCfdi', 'POST', body);
    }
    
    // Aquí se añadirían los otros métodos: cancelar, consultarEstatus, etc.
}


// --- Middleware de Autenticación ---
const authenticateToken = (req, res, next) => { /* ... (código existente) ... */ };


// --- Rutas del Servicio de PAC ---

// POST /stamp - Timbrar un nuevo CFDI
app.post('/stamp', authenticateToken, async (req, res) => {
    const { restaurantId, xmlBase64 } = req.body;
    const userId = req.user.id;

    if (!restaurantId || !xmlBase64) {
        return res.status(400).json({ success: false, message: 'Se requiere restaurantId y xmlBase64.' });
    }

    try {
        // **PATRÓN DE MICROSERVICIOS: Obtener datos de otro servicio**
        // 1. Llamar al restaurant-service para obtener los datos fiscales y credenciales del PAC
        const restaurantServiceUrl = process.env.RESTAURANT_SERVICE_URL;
        const respRestaurant = await fetch(`${restaurantServiceUrl}/restaurants/${restaurantId}`, {
            headers: { 'Authorization': req.headers.authorization } // Pasamos el mismo token
        });
        const restaurantData = await respRestaurant.json();

        if (!respRestaurant.ok || !restaurantData.success) {
            throw new Error('No se pudo obtener la información del restaurante.');
        }
        
        // Asumimos que las credenciales del PAC se guardan en el modelo FiscalData
        const { csdCertificateUrl, csdKeyUrl, csdPassword, rfc } = restaurantData.restaurant.FiscalData;
        const { prodigiaContrato, prodigiaUsuario, prodigiaPassword } = restaurantData.restaurant; // Nuevos campos a agregar en el modelo Restaurant

        // TODO: Obtener el contenido de los archivos .cer y .key desde sus URLs
        const certBase64 = "CONTENIDO_DEL_CERTIFICADO_EN_BASE64";
        const keyBase64 = "CONTENIDO_DE_LA_LLAVE_EN_BASE64";

        // 2. Comunicarse con el PAC
        const client = new ProdigiaClient(prodigiaContrato, prodigiaUsuario, prodigiaPassword);
        const timbradoResponse = await client.timbrar(xmlBase64, certBase64, keyBase64, csdPassword);
        
        if (timbradoResponse.codigo !== 0) {
            return res.status(400).json({ success: false, message: `Error del PAC: ${timbradoResponse.mensaje}`, code: timbradoResponse.codigo });
        }

        // 3. Guardar el resultado en nuestra base de datos
        const newCfdi = await Cfdi.create({
            uuid: timbradoResponse.uuid,
            restaurantId,
            userId,
            xmlBase64: timbradoResponse.xmlBase64,
            pdfBase64: timbradoResponse.pdfBase64,
            status: 'Vigente'
        });

        res.status(201).json({ success: true, cfdi: newCfdi });

    } catch (error) {
        console.error('[PAC-Service /stamp] Error:', error);
        res.status(500).json({ success: false, message: error.message });
    }
});


// --- Arranque del Servidor ---
const PORT = process.env.PAC_SERVICE_PORT || 3005;
const startServer = async () => {
    try {
        await sequelize.authenticate();
        console.log('[PAC-Service] Conexión con la BD establecida.');
        await sequelize.sync({ alter: true });
        console.log('[PAC-Service] Modelos sincronizados.');
        app.listen(PORT, () => {
            console.log(`🚀 PAC-Service profesional escuchando en el puerto ${PORT}`);
        });
    } catch (error) {
        console.error('[PAC-Service] Error catastrófico al iniciar:', error);
        process.exit(1);
    }
};

startServer();
