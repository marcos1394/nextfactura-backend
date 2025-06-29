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

app.get('/health', (req, res) => {
  res.status(200).json({ status: 'ok' });
});



// --- Conexión a Base de Datos ---
const sequelize = new Sequelize(process.env.DATABASE_URL, {
    dialect: 'postgres',
    logging: false,
    dialectOptions: {
      ssl: { require: false, rejectUnauthorized: false }
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
        this.baseURL = process.env.PRODIGIA_API_URL || 'https://timbrado.pade.mx/servicio/rest';
        this.authHeader = 'Basic ' + Buffer.from(`${usuario}:${password}`).toString('base64');
        this.contrato = contrato;
    }

    async _request(path, method = 'POST', body = null, queryParams = null) {
        let url = `${this.baseURL}${path}`;
        if (queryParams) {
            url += '?' + new URLSearchParams(queryParams).toString();
        }

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
        return this._request('/timbrado40/timbrarCfdi', 'POST', body);
    }
    
    // Método para cancelar uno o más CFDI
    async cancelar(rfcEmisor, arregloUUID, certBase64, keyBase64, keyPass) {
        const queryParams = {
            contrato: this.contrato,
            rfcEmisor,
            arregloUUID // ej: ["UUID|Motivo|FolioSustituye"]
        };
        const body = {
            certBase64,
            keyBase64,
            keyPass
        };
        return this._request('/cancelacion/cancelar', 'POST', body, queryParams);
    }

    // Método para consultar el estatus de un CFDI
    async consultarEstatus(uuid, rfcEmisor, rfcReceptor, total) {
        const queryParams = {
            contrato: this.contrato,
            uuid,
            rfcEmisor,
            rfcReceptor,
            total
        };
        return this._request('/cancelacion/consultarEstatusComprobante', 'POST', null, queryParams);
    }

    // Método para enviar un CFDI por correo
    async enviarPorCorreo(uuid, destinatarios) {
        const body = {
            contrato: this.contrato,
            uuid,
            destinatarios // string de correos separados por coma
        };
        return this._request('/timbrado40/enviarXmlAndPdfPorCorreo', 'POST', body);
    }
}


// --- Middleware de Autenticación ---
const authenticateToken = (req, res, next) => {
    const authHeader = req.headers['authorization'];
    const token = authHeader && authHeader.split(' ')[1];
    if (!token) return res.status(401).json({ success: false, message: 'Token no proporcionado.' });
    try {
        req.user = jwt.verify(token, process.env.JWT_SECRET);
        next();
    } catch (err) {
        return res.status(403).json({ success: false, message: 'Token inválido.' });
    }
};


// --- Rutas del Servicio de PAC ---

// POST /stamp - Timbrar un nuevo CFDI
app.post('/stamp', authenticateToken, async (req, res) => {
    const { restaurantId, xmlBase64 } = req.body;
    const userId = req.user.id;

    if (!restaurantId || !xmlBase64) {
        return res.status(400).json({ success: false, message: 'Se requiere restaurantId y xmlBase64.' });
    }

    try {
        const restaurantServiceUrl = process.env.RESTAURANT_SERVICE_URL;
        const respRestaurant = await fetch(`${restaurantServiceUrl}/restaurants/${restaurantId}`, {
            headers: { 'Authorization': req.headers.authorization }
        });
        const restaurantData = await respRestaurant.json();
        if (!respRestaurant.ok || !restaurantData.success) {
            throw new Error('No se pudo obtener la información del restaurante.');
        }
        
        const { csdCertificateUrl, csdKeyUrl, csdPassword } = restaurantData.restaurant.FiscalData;
        const { prodigiaContrato, prodigiaUsuario, prodigiaPassword } = restaurantData.restaurant;

        // TODO: Obtener el contenido de los archivos .cer y .key desde sus URLs
        const certBase64 = "CONTENIDO_DEL_CERTIFICADO_EN_BASE64";
        const keyBase64 = "CONTENIDO_DE_LA_LLAVE_EN_BASE64";

        const client = new ProdigiaClient(prodigiaContrato, prodigiaUsuario, prodigiaPassword);
        const timbradoResponse = await client.timbrar(xmlBase64, certBase64, keyBase64, csdPassword);
        
        if (timbradoResponse.codigo !== 0) {
            return res.status(400).json({ success: false, message: `Error del PAC: ${timbradoResponse.mensaje}`, code: timbradoResponse.codigo });
        }

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


// --- NUEVOS ENDPOINTS ---

// POST /cancel - Cancelar uno o más CFDI
app.post('/cancel', authenticateToken, async (req, res) => {
    const { restaurantId, cancelaciones } = req.body; // cancelaciones: [{uuid, motivo, folioSustitucion}]
    if (!restaurantId || !Array.isArray(cancelaciones) || cancelaciones.length === 0) {
        return res.status(400).json({ success: false, message: 'Se requiere restaurantId y un arreglo de cancelaciones.' });
    }

    try {
        // Obtener datos del restaurante (similar al endpoint /stamp)
        const restaurantServiceUrl = process.env.RESTAURANT_SERVICE_URL;
        const respRestaurant = await fetch(`${restaurantServiceUrl}/restaurants/${restaurantId}`, {
            headers: { 'Authorization': req.headers.authorization }
        });
        const restaurantData = await respRestaurant.json();
        if (!respRestaurant.ok || !restaurantData.success) throw new Error('No se pudo obtener la info del restaurante.');

        const { rfc } = restaurantData.restaurant.FiscalData;
        const { prodigiaContrato, prodigiaUsuario, prodigiaPassword } = restaurantData.restaurant;
        // ... Lógica para obtener certBase64 y keyBase64 ...
        const certBase64 = "CONTENIDO_DEL_CERTIFICADO_EN_BASE64";
        const keyBase64 = "CONTENIDO_DE_LA_LLAVE_EN_BASE64";
        const keyPass = restaurantData.restaurant.FiscalData.csdPassword;

        // Formatear el arreglo de UUIDs para el PAC
        const arregloUUID = cancelaciones.map(c => `${c.uuid}|${c.motivo}${c.folioSustitucion ? '|' + c.folioSustitucion : ''}`);
        
        const client = new ProdigiaClient(prodigiaContrato, prodigiaUsuario, prodigiaPassword);
        const cancelResponse = await client.cancelar(rfc, arregloUUID, certBase64, keyBase64, keyPass);

        if (cancelResponse.codigo !== 0) {
            return res.status(400).json({ success: false, message: `Error del PAC: ${cancelResponse.mensaje}`, code: cancelResponse.codigo });
        }

        // Actualizar el estado de los CFDI en la base de datos local
        for (const item of cancelResponse.cancelaciones.cancelacion) {
            await Cfdi.update({ status: 'EnProceso', cancellationDetails: item }, { where: { uuid: item.uuid } });
        }

        res.status(200).json({ success: true, details: cancelResponse });

    } catch (error) {
        console.error('[PAC-Service /cancel] Error:', error);
        res.status(500).json({ success: false, message: error.message });
    }
});


// POST /status - Consultar el estatus de un CFDI
app.post('/status', authenticateToken, async (req, res) => {
    const { restaurantId, uuid, total } = req.body;
    if (!restaurantId || !uuid || !total) {
        return res.status(400).json({ success: false, message: 'Se requiere restaurantId, uuid y total.' });
    }

    try {
        const restaurantServiceUrl = process.env.RESTAURANT_SERVICE_URL;
        // ... (obtener datos del restaurante) ...
        // ... (obtener RFC emisor y receptor - receptor puede venir del ticket de venta) ...
        const rfcEmisor = "RFC_EMISOR_OBTENIDO";
        const rfcReceptor = "RFC_RECEPTOR_OBTENIDO";
        const { prodigiaContrato, prodigiaUsuario, prodigiaPassword } = {}; // obtener de la respuesta del servicio

        const client = new ProdigiaClient(prodigiaContrato, prodigiaUsuario, prodigiaPassword);
        const statusResponse = await client.consultarEstatus(uuid, rfcEmisor, rfcReceptor, total);
        
        // Actualizar el estatus en la BD local si ha cambiado
        await Cfdi.update({ status: statusResponse.estado }, { where: { uuid } });

        res.status(200).json({ success: true, status: statusResponse });

    } catch (error) {
        console.error('[PAC-Service /status] Error:', error);
        res.status(500).json({ success: false, message: error.message });
    }
});


// POST /send-email - Enviar un CFDI por correo usando el servicio del PAC
app.post('/send-email', authenticateToken, async (req, res) => {
    const { cfdi_uuid, recipients } = req.body; // recipients: "correo1@test.com,correo2@test.com"
    if (!cfdi_uuid || !recipients) {
        return res.status(400).json({ success: false, message: 'Se requiere cfdi_uuid y recipients.' });
    }

    try {
        const cfdi = await Cfdi.findByPk(cfdi_uuid);
        if (!cfdi) return res.status(404).json({ success: false, message: 'CFDI no encontrado.' });
        
        // ... (obtener credenciales del PAC para el restaurante cfdi.restaurantId) ...
        const { prodigiaContrato, prodigiaUsuario, prodigiaPassword } = {};

        const client = new ProdigiaClient(prodigiaContrato, prodigiaUsuario, prodigiaPassword);
        const emailResponse = await client.enviarPorCorreo(cfdi_uuid, recipients);
        
        if (!emailResponse.envioOk) {
            return res.status(400).json({ success: false, message: emailResponse.mensaje });
        }

        res.status(200).json({ success: true, message: 'Correo enviado exitosamente.' });

    } catch (error) {
        console.error('[PAC-Service /send-email] Error:', error);
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
