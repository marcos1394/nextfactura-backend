// --- services/pac-service/server.js (Versión Profesional y Completa) ---

require('dotenv').config();
const logger = require('./logger'); // Importa tu nuevo logger

// --- Imports de Librerías ---
const express = require('express');
const cors = require('cors');
const { Sequelize, DataTypes, UUIDV4 } = require('sequelize');
const jwt = require('jsonwebtoken');
const fetch = require('node-fetch');
const fs = require('fs').promises;
const https = require('https');

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
    cancellationDetails: { type: DataTypes.JSONB },
    rfcEmisor: { type: DataTypes.STRING, allowNull: false },
    rfcReceptor: { type: DataTypes.STRING, allowNull: false },
    total: { type: DataTypes.DECIMAL(12, 2), allowNull: false }
}, { tableName: 'cfdis', timestamps: true });

// --- Utilidad para descargar archivos de certificados ---
async function downloadFile(url) {
    return new Promise((resolve, reject) => {
        https.get(url, (response) => {
            if (response.statusCode !== 200) {
                reject(new Error(`HTTP ${response.statusCode}: ${response.statusMessage}`));
                return;
            }
            
            const chunks = [];
            response.on('data', (chunk) => chunks.push(chunk));
            response.on('end', () => {
                const buffer = Buffer.concat(chunks);
                resolve(buffer.toString('base64'));
            });
        }).on('error', reject);
    });
}

// --- Cliente de API para Prodigia (Patrón Profesional) ---
// Centraliza la lógica de comunicación con el PAC.
class ProdigiaClient {
    constructor(contrato, usuario, password) {
        this.baseURL = process.env.PRODIGIA_API_URL || 'https://timbrado.pade.mx/servicio/rest';
        this.authHeader = 'Basic ' + Buffer.from(`${usuario}:${password}`).toString('base64');
        this.contrato = contrato;
    }

    async _request(path, method = 'POST', body = null, queryParams = null, contentType = 'application/json') {
        let url = `${this.baseURL}${path}`;
        if (queryParams) {
            const params = new URLSearchParams();
            Object.keys(queryParams).forEach(key => {
                if (Array.isArray(queryParams[key])) {
                    queryParams[key].forEach(val => params.append(key, val));
                } else {
                    params.append(key, queryParams[key]);
                }
            });
            url += '?' + params.toString();
        }

        const options = {
            method,
            headers: {
                'Authorization': this.authHeader,
                'Content-Type': contentType
            }
        };
        
        if (body) {
            if (contentType === 'application/json') {
                options.body = JSON.stringify(body);
            } else {
                options.body = body;
            }
        }

        logger.info(`[ProdigiaClient] Requesting: ${method} ${url}`);
        const response = await fetch(url, options);
        
        let data;
        try {
            data = await response.json();
        } catch (error) {
            const textData = await response.text();
            logger.error('[ProdigiaClient] Response not JSON:', textData);
            throw new Error('Respuesta del PAC no es JSON válido');
        }

        if (!response.ok) {
            logger.error('[ProdigiaClient] Error Response:', data);
            throw new Error(data.mensaje || 'Error en la comunicación con el PAC.');
        }
        
        logger.info('[ProdigiaClient] Response OK');
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
            opciones: ["GENERAR_PDF", "RESPUESTA_JSON"] // Solicitamos el PDF y respuesta JSON
        };
        return this._request('/timbrado40/timbrarCfdi', 'POST', body);
    }
    
    // Método para cancelar uno o más CFDI
    async cancelar(rfcEmisor, arregloUUID, certBase64, keyBase64, keyPass) {
        const queryParams = {
            contrato: this.contrato,
            rfcEmisor
        };
        
        // Agregar cada UUID del arreglo como parámetro separado
        arregloUUID.forEach((uuid, index) => {
            queryParams[`arregloUUID[${index}]`] = uuid;
        });

        const body = {
            certBase64,
            keyBase64,
            keyPass
        };
        
        return this._request('/cancelacion/cancelar', 'POST', body, queryParams, 'application/xml');
    }

    // Método para consultar el estatus de un CFDI
    async consultarEstatus(uuid, rfcEmisor, rfcReceptor, total) {
        const queryParams = {
            contrato: this.contrato,
            uuid,
            rfcEmisor,
            rfcReceptor,
            total: total.toString()
        };
        return this._request('/cancelacion/consultarEstatusComprobante', 'POST', null, queryParams, 'application/xml');
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

    // Método para recuperar CFDI por UUID
    async recuperarCfdiPorUUID(uuid) {
        const queryParams = {
            contrato: this.contrato,
            uuid
        };
        return this._request('/consulta/cfdPorUUID', 'GET', null, queryParams);
    }

    // Método para recuperar acuse de cancelación
    async recuperarAcuseCancelacion(uuid) {
        const queryParams = {
            contrato: this.contrato,
            uuid
        };
        return this._request('/consulta/acuseCancelacion', 'GET', null, queryParams);
    }

    // Método para responder solicitud de cancelación
    async responderSolicitudCancelacion(rfcReceptor, arregloUUID, certBase64, keyBase64, keyPass) {
        const queryParams = {
            contrato: this.contrato,
            rfcReceptor
        };

        arregloUUID.forEach((uuid, index) => {
            queryParams[`arregloUUID[${index}]`] = uuid;
        });

        const body = {
            certBase64,
            keyBase64,
            keyPass
        };

        return this._request('/cancelacion/responderSolicitudCancelacion', 'POST', body, queryParams, 'application/xml');
    }

    // Método para consultar peticiones pendientes
    async consultarPeticionesPendientes(rfcReceptor) {
        const queryParams = {
            contrato: this.contrato,
            rfcReceptor
        };
        return this._request('/cancelacion/consultarPeticionesPendientes', 'POST', null, queryParams, 'application/xml');
    }

    // Método para consultar CFDI relacionados
    async consultarCfdiRelacionados(uuid, rfcEmisor, rfcReceptor, certBase64, keyBase64, keyPass) {
        const queryParams = {
            contrato: this.contrato,
            uuid,
            rfcEmisor,
            rfcReceptor
        };

        const body = {
            certBase64,
            keyBase64,
            keyPass
        };

        return this._request('/cancelacion/consultarCfdiRelacionados', 'GET', body, queryParams, 'application/xml');
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

// --- Función auxiliar para obtener datos del restaurante ---
async function getRestaurantData(restaurantId, authHeader) {
    const restaurantServiceUrl = process.env.RESTAURANT_SERVICE_URL;
    const respRestaurant = await fetch(`${restaurantServiceUrl}/restaurants/${restaurantId}`, {
        headers: { 'Authorization': authHeader }
    });
    const restaurantData = await respRestaurant.json();
    if (!respRestaurant.ok || !restaurantData.success) {
        throw new Error('No se pudo obtener la información del restaurante.');
    }
    return restaurantData.restaurant;
}

// --- Función auxiliar para obtener certificados ---
async function getCertificates(restaurant) {
    const { csdCertificateUrl, csdKeyUrl, csdPassword } = restaurant.FiscalData;
    
    if (!csdCertificateUrl || !csdKeyUrl || !csdPassword) {
        throw new Error('Datos fiscales incompletos: se requiere certificado, llave privada y contraseña.');
    }

    try {
        const certBase64 = await downloadFile(csdCertificateUrl);
        const keyBase64 = await downloadFile(csdKeyUrl);
        
        return { certBase64, keyBase64, keyPass: csdPassword };
    } catch (error) {
        throw new Error(`Error al descargar certificados: ${error.message}`);
    }
}

// --- Rutas del Servicio de PAC ---

// POST /stamp - Timbrar un nuevo CFDI
app.post('/stamp', authenticateToken, async (req, res) => {
    const { restaurantId, xmlBase64, rfcReceptor, total, esPrueba = false } = req.body;
    const userId = req.user.id;

    if (!restaurantId || !xmlBase64 || !rfcReceptor || !total) {
        return res.status(400).json({ 
            success: false, 
            message: 'Se requiere restaurantId, xmlBase64, rfcReceptor y total.' 
        });
    }

    try {
        const restaurant = await getRestaurantData(restaurantId, req.headers.authorization);
        const { rfc } = restaurant.FiscalData;
        const { prodigiaContrato, prodigiaUsuario, prodigiaPassword } = restaurant;

        if (!prodigiaContrato || !prodigiaUsuario || !prodigiaPassword) {
            throw new Error('Credenciales de Prodigia no configuradas para este restaurante.');
        }

        const { certBase64, keyBase64, keyPass } = await getCertificates(restaurant);

        const client = new ProdigiaClient(prodigiaContrato, prodigiaUsuario, prodigiaPassword);
        const timbradoResponse = await client.timbrar(xmlBase64, certBase64, keyBase64, keyPass, esPrueba);
        
        if (timbradoResponse.codigo !== 0) {
            return res.status(400).json({ 
                success: false, 
                message: `Error del PAC: ${timbradoResponse.mensaje}`, 
                code: timbradoResponse.codigo 
            });
        }

        const newCfdi = await Cfdi.create({
            uuid: timbradoResponse.uuid,
            restaurantId,
            userId,
            xmlBase64: timbradoResponse.xmlBase64,
            pdfBase64: timbradoResponse.pdfBase64,
            status: 'Vigente',
            rfcEmisor: rfc,
            rfcReceptor,
            total: parseFloat(total)
        });

        res.status(201).json({ success: true, cfdi: newCfdi });

    } catch (error) {
        logger.error('[PAC-Service /stamp] Error:', { error: error.message, stack: error.stack });
        res.status(500).json({ success: false, message: error.message });
    }
});

// POST /cancel - Cancelar uno o más CFDI
app.post('/cancel', authenticateToken, async (req, res) => {
    const { restaurantId, cancelaciones } = req.body; // cancelaciones: [{uuid, motivo, folioSustitucion}]
    
    if (!restaurantId || !Array.isArray(cancelaciones) || cancelaciones.length === 0) {
        return res.status(400).json({ 
            success: false, 
            message: 'Se requiere restaurantId y un arreglo de cancelaciones.' 
        });
    }

    try {
        const restaurant = await getRestaurantData(restaurantId, req.headers.authorization);
        const { rfc } = restaurant.FiscalData;
        const { prodigiaContrato, prodigiaUsuario, prodigiaPassword } = restaurant;

        const { certBase64, keyBase64, keyPass } = await getCertificates(restaurant);

        // Formatear el arreglo de UUIDs para el PAC según la documentación
        const arregloUUID = cancelaciones.map(c => {
            let uuidString = `${c.uuid}|${c.motivo}`;
            if (c.folioSustitucion) {
                uuidString += `|${c.folioSustitucion}`;
            }
            return uuidString;
        });
        
        const client = new ProdigiaClient(prodigiaContrato, prodigiaUsuario, prodigiaPassword);
        const cancelResponse = await client.cancelar(rfc, arregloUUID, certBase64, keyBase64, keyPass);

        if (cancelResponse.codigo !== 0) {
            return res.status(400).json({ 
                success: false, 
                message: `Error del PAC: ${cancelResponse.mensaje}`, 
                code: cancelResponse.codigo 
            });
        }

        // Actualizar el estado de los CFDI en la base de datos local
        if (cancelResponse.cancelaciones && cancelResponse.cancelaciones.cancelacion) {
            const cancelacionArray = Array.isArray(cancelResponse.cancelaciones.cancelacion) 
                ? cancelResponse.cancelaciones.cancelacion 
                : [cancelResponse.cancelaciones.cancelacion];

            for (const item of cancelacionArray) {
                await Cfdi.update({ 
                    status: item.codigo === '201' ? 'EnProceso' : 'Cancelado', 
                    cancellationDetails: item 
                }, { where: { uuid: item.uuid } });
            }
        }

        res.status(200).json({ success: true, details: cancelResponse });

    } catch (error) {
        logger.error('[PAC-Service /cancel] Error:', { error: error.message, stack: error.stack });
        res.status(500).json({ success: false, message: error.message });
    }
});

// POST /status - Consultar el estatus de un CFDI
app.post('/status', authenticateToken, async (req, res) => {
    const { uuid } = req.body;
    
    if (!uuid) {
        return res.status(400).json({ success: false, message: 'Se requiere uuid.' });
    }

    try {
        // Buscar el CFDI en la base de datos local para obtener la información necesaria
        const cfdi = await Cfdi.findByPk(uuid);
        if (!cfdi) {
            return res.status(404).json({ success: false, message: 'CFDI no encontrado.' });
        }

        const restaurant = await getRestaurantData(cfdi.restaurantId, req.headers.authorization);
        const { prodigiaContrato, prodigiaUsuario, prodigiaPassword } = restaurant;

        const client = new ProdigiaClient(prodigiaContrato, prodigiaUsuario, prodigiaPassword);
        const statusResponse = await client.consultarEstatus(
            uuid, 
            cfdi.rfcEmisor, 
            cfdi.rfcReceptor, 
            cfdi.total
        );
        
        // Actualizar el estatus en la BD local si ha cambiado
        if (statusResponse.estado) {
            await Cfdi.update({ status: statusResponse.estado }, { where: { uuid } });
        }

        res.status(200).json({ success: true, status: statusResponse });

    } catch (error) {
        logger.error('[PAC-Service /status] Error:', { error: error.message, stack: error.stack });
        res.status(500).json({ success: false, message: error.message });
    }
});

// POST /send-email - Enviar un CFDI por correo usando el servicio del PAC
app.post('/send-email', authenticateToken, async (req, res) => {
    const { cfdi_uuid, recipients } = req.body; // recipients: "correo1@test.com,correo2@test.com"
    
    if (!cfdi_uuid || !recipients) {
        return res.status(400).json({ 
            success: false, 
            message: 'Se requiere cfdi_uuid y recipients.' 
        });
    }

    // Validar que no sean más de 3 correos según la documentación
    const emailArray = recipients.split(',').map(email => email.trim());
    if (emailArray.length > 3) {
        return res.status(400).json({ 
            success: false, 
            message: 'Máximo 3 correos electrónicos permitidos.' 
        });
    }

    try {
        const cfdi = await Cfdi.findByPk(cfdi_uuid);
        if (!cfdi) {
            return res.status(404).json({ success: false, message: 'CFDI no encontrado.' });
        }
        
        const restaurant = await getRestaurantData(cfdi.restaurantId, req.headers.authorization);
        const { prodigiaContrato, prodigiaUsuario, prodigiaPassword } = restaurant;

        const client = new ProdigiaClient(prodigiaContrato, prodigiaUsuario, prodigiaPassword);
        const emailResponse = await client.enviarPorCorreo(cfdi_uuid, recipients);
        
        if (!emailResponse.envioOk) {
            return res.status(400).json({ 
                success: false, 
                message: emailResponse.mensaje || 'Error al enviar correo.' 
            });
        }

        res.status(200).json({ success: true, message: 'Correo enviado exitosamente.' });

    } catch (error) {
        logger.error('[PAC-Service /send-email] Error:', { error: error.message, stack: error.stack });
        res.status(500).json({ success: false, message: error.message });
    }
});

// GET /cfdi/:uuid - Recuperar CFDI por UUID
app.get('/cfdi/:uuid', authenticateToken, async (req, res) => {
    const { uuid } = req.params;

    try {
        const cfdi = await Cfdi.findByPk(uuid);
        if (!cfdi) {
            return res.status(404).json({ success: false, message: 'CFDI no encontrado.' });
        }

        const restaurant = await getRestaurantData(cfdi.restaurantId, req.headers.authorization);
        const { prodigiaContrato, prodigiaUsuario, prodigiaPassword } = restaurant;

        const client = new ProdigiaClient(prodigiaContrato, prodigiaUsuario, prodigiaPassword);
        const cfdiResponse = await client.recuperarCfdiPorUUID(uuid);

        if (cfdiResponse.codigo !== 0) {
            return res.status(400).json({ 
                success: false, 
                message: `Error del PAC: ${cfdiResponse.mensaje}`, 
                code: cfdiResponse.codigo 
            });
        }

        res.status(200).json({ success: true, cfdi: cfdiResponse });

    } catch (error) {
        logger.error('[PAC-Service /cfdi] Error:', { error: error.message, stack: error.stack });
        res.status(500).json({ success: false, message: error.message });
    }
});

// GET /cancellation-receipt/:uuid - Recuperar acuse de cancelación
app.get('/cancellation-receipt/:uuid', authenticateToken, async (req, res) => {
    const { uuid } = req.params;

    try {
        const cfdi = await Cfdi.findByPk(uuid);
        if (!cfdi) {
            return res.status(404).json({ success: false, message: 'CFDI no encontrado.' });
        }

        const restaurant = await getRestaurantData(cfdi.restaurantId, req.headers.authorization);
        const { prodigiaContrato, prodigiaUsuario, prodigiaPassword } = restaurant;

        const client = new ProdigiaClient(prodigiaContrato, prodigiaUsuario, prodigiaPassword);
        const acuseResponse = await client.recuperarAcuseCancelacion(uuid);

        if (acuseResponse.codigo !== 0) {
            return res.status(400).json({ 
                success: false, 
                message: `Error del PAC: ${acuseResponse.mensaje}`, 
                code: acuseResponse.codigo 
            });
        }

        res.status(200).json({ success: true, acuse: acuseResponse });

    } catch (error) {
        logger.error('[PAC-Service /cancellation-receipt] Error:', { error: error.message, stack: error.stack });
        res.status(500).json({ success: false, message: error.message });
    }
});

// POST /respond-cancellation - Responder solicitud de cancelación
app.post('/respond-cancellation', authenticateToken, async (req, res) => {
    const { restaurantId, respuestas } = req.body; // respuestas: [{uuid, respuesta: 'Aceptacion'|'Rechazo'}]

    if (!restaurantId || !Array.isArray(respuestas) || respuestas.length === 0) {
        return res.status(400).json({ 
            success: false, 
            message: 'Se requiere restaurantId y un arreglo de respuestas.' 
        });
    }

    try {
        const restaurant = await getRestaurantData(restaurantId, req.headers.authorization);
        const { rfc } = restaurant.FiscalData;
        const { prodigiaContrato, prodigiaUsuario, prodigiaPassword } = restaurant;

        const { certBase64, keyBase64, keyPass } = await getCertificates(restaurant);

        // Formatear el arreglo según la documentación: UUID|Aceptacion o UUID|Rechazo
        const arregloUUID = respuestas.map(r => `${r.uuid}|${r.respuesta}`);

        const client = new ProdigiaClient(prodigiaContrato, prodigiaUsuario, prodigiaPassword);
        const respuestaResponse = await client.responderSolicitudCancelacion(
            rfc, 
            arregloUUID, 
            certBase64, 
            keyBase64, 
            keyPass
        );

        if (respuestaResponse.codigo !== 0) {
            return res.status(400).json({ 
                success: false, 
                message: `Error del PAC: ${respuestaResponse.mensaje}`, 
                code: respuestaResponse.codigo 
            });
        }

        res.status(200).json({ success: true, response: respuestaResponse });

    } catch (error) {
        logger.error('[PAC-Service /respond-cancellation] Error:', { error: error.message, stack: error.stack });
        res.status(500).json({ success: false, message: error.message });
    }
});

// GET /pending-cancellations/:restaurantId - Consultar peticiones pendientes
app.get('/pending-cancellations/:restaurantId', authenticateToken, async (req, res) => {
    const { restaurantId } = req.params;

    try {
        const restaurant = await getRestaurantData(restaurantId, req.headers.authorization);
        const { rfc } = restaurant.FiscalData;
        const { prodigiaContrato, prodigiaUsuario, prodigiaPassword } = restaurant;

        const client = new ProdigiaClient(prodigiaContrato, prodigiaUsuario, prodigiaPassword);
        const pendingResponse = await client.consultarPeticionesPendientes(rfc);

        if (pendingResponse.codigo !== 0) {
            return res.status(400).json({ 
                success: false, 
                message: `Error del PAC: ${pendingResponse.mensaje}`, 
                code: pendingResponse.codigo 
            });
        }

        res.status(200).json({ success: true, pending: pendingResponse });

    } catch (error) {
        logger.error('[PAC-Service /pending-cancellations] Error:', { error: error.message, stack: error.stack });
        res.status(500).json({ success: false, message: error.message });
    }
});

// GET /related-cfdi/:uuid - Consultar CFDI relacionados
app.get('/related-cfdi/:uuid', authenticateToken, async (req, res) => {
    const { uuid } = req.params;

    try {
        const cfdi = await Cfdi.findByPk(uuid);
        if (!cfdi) {
            return res.status(404).json({ success: false, message: 'CFDI no encontrado.' });
        }

        const restaurant = await getRestaurantData(cfdi.restaurantId, req.headers.authorization);
        const { prodigiaContrato, prodigiaUsuario, prodigiaPassword } = restaurant;

        const { certBase64, keyBase64, keyPass } = await getCertificates(restaurant);

        const client = new ProdigiaClient(prodigiaContrato, prodigiaUsuario, prodigiaPassword);
        const relatedResponse = await client.consultarCfdiRelacionados(
            uuid,
            cfdi.rfcEmisor,
            cfdi.rfcReceptor,
            certBase64,
            keyBase64,
            keyPass
        );

        if (relatedResponse.codigo !== 0) {
            return res.status(400).json({ 
                success: false, 
                message: `Error del PAC: ${relatedResponse.mensaje}`, 
                code: relatedResponse.codigo 
            });
        }

        res.status(200).json({ success: true, related: relatedResponse });

    } catch (error) {
        logger.error('[PAC-Service /related-cfdi] Error:', { error: error.message, stack: error.stack });
        res.status(500).json({ success: false, message: error.message });
    }
});

// GET /cfdi/restaurant/:restaurantId - Obtener todos los CFDI de un restaurante
app.get('/cfdi/restaurant/:restaurantId', authenticateToken, async (req, res) => {
    const { restaurantId } = req.params;
    const { page = 1, limit = 10, status } = req.query;

    try {
        const whereClause = { restaurantId };
        if (status) {
            whereClause.status = status;
        }

        const cfdis = await Cfdi.findAndCountAll({
            where: whereClause,
            limit: parseInt(limit),
            offset: (parseInt(page) - 1) * parseInt(limit),
            order: [['createdAt', 'DESC']]
        });

        res.status(200).json({ 
            success: true, 
            cfdis: cfdis.rows,
            total: cfdis.count,
            page: parseInt(page),
            totalPages: Math.ceil(cfdis.count / parseInt(limit))
        });

    } catch (error) {
        logger.error('[PAC-Service /cfdi/restaurant] Error:', { error: error.message, stack: error.stack });
        res.status(500).json({ success: false, message: error.message });
    }
});

// --- Arranque del Servidor ---
const PORT = process.env.PAC_SERVICE_PORT || 3005;

const startServer = async () => {
    try {
        // 1. Solo verifica que la conexión a la base de datos funciona.
        await sequelize.authenticate();
        logger.info(`[PAC-Service] Conexión con la base de datos establecida exitosamente.`);

        // 2. La sincronización de modelos se ha eliminado.
        // El servicio ahora asume que las tablas ya existen y están correctas.
        
        // 3. Inicia el servidor Express para escuchar peticiones.
        app.listen(PORT, () => {
            logger.info(`🚀 PAC Service escuchando en el puerto ${PORT}`);
        });
    } catch (error) {
        logger.error('Error catastrófico al iniciar PAC Service', { 
            service: 'pac-service',
            error: error.message, 
            stack: error.stack 
        });
    }
};

startServer();