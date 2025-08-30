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
const http = require('http'); // Asegúrate de tener esta
const Factura = require('facturajs'); // <-- IMPORTAMOS LA NUEVA LIBRERÍA


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
// services/pac-service/server.js

// La función ahora devuelve el Buffer del archivo, que es lo que 'facturajs' necesita
// Reemplaza la función downloadFile existente con esta
async function downloadFile(url) {
    // Determinamos qué cliente usar (http o https) basándonos en el protocolo de la URL
    const client = url.startsWith('https:') ? https : http;

    return new Promise((resolve, reject) => {
        client.get(url, (response) => {
            if (response.statusCode !== 200) {
                // Rechazamos la promesa si la respuesta no es exitosa
                return reject(new Error(`Fallo al descargar archivo. Status Code: ${response.statusCode}`));
            }

            const chunks = [];
            response.on('data', (chunk) => chunks.push(chunk));
            response.on('end', () => {
                // Devolvemos el Buffer del archivo, que es lo que necesitan las librerías de CFDI
                resolve(Buffer.concat(chunks));
            });
        }).on('error', (err) => {
            // Rechazamos la promesa en caso de un error de red
            reject(err);
        });
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

// Middleware para comunicación interna segura
const authenticateService = (req, res, next) => {
    const secretKey = req.headers['x-internal-secret'];
    if (!secretKey || secretKey !== process.env.INTERNAL_SECRET_KEY) {
        return res.status(403).json({ success: false, message: 'Acceso no autorizado.' });
    }
    next();
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
app.post('/stamp', authenticateService, async (req, res) => {
    const { ticket, ticketDetails, clientFiscalData, restaurantFiscalData } = req.body;
    const userId = restaurantFiscalData.userId;
    const restaurantId = restaurantFiscalData.id;

    if (!ticket || !ticketDetails || !clientFiscalData || !restaurantFiscalData) {
        return res.status(400).json({ success: false, message: 'Faltan datos para el timbrado.' });
    }

    try {
        // --- PASO 1: VERIFICAR Y USAR UN TIMBRE ---
        logger.info(`[PAC-Service] Verificando timbres para el usuario ${userId}`);
        const paymentServiceUrl = process.env.PAYMENT_SERVICE_URL || 'http://payment-service:4003';
        const stampResponse = await fetch(`${paymentServiceUrl}/internal/use-stamp`, {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ userId })
        });

        if (!stampResponse.ok) {
            const errorData = await stampResponse.json();
            return res.status(402).json({ success: false, message: errorData.message || 'No tienes timbres disponibles.' });
        }
        logger.info(`[PAC-Service] Timbre validado y descontado para el usuario ${userId}.`);

        // --- PASO 2: DESCARGAR CERTIFICADOS (CSD) ---
        const { csdCertificateUrl, csdKeyUrl, csdPassword } = restaurantFiscalData;
        const [certFileContent, keyFileContent] = await Promise.all([
            downloadFile(csdCertificateUrl), // Esta función debe devolver un Buffer
            downloadFile(csdKeyUrl)
        ]);
        
        // --- PASO 3: CREAR Y SELLAR EL CFDI CON FACTURAJS ---
        const subTotal = ticketDetails.reduce((acc, item) => acc + (item.cantidad * item.precio), 0);
        const iva = subTotal * 0.16; // Asumiendo IVA 16% para todos los productos
        const total = subTotal + iva;

        const cfdi = new Factura({
            Serie: 'A', // Puedes hacerlo configurable por restaurante
            Folio: ticket.id,
            Fecha: new Date().toISOString().slice(0, 19),
            LugarExpedicion: restaurantFiscalData.zipCode,
            Moneda: 'MXN',
            TipoDeComprobante: 'I',
            MetodoPago: 'PUE',
            FormaPago: '01', // TODO: Este dato debería venir del ticket
            SubTotal: subTotal,
            Total: total,
            Exportacion: '01',
            Emisor: {
                Rfc: restaurantFiscalData.rfc,
                Nombre: restaurantFiscalData.businessName,
                RegimenFiscal: restaurantFiscalData.fiscalRegime,
            },
            Receptor: {
                Rfc: clientFiscalData.rfc,
                Nombre: clientFiscalData.razonSocial,
                DomicilioFiscalReceptor: clientFiscalData.zipCode,
                RegimenFiscalReceptor: clientFiscalData.fiscalRegime,
                UsoCFDI: 'G03',
            },
            Conceptos: ticketDetails.map(item => ({
                ClaveProdServ: item.claveProdServ || '01010101', // TODO: Mapear a catálogo SAT
                Cantidad: item.cantidad,
                ClaveUnidad: item.claveUnidad || 'E48', // TODO: Mapear a catálogo SAT
                Descripcion: item.descripcion,
                ValorUnitario: item.precio,
                Importe: item.cantidad * item.precio,
                ObjetoImp: '02',
            })),
        });

        cfdi.sellar(keyFileContent, csdPassword);
        const xmlString = cfdi.xml();
        const xmlBase64 = Buffer.from(xmlString).toString('base64');
        logger.info('[PAC-Service] XML sellado y listo para enviar al PAC.');

        // --- PASO 4: TIMBRAR CON PRODIGIA USANDO CREDENCIALES GLOBALES ---
        const client = new ProdigiaClient(
            process.env.PRODIGIA_CONTRATO,
            process.env.PRODIGIA_USUARIO,
            process.env.PRODIGIA_PASSWORD
        );
        const timbradoResponse = await client.timbrar(xmlBase64, false); // false para modo producción

        if (timbradoResponse.codigo !== 0) {
            logger.warn(`[PAC-Service] Fallo del PAC. Devolviendo timbre al usuario ${userId}.`);
            await fetch(`${paymentServiceUrl}/internal/refund-stamp`, {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({ userId })
            });
            throw new Error(`Error del PAC (${timbradoResponse.codigo}): ${timbradoResponse.mensaje}`);
        }
        logger.info(`[PAC-Service] Timbrado exitoso. UUID: ${timbradoResponse.uuid}`);

        // --- PASO 5: GUARDAR REGISTRO EN LA BASE DE DATOS ---
        const newCfdi = await Cfdi.create({
            uuid: timbradoResponse.uuid,
            restaurantId,
            userId,
            status: 'Vigente',
            xmlBase64: timbradoResponse.xmlBase64,
            pdfBase64: timbradoResponse.pdfBase64,
            rfcEmisor: restaurantFiscalData.rfc,
            rfcReceptor: clientFiscalData.rfc,
            total: total
        });
        
        // --- PASO 6: DEVOLVER RESPUESTA EXITOSA ---
        res.status(201).json({
            success: true,
            message: 'Factura timbrada exitosamente.',
            uuid: newCfdi.uuid,
            xml: newCfdi.xmlBase64,
            pdf: newCfdi.pdfBase64
        });

    } catch (error) {
        logger.error('[PAC-Service /stamp] Error:', { error: error.message, stack: error.stack });
        res.status(500).json({ success: false, message: error.message || 'Error interno en el servicio de timbrado.' });
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