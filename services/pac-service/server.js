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
const { create } = require('xmlbuilder2'); // Importamos el constructor de XML
const crypto = require('crypto'); // Importamos la librería de criptografía de Node.js


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
// En services/pac-service/server.js

async function downloadFile(url) {
    // --- CORRECCIÓN CLAVE ---
    // Reemplazamos 'localhost' o '127.0.0.1' con el nombre del servicio de Docker.
    // Esto asegura que la petición se dirija al contenedor correcto dentro de la red de Docker.
    const correctedUrl = new URL(url);
    if (correctedUrl.hostname === 'localhost' || correctedUrl.hostname === '127.0.0.1') {
        correctedUrl.hostname = 'restaurant-service';
    }
    // --- FIN DE LA CORRECCIÓN ---
    
    const client = correctedUrl.protocol === 'https:' ? https : http;

    return new Promise((resolve, reject) => {
        // Usamos la URL corregida para la petición
        client.get(correctedUrl.href, (response) => {
            if (response.statusCode !== 200) {
                return reject(new Error(`Fallo al descargar archivo. Status: ${response.statusCode}`));
            }
            
            const chunks = [];
            response.on('data', (chunk) => chunks.push(chunk));
            response.on('end', () => {
                resolve(Buffer.concat(chunks));
            });
        }).on('error', (err) => {
            reject(err);
        });
    });
}


// En services/pac-service/server.js

function buildCadenaOriginal(cfdiObject) {
    const comprobante = cfdiObject['cfdi:Comprobante'];
    const emisor = comprobante['cfdi:Emisor'];
    const receptor = comprobante['cfdi:Receptor'];
    const conceptos = Array.isArray(comprobante['cfdi:Conceptos']['cfdi:Concepto'])
        ? comprobante['cfdi:Conceptos']['cfdi:Concepto']
        : [comprobante['cfdi:Conceptos']['cfdi:Concepto']];

    // El orden de los campos es estricto y definido por el SAT.
    const parts = [
        '||4.0',
        comprobante['@Serie'],
        comprobante['@Folio'],
        comprobante['@Fecha'],
        comprobante['@FormaPago'],
        comprobante['@NoCertificado'],
        comprobante['@SubTotal'],
        comprobante['@Moneda'],
        comprobante['@Total'],
        comprobante['@TipoDeComprobante'],
        comprobante['@Exportacion'],
        comprobante['@MetodoPago'],
        comprobante['@LugarExpedicion'],
        emisor['@Rfc'],
        emisor['@Nombre'],
        emisor['@RegimenFiscal'],
        receptor['@Rfc'],
        receptor['@Nombre'],
        receptor['@DomicilioFiscalReceptor'],
        receptor['@RegimenFiscalReceptor'],
        receptor['@UsoCFDI'],
    ];

    conceptos.forEach(con => {
        parts.push(con['@ClaveProdServ']);
        parts.push(con['@Cantidad']);
        parts.push(con['@ClaveUnidad']);
        parts.push(con['@Descripcion']);
        parts.push(con['@ValorUnitario']);
        parts.push(con['@Importe']);
        parts.push(con['@ObjetoImp']);
    });
    
    parts.push('||');
    return parts.join('|');
}

// En services/pac-service/server.js

function createAndSealCfdi(ticket, ticketDetails, clientFiscalData, restaurantFiscalData, csd) {
    logger.info('[PAC-Service] Iniciando construcción y sellado de CFDI 4.0.');
    
    const { certBase64, keyBase64, password: csdPassword } = csd;
    const certFileContent = Buffer.from(certBase64, 'base64');
    const keyFileContent = Buffer.from(keyBase64, 'base64');

    const cert = new crypto.X509Certificate(certFileContent);
    const noCertificado = cert.serialNumber;
    const certificadoB64 = cert.raw.toString('base64');
    
    const conceptos = ticketDetails.map(item => {
        const importe = parseFloat((item.cantidad * item.precio).toFixed(2));
        
        // El saneamiento de la descripción se hace aquí, DENTRO del bucle.
        const descripcionSegura = (item.descripcion || 'Concepto sin descripción')
            .replace(/&/g, '&amp;')
            .replace(/</g, '&lt;')
            .replace(/>/g, '&gt;')
            .replace(/"/g, '&quot;')
            .replace(/'/g, '&apos;');

        return {
            '@ClaveProdServ': '01010101',
            '@Cantidad': item.cantidad,
            '@ClaveUnidad': 'E48',
            '@Descripcion': descripcionSegura, // Usamos la variable segura
            '@ValorUnitario': item.precio.toFixed(2),
            '@Importe': importe.toFixed(2),
            '@ObjetoImp': '02',
        };
    });

    const subTotal = conceptos.reduce((acc, con) => acc + parseFloat(con['@Importe']), 0);
    const iva = subTotal * 0.16;
    const total = subTotal + iva;

    const cfdiObject = {
        'cfdi:Comprobante': {
            '@xmlns:cfdi': 'http://www.sat.gob.mx/cfd/4',
            '@Version': '4.0', '@Serie': 'A', '@Folio': ticket.id.toString(),
            '@Fecha': new Date().toISOString().slice(0, 19),
            '@FormaPago': '01',
            '@NoCertificado': noCertificado,
            '@Certificado': certificadoB64,
            '@SubTotal': subTotal.toFixed(2),
            '@Moneda': 'MXN', '@Total': total.toFixed(2),
            '@TipoDeComprobante': 'I', '@Exportacion': '01', '@MetodoPago': 'PUE',
            '@LugarExpedicion': restaurantFiscalData.zipCode,
            '@Sello': '', // Se llena después
            'cfdi:Emisor': {
                '@Rfc': restaurantFiscalData.rfc,
                '@Nombre': restaurantFiscalData.businessName,
                '@RegimenFiscal': restaurantFiscalData.fiscalRegime,
            },
            'cfdi:Receptor': {
                '@Rfc': clientFiscalData.rfc,
                '@Nombre': clientFiscalData.razonSocial,
                '@DomicilioFiscalReceptor': clientFiscalData.zipCode,
                '@RegimenFiscalReceptor': clientFiscalData.fiscalRegime,
                '@UsoCFDI': 'G03',
            },
            'cfdi:Conceptos': { 'cfdi:Concepto': conceptos },
        }
    };
    
    const cadenaOriginal = buildCadenaOriginal(cfdiObject);
    
    // --- CORRECCIÓN CLAVE ---
    // 1. Creamos el "adaptador" para la llave privada, pasándole la contraseña.
    const privateKey = crypto.createPrivateKey({
        key: keyFileContent,
        passphrase: csdPassword,
        format: 'pem', // Formato estándar de las llaves del SAT
        type: 'pkcs8'
    });

    // 2. Usamos el 'adaptador' (privateKey) para firmar.
    const sign = crypto.createSign('RSA-SHA256');
    sign.update(cadenaOriginal);
    const sello = sign.sign(privateKey, 'base64');
    // --- FIN DE LA CORRECCIÓN ---
    
    cfdiObject['cfdi:Comprobante']['@Sello'] = sello;
    const xmlFinal = create(cfdiObject).end({ prettyPrint: true });
    
    logger.info('[PAC-Service] XML sellado manualmente y listo.');
    return xmlFinal;
}


// --- Cliente de API para Prodigia (Patrón Profesional) ---
// Centraliza la lógica de comunicación con el PAC.
// En services/pac-service/server.js

class ProdigiaClient {
    constructor(contrato, usuario, password) {
        this.baseURL = process.env.PRODIGIA_API_URL || 'https://timbrado.pade.mx/servicio/rest';
        this.authHeader = 'Basic ' + Buffer.from(`${usuario}:${password}`).toString('base64');
        this.contrato = contrato;
    }

    async _request(path, method = 'POST', body = null, queryParams = {}) {
        const params = new URLSearchParams(queryParams);
        const url = `${this.baseURL}${path}?${params.toString()}`;

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

        logger.info(`[ProdigiaClient] Requesting: ${method} ${url}`);
        const response = await fetch(url, options);
        
        const responseText = await response.text();
        if (!responseText) {
            if (!response.ok) throw new Error(`Error ${response.status}: ${response.statusText}`);
            return { success: true };
        }

        // --- CORRECCIÓN CLAVE: Verificamos si la respuesta es HTML ---
        if (responseText.trim().startsWith('<')) {
            logger.error('[ProdigiaClient] Error: PAC devolvió HTML.', { html: responseText.substring(0, 500) });
            throw new Error('El PAC devolvió una respuesta inesperada (HTML). Revisa los parámetros de la petición.');
        }

        const data = JSON.parse(responseText);

        if (!response.ok) {
            logger.error('[ProdigiaClient] Error Response:', data);
            throw new Error(data.mensaje || `Error del PAC: ${response.statusText}`);
        }
        
        logger.info('[ProdigiaClient] Response OK');
        return data;
    }

    // --- MÉTODO CORREGIDO ---
    async timbrarDesdeJson(cfdiJson, certBase64, keyBase64, keyPass, esPrueba = false) {
        const body = {
            cfdiJson,
            contrato: this.contrato, // El contrato ahora va en el body
            certBase64,
            keyBase64,
            keyPass
        };
        const queryParams = {
            prueba: esPrueba,
            opciones: ["GENERAR_PDF", "RESPUESTA_JSON"]
        };
        return this._request('/timbrado40/timbrarCfdi', 'POST', body, queryParams);
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
// --- ENDPOINT DE TIMBRADO ABSOLUTAMENTE COMPLETO ---
// En services/pac-service/server.js

app.post('/stamp', authenticateService, async (req, res) => {
    const { ticket, ticketDetails, clientFiscalData, restaurantFiscalData, csd } = req.body;
    const userId = restaurantFiscalData.userId;
    const restaurantId = restaurantFiscalData.id;

    if (!ticket || !ticketDetails || !clientFiscalData || !restaurantFiscalData || !csd) {
        return res.status(400).json({ success: false, message: 'Faltan datos para el timbrado.' });
    }

    try {
        // --- PASO 1: VERIFICAR Y USAR UN TIMBRE ---
        logger.info(`[PAC-Service] Verificando timbres para el usuario ${userId}`);
        const paymentServiceUrl = process.env.PAYMENT_SERVICE_URL || 'http://payment-service:4003';
        const stampResponse = await fetch(`${paymentServiceUrl}/internal/use-stamp`, {
            method: 'POST',
            headers: { 'Content-Type': 'application/json', 'X-Internal-Secret': process.env.INTERNAL_SECRET_KEY },
            body: JSON.stringify({ userId })
        });
        if (!stampResponse.ok) {
            const errorData = await stampResponse.json();
            return res.status(402).json({ success: false, message: errorData.message || 'No tienes timbres disponibles.' });
        }
        logger.info(`[PAC-Service] Timbre validado y descontado.`);

        // --- PASO 2: EXTRAER DATOS DEL CERTIFICADO ---
        const { certBase64, keyBase64, password: csdPassword } = csd;
        const certFileContent = Buffer.from(certBase64, 'base64');
        const cert = new crypto.X509Certificate(certFileContent);
        
        // Obtenemos el número de serie y el contenido en Base64 del certificado
        const noCertificado = cert.serialNumber;
        const certificadoB64 = cert.raw.toString('base64');

        // --- PASO 3: CONSTRUIR EL OBJETO JSON COMPLETO PARA EL PAC ---
        const subTotal = ticketDetails.reduce((acc, item) => acc + (item.cantidad * item.precio), 0);
        const total = subTotal * 1.16; // Asumiendo IVA 16%.

        const cfdiJson = {
            "noCertificado": noCertificado,
            "certificado": certificadoB64,
            "Serie": "A",
            "Folio": ticket.id.toString(),
            "Fecha": new Date().toISOString().slice(0, 19),
            "LugarExpedicion": restaurantFiscalData.zipCode,
            "Moneda": "MXN",
            "TipoDeComprobante": "I",
            "MetodoPago": "PUE",
            "FormaPago": "01",
            "SubTotal": subTotal,
            "Total": total,
            "Exportacion": "01",
            "Emisor": {
                "Rfc": restaurantFiscalData.rfc,
                "Nombre": restaurantFiscalData.businessName,
                "RegimenFiscal": restaurantFiscalData.fiscalRegime,
            },
            "Receptor": {
                "Rfc": clientFiscalData.rfc,
                "Nombre": clientFiscalData.razonSocial,
                "DomicilioFiscalReceptor": clientFiscalData.zipCode,
                "RegimenFiscalReceptor": clientFiscalData.fiscalRegime,
                "UsoCFDI": "G03",
            },
            "Conceptos": ticketDetails.map(item => ({
                "ClaveProdServ": "01010101",
                "Cantidad": item.cantidad,
                "ClaveUnidad": "E48",
                "Descripcion": item.descripcion,
                "ValorUnitario": item.precio,
                "Importe": item.cantidad * item.precio,
                "ObjetoImp": "02",
            })),
        };
        
        // --- PASO 4: TIMBRAR USANDO EL MÉTODO JSON DE PRODIGIA ---
        const client = new ProdigiaClient(
            process.env.PRODIGIA_CONTRATO,
            process.env.PRODIGIA_USUARIO,
            process.env.PRODIGIA_PASSWORD
        );
        
        logger.info(`[PAC-Service] Enviando petición de timbrado a Prodigia.`);
        const timbradoResponse = await client.timbrarDesdeJson(cfdiJson, certBase64, keyBase64, csdPassword, true);

        if (timbradoResponse.codigo !== 0) {
            logger.warn(`[PAC-Service] Fallo del PAC (${timbradoResponse.codigo}). Devolviendo timbre al usuario ${userId}.`);
            await fetch(`${paymentServiceUrl}/internal/refund-stamp`, {
                method: 'POST',
                headers: { 'Content-Type': 'application/json', 'X-Internal-Secret': process.env.INTERNAL_SECRET_KEY },
                body: JSON.stringify({ userId })
            });
            throw new Error(`Error del PAC: ${timbradoResponse.mensaje}`);
        }
        logger.info(`[PAC-Service] Timbrado exitoso. UUID: ${timbradoResponse.uuid}`);

        // --- PASO 5: GUARDAR REGISTRO EN LA BASE DE DATOS ---
        const newCfdi = await Cfdi.create({
            uuid: timbradoResponse.uuid,
            restaurantId: restaurantFiscalData.id,
            userId: userId,
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