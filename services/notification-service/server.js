// Usamos require('crypto') para generar IDs de petición únicos para los logs
const crypto = require('crypto');
const express = require('express');
const cors = require('cors');
const { Resend } = require('resend');

const app = express();
app.use(cors());
app.use(express.json({ limit: '5mb' })); // Límite generoso para los adjuntos en base64

// --- INICIALIZACIÓN DEL CLIENTE DE RESEND ---
// El constructor de Resend buscará automáticamente la variable de entorno RESEND_API_KEY
const resend = new Resend();

// --- MIDDLEWARE DE SEGURIDAD INTERNA ---
// Asegura que solo otros de tus microservicios puedan llamar a estos endpoints
const authenticateService = (req, res, next) => {
    const secretKey = req.headers['x-internal-secret'];
    if (!secretKey || secretKey !== process.env.INTERNAL_SECRET_KEY) {
        console.warn('[Notification-Service] Intento de acceso no autorizado sin clave interna.');
        return res.status(403).json({ success: false, message: 'Acceso no autorizado.' });
    }
    next();
};

// --- MIDDLEWARE DE LOGGING PROFESIONAL ---
// Registra cada petición entrante con un ID único para fácil seguimiento
app.use((req, res, next) => {
    const requestId = crypto.randomUUID();
    req.id = requestId; // Adjuntamos el ID a la petición para usarlo en otros logs
    console.log(`[Request IN] ID: ${requestId} | ${req.method} ${req.originalUrl} | IP: ${req.ip}`);
    next();
});

// --- ENDPOINTS DEL SERVICIO ---

// Endpoint de salud para Docker
app.get('/health', (req, res) => {
    res.status(200).json({ status: 'ok' });
});

// Endpoint para enviar la factura (llamado por el pac-service)
app.post('/send-invoice', authenticateService, async (req, res) => {
    const { recipientEmail, pdfBase64, xmlBase64, clientName, restaurantName } = req.body;

    console.log(`[Request RUN] ID: ${req.id} | Iniciando envío de factura a ${recipientEmail}`);

    if (!recipientEmail || !pdfBase64 || !xmlBase64) {
        console.error(`[Request FAIL] ID: ${req.id} | Faltan datos para enviar la factura.`);
        return res.status(400).json({ success: false, message: 'Faltan datos para enviar la factura.' });
    }
    
    try {
        await resend.emails.send({
            from: `Facturación ${restaurantName} <${process.env.EMAIL_FROM}>`,
            to: recipientEmail,
            subject: `Tu factura de ${restaurantName}`,
            html: `<p>Hola ${clientName || ''},</p><p>Adjuntamos tu factura electrónica en formatos PDF y XML.</p><p>Gracias por tu preferencia.</p>`,
            attachments: [
                { filename: 'factura.pdf', content: pdfBase64 },
                { filename: 'factura.xml', content: xmlBase64 },
            ],
        });
        console.log(`[Request OK] ID: ${req.id} | Correo de factura enviado exitosamente a ${recipientEmail}`);
        res.status(200).json({ success: true, message: 'Correo enviado.' });
    } catch (error) {
        console.error(`[Request FAIL] ID: ${req.id} | Error de Resend al enviar factura:`, error);
        res.status(500).json({ success: false, message: 'Error al enviar el correo de la factura.' });
    }
});

// Endpoint para el formulario de contacto (llamado por el frontend web y mobile)
// Este es público, pero en producción podrías añadir un rate-limiter aquí.
app.post('/contact-form', async (req, res) => {
    const { subject, message, userInfo } = req.body;
    const fromEmail = userInfo?.email || 'Usuario Anónimo';

    console.log(`[Request IN] ID: ${req.id} | Mensaje de contacto recibido de ${fromEmail}`);

    if (!subject || !message) {
        console.error(`[Request FAIL] ID: ${req.id} | Formulario de contacto incompleto.`);
        return res.status(400).json({ success: false, message: 'El asunto y el mensaje son requeridos.' });
    }

    try {
        const emailHtml = `
            <h1>Nuevo Mensaje de Soporte desde Formulario</h1>
            <p><strong>De:</strong> ${fromEmail}</p>
            <p><strong>User ID:</strong> ${userInfo?.id || 'N/A'}</p>
            <p><strong>Asunto:</strong> ${subject}</p>
            <hr>
            <p style="white-space: pre-wrap;">${message}</p>
        `;
        
        await resend.emails.send({
            from: `Contacto Plataforma <${process.env.EMAIL_FROM}>`,
            to: process.env.SUPPORT_EMAIL,
            subject: `Nuevo Mensaje: ${subject}`,
            html: emailHtml,
        });
        console.log(`[Request OK] ID: ${req.id} | Mensaje de contacto enviado a soporte.`);
        res.status(200).json({ success: true, message: 'Mensaje enviado exitosamente.' });

    } catch (error) {
        console.error(`[Request FAIL] ID: ${req.id} | Error de Resend al enviar mensaje de contacto:`, error);
        res.status(500).json({ success: false, message: 'Error al enviar el mensaje.' });
    }
});

// --- ARRANQUE DEL SERVIDOR ---
const PORT = process.env.NOTIFICATION_SERVICE_PORT || 4007;
app.listen(PORT, () => {
    console.log(`🚀 Notification-Service escuchando en el puerto ${PORT}`);
    if (!process.env.RESEND_API_KEY) {
        console.warn('ADVERTENCIA: La variable RESEND_API_KEY no está configurada. El envío de correos no funcionará.');
    }
});