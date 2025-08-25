// services/connector-service/server.js

require('dotenv').config();
const http = require('http');
const express = require('express');
const { WebSocketServer } = require('ws');
const { v4: uuidv4 } = require('uuid');
const { createClient } = require('redis'); // Para publicar respuestas

// --- 1. CONFIGURACIÓN INICIAL ---
const app = express();
app.use(express.json());
const server = http.createServer(app);
const wss = new WebSocketServer({ server });

// Cliente de Redis para publicar mensajes en el canal de respuestas.
const publisher = createClient({ url: process.env.REDIS_URL || 'redis://redis:6379' });
publisher.on('error', (err) => console.error('[Connector-Service] Error en el cliente Redis Publisher:', err));
publisher.connect();

// Mapa para guardar las conexiones activas de los agentes.
const clients = new Map();

console.log('[Connector-Service] Servicio iniciando...');

// --- 2. LÓGICA DE MANEJO DE CONEXIONES WEBSOCKET ---
wss.on('connection', (ws, req) => {
    const agentKey = req.headers['x-agent-key'];

    if (!agentKey) {
        console.warn('[Connector-Service] Conexión rechazada: Falta la cabecera X-Agent-Key.');
        ws.terminate();
        return;
    }

    // TODO: Validar 'agentKey' contra la base de datos para obtener el restaurantId real.
    // Por ahora, el agentKey (que debería ser el restaurantId) será nuestro identificador.
    const clientId = agentKey;

    ws.id = uuidv4(); // ID único para la sesión actual de la conexión
    clients.set(clientId, ws);

    console.log(`[Connector-Service] Agente conectado. Cliente ID: ${clientId}. Sesión: ${ws.id}. Clientes totales: ${clients.size}`);
    ws.send(JSON.stringify({ type: 'welcome', message: 'Conexión establecida con NextFactura.' }));

    // --- MANEJO DE MENSAJES DEL AGENTE ---
    ws.on('message', (message) => {
        try {
            const parsedMessage = JSON.parse(message);
            console.log(`[Connector-Service] Mensaje recibido del Cliente ID ${clientId}.`);

            // Verificamos si este mensaje es una respuesta a una petición anterior
            if (parsedMessage.correlationId) {
                const responsePayload = JSON.stringify({
                    correlationId: parsedMessage.correlationId,
                    data: parsedMessage.data || null,
                    error: parsedMessage.error || null,
                });

                // Publicamos la respuesta en el canal de Redis para que el pos-service la escuche.
                publisher.publish('agent-responses', responsePayload);
                console.log(`[Connector-Service] Respuesta para ${parsedMessage.correlationId} publicada en Redis.`);
            }

        } catch (error) {
            console.error(`[Connector-Service] Error procesando mensaje del Cliente ID ${clientId}:`, error);
        }
    });

    // --- MANEJO DE DESCONEXIÓN Y ERRORES ---
    ws.on('close', () => {
        clients.delete(clientId);
        console.log(`[Connector-Service] Agente desconectado. Cliente ID: ${clientId}. Clientes totales: ${clients.size}`);
    });

    ws.on('error', (error) => {
        console.error(`[Connector-Service] Error en la conexión del Cliente ID ${clientId}:`, error);
    });
});

// --- 3. API INTERNA PARA QUE OTROS SERVICIOS USEN EL CONECTOR ---
app.post('/internal/send-command', (req, res) => {
    const { clientId, command, correlationId, data } = req.body;

    if (!clientId || !command || !correlationId) {
        return res.status(400).json({ success: false, message: 'clientId, command, y correlationId son requeridos.' });
    }

    console.log(`[Connector-Service] Petición interna para enviar '${command}' al Cliente ID ${clientId} (Corr: ${correlationId})`);
    const targetClient = clients.get(clientId);

    if (targetClient && targetClient.readyState === 1) { // 1 === WebSocket.OPEN
        const message = JSON.stringify({ command, correlationId, data });
        targetClient.send(message);
        console.log(`[Connector-Service] Comando '${command}' enviado exitosamente al Cliente ID ${clientId}.`);
        res.status(200).json({ success: true, message: "Comando enviado al agente." });
    } else {
        console.error(`[Connector-Service] ERROR: No se pudo enviar el comando. Agente con Cliente ID ${clientId} no encontrado o no conectado.`);
        res.status(404).json({ success: false, message: `Agente con Cliente ID ${clientId} no está conectado.` });
    }
});

app.get('/health', (req, res) => {
    res.status(200).json({
        status: 'ok',
        connectedClients: clients.size,
        redisConnected: publisher.isOpen,
    });
});

// --- 4. INICIAR EL SERVIDOR ---
const PORT = process.env.CONNECTOR_SERVICE_PORT || 4006;
server.listen(PORT, () => {
    console.log(`🚀 Connector-Service (HTTP y WebSocket) escuchando en el puerto ${PORT}`);
});