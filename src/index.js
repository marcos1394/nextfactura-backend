// --- app.js (Refactorizado para Cognito + Monolito Lambda) ---



// --- Imports ---

const express = require('express');

const serverless = require('serverless-http'); // Para compatibilidad con Lambda

const bodyParser = require('body-parser');

const { Sequelize, DataTypes, Op } = require('sequelize'); // Sequelize y Operadores

const AWS = require('aws-sdk'); // SDK de AWS para SES, S3, Route53

const { MercadoPagoConfig, Preference, Payment} = require('mercadopago'); // SDK Mercado Pago

const fetch = require('node-fetch'); // Si lo usas para llamadas externas

const multer = require('multer'); // Para subida de archivos

const sql = require('mssql'); // Para conectar a SQL Server



const upload = multer(); // Instancia de Multer



const app = express(); // Instancia de Express



// --- Configuración de Sequelize (Conexión a tu RDS Postgres) ---

// Asegúrate de que las variables de entorno estén configuradas en tu Lambda

const sequelize = new Sequelize(process.env.DB_NAME, process.env.DB_USER, process.env.DB_PASSWORD, {

  host: process.env.DB_HOST,

  dialect: 'postgres',

  logging: console.log, // Cambia a false en producción si no necesitas logs de SQL

  dialectOptions: {

    ssl: {

      require: true,

      rejectUnauthorized: false, // Considera usar el CA correcto en producción

    },

    keepAlive: true,

  },

  pool: { max: 5, min: 0, idle: 30000, acquire: 60000 },

});



// --- Modelos de Datos Sequelize Adaptados ---



// Modelo User: SIN contraseña ni tokens. USA cognitoSub como PK.

const User = sequelize.define('User', {

    cognitoSub: {

        type: DataTypes.STRING,

        allowNull: false,

        unique: true,

        primaryKey: true, // 'sub' de Cognito como Clave Primaria

    },

    name: { type: DataTypes.STRING, field: 'name', allowNull: true },

    email: { type: DataTypes.STRING, field: 'email', allowNull: false, unique: true },

    username: { type: DataTypes.STRING, field: 'username', allowNull: true }, // username de Cognito

    restaurantName: { type: DataTypes.STRING, field: 'restaurantname', allowNull: true },

    phoneNumber: { type: DataTypes.STRING, field: 'phonenumber', allowNull: true },

    role: { type: DataTypes.STRING, field: 'role', defaultValue: 'RestaurantOwners' }, // Rol de la aplicación

    createdAt: { type: DataTypes.DATE, field: 'createdat' },

    updatedAt: { type: DataTypes.DATE, field: 'updatedat' },

  }, {

    tableName: 'users',

    freezeTableName: true,

    timestamps: true,

    indexes: [ { fields: ['email'], unique: true } ]

  }

);



// Modelo Restaurant: user_id ahora es cognitoSub

const Restaurant = sequelize.define('Restaurant', {

    id: { type: DataTypes.INTEGER, primaryKey: true, autoIncrement: true }, // Mantenemos un ID numérico interno para Restaurant

    user_id: { type: DataTypes.STRING, field: 'user_id', allowNull: false, references: { model: User, key: 'cognitoSub' } }, // FK a User.cognitoSub

    name: { type: DataTypes.STRING, field: 'name' },

    address: { type: DataTypes.STRING, field: 'address' },

    connection_host: { type: DataTypes.STRING, field: 'connection_host' },

    connection_port: { type: DataTypes.STRING, field: 'connection_port' },

    connection_user: { type: DataTypes.STRING, field: 'connection_user' },

    connection_password: { type: DataTypes.STRING, field: 'connection_password' },

    connection_db_name: { type: DataTypes.STRING, field: 'connection_db_name' },

    logo_url: { type: DataTypes.STRING, field: 'logo_url' },

    vpn_username: { type: DataTypes.STRING, field: 'vpn_username' },

    vpn_password: { type: DataTypes.STRING, field: 'vpn_password' }

  }, {

    tableName: 'restaurants',

    freezeTableName: true,

    timestamps: true,

    indexes: [ { fields: ['user_id'] } ] // Índice en user_id

  }

);



// Modelo PortalConfig: user_id ahora es cognitoSub

const PortalConfig = sequelize.define('PortalConfig', {

    id: { type: DataTypes.INTEGER, primaryKey: true, autoIncrement: true },

    user_id: { type: DataTypes.STRING, allowNull: false, references: { model: User, key: 'cognitoSub' } },

    portal_name: { type: DataTypes.STRING },

    portal_logo_url:{type:DataTypes.STRING},

    custom_domain: { type: DataTypes.STRING },

    primary_color: { type: DataTypes.STRING },

    secondary_color: { type: DataTypes.STRING },

  }, {

    tableName: 'portal_config',

    freezeTableName: true,

    timestamps: true,

    indexes: [ { fields: ['user_id'] } ]

  }

);



// Modelo FiscalData: restaurant_id referencia Restaurants.id

const FiscalData = sequelize.define('FiscalData', {

    id: { type: DataTypes.INTEGER, primaryKey: true, autoIncrement: true },

    restaurant_id: { type: DataTypes.INTEGER, field: 'restaurant_id', allowNull: false, references: { model: Restaurant, key: 'id' } }, // FK a Restaurants.id

    rfc: { type: DataTypes.STRING, field: 'rfc' },

    fiscal_address: { type: DataTypes.STRING, field: 'fiscal_address' },

    csd_password: { type: DataTypes.STRING, field: 'csd_password' },

    csd_certificate_url: { type: DataTypes.STRING, field: 'csd_certificate_url' },

    csd_key_url: { type: DataTypes.STRING, field: 'csd_key_url' },

  }, {

    tableName: 'fiscal_data',

    freezeTableName: true,

    timestamps: true,

    indexes: [ { fields: ['restaurant_id'] } ]

  }

);



// Modelo PlanPurchase: user_id ahora es cognitoSub

const PlanPurchase = sequelize.define('PlanPurchase', {

    id: { type: DataTypes.INTEGER, primaryKey: true, autoIncrement: true },

    user_id: { type: DataTypes.STRING, allowNull: false, references: { model: User, key: 'cognitoSub' } },

    plan_name: { type: DataTypes.STRING, allowNull: false },

    price: { type: DataTypes.FLOAT, allowNull: false },

    purchase_date: { type: DataTypes.DATE, defaultValue: DataTypes.NOW },

    status: { type: DataTypes.STRING, defaultValue: 'pending', allowNull: false },

    payment_id: { type: DataTypes.STRING, allowNull: true, unique: true },

    payment_provider: { type: DataTypes.STRING, defaultValue: 'mercadopago' },

    preference_id: { type: DataTypes.STRING, allowNull: true },

    notes: { type: DataTypes.TEXT, allowNull: true },

    createdAt: { type: DataTypes.DATE, field: 'createdat' }, // Asegurar nombres correctos

    updatedAt: { type: DataTypes.DATE, field: 'updatedat' },

  }, {

    tableName: 'plan_purchases',

    freezeTableName: true,

    timestamps: true, // Sequelize maneja createdAt y updatedAt

    indexes: [

        { fields: ['user_id', 'status'] },

        { fields: ['payment_id'], unique: true, where: { payment_id: { [Op.ne]: null } } }

    ]

  }

);



app.use((req, res, next) => {

    // Loguear método, path y headers importantes al inicio

    console.log(`[DEBUG] >>> Request Start: ${req.method} ${req.path}`);

    console.log('[DEBUG] Request Headers (Inicio):', JSON.stringify({

        'content-type': req.headers['content-type'], // Loguear específicamente content-type

        'origin': req.headers['origin'],

        // Añade otros headers si son relevantes para depurar

    }, null, 2));

    next();

  });



  // Middleware para Parsear JSON (¡Asegúrate que esté aquí!)

app.use(bodyParser.json());

// Middleware para Parsear URL-Encoded (Probablemente no necesario si solo usas JSON)

app.use(bodyParser.urlencoded({ extended: true }));



app.use((req, res, next) => {

    console.log('[DEBUG] Body Type AFTER Parsers:', typeof req.body);

    console.log('[DEBUG] Is Body a Buffer?:', Buffer.isBuffer(req.body));

    console.log('[DEBUG] Body AFTER Parsers (Raw):', JSON.stringify(req.body, null, 2));

 

    // Intentar parsear manualmente SI ES UN BUFFER y el Content-Type era JSON

    if (Buffer.isBuffer(req.body) && req.headers['content-type']?.includes('application/json')) {

        console.warn('[DEBUG] Body still a Buffer despite Content-Type JSON! Attempting manual parse...');

        try {

            // API Gateway Lambda Proxy puede enviar el body como string base64 o texto plano

            let bodyString;

            if (req.apiGateway?.event?.isBase64Encoded) {

                console.log('[DEBUG] Body seems Base64 encoded, decoding...');

                bodyString = Buffer.from(req.apiGateway.event.body, 'base64').toString('utf8');

            } else {

                // Si no está codificado en base64, serverless-http debería pasarlo como string

                // o el body original si bodyParser falló. Intentemos convertir el buffer.

                bodyString = req.body.toString('utf8');

                // O intenta obtenerlo del evento original si serverless-http no lo modificó

                // bodyString = req.apiGateway?.event?.body;

            }

 

            if (typeof bodyString === 'string' && bodyString.length > 0) {

                console.log('[DEBUG] Body as String:', bodyString);

                // Parsear el string a JSON y REEMPLAZAR req.body

                req.body = JSON.parse(bodyString);

                console.log('[DEBUG] Manual parse SUCCESS. New req.body:', JSON.stringify(req.body, null, 2));

            } else {

               console.warn('[DEBUG] Body string is empty or invalid after potential decoding.');

            }

        } catch (parseError) {

            console.error('[DEBUG] Manual JSON parse FAILED:', parseError);

            // Dejar req.body como Buffer, la ruta fallará después

        }

    }

    next();

  });



  app.use((req, res, next) => {

    const origin = req.headers.origin;

    console.log(`[CORS Middleware] Request Origin Header: ${origin}`);



    // Define tus orígenes permitidos: cadenas exactas y expresiones regulares

    const allowedOriginsPatterns = [

        process.env.CLIENT_URL_PROD || "https://nextmanager.com.mx",

        process.env.CLIENT_URL_PROD_WWW || "https://www.nextmanager.com.mx",

        process.env.CLIENT_URL_DEV || "http://localhost:3000", // Para desarrollo local del micrositio

        // Regex para permitir CUALQUIER subdominio de nextmanager.com.mx bajo https

        /^https:\/\/[a-zA-Z0-9-]+\.nextmanager\.com\.mx$/

    ];



    let originIsAllowed = false;



    if (origin) { // Si el header 'Origin' está presente

        for (const pattern of allowedOriginsPatterns) {

            if (pattern instanceof RegExp && pattern.test(origin)) {

                originIsAllowed = true;

                break;

            }

            if (typeof pattern === 'string' && pattern === origin) {

                originIsAllowed = true;

                break;

            }

        }

    } else {

        // Si no hay 'Origin' header, no es estrictamente una solicitud CORS del navegador que necesite ACAO para ser validada.

        // Puede ser una solicitud del mismo origen, una herramienta como Postman, o una prueba desde API Gateway.

        // Dejamos que continúe; si el navegador lo interpreta como CORS y no tenía 'Origin', ya fallaría antes.

        // O, si queremos ser estrictos y solo permitir orígenes definidos para cualquier solicitud:

        // originIsAllowed = false; // (pero esto podría bloquear Postman/pruebas directas sin origin)

        // Por ahora, asumimos que si no hay 'Origin', no es un bloqueo CORS del navegador.

        console.log("[CORS Middleware] No Origin header present in request.");

    }



    if (originIsAllowed) {

        res.setHeader('Access-Control-Allow-Origin', origin); // Refleja el origen que hizo match

        console.log(`[CORS Middleware] Origin allowed and header set: ${origin}`);

    } else if (origin) { // Si había un 'Origin' pero no coincidió con ningún patrón

        console.warn(`[CORS Middleware] Origin NOT ALLOWED by custom logic: ${origin}`);

        // No se establece 'Access-Control-Allow-Origin', el navegador lo bloqueará.

    }

   

    // Estas cabeceras son importantes para el preflight (OPTIONS) y también para la solicitud principal.

    res.setHeader('Access-Control-Allow-Methods', 'GET, POST, PUT, DELETE, OPTIONS');

    res.setHeader('Access-Control-Allow-Headers', 'Content-Type, Authorization, X-Amz-Date, X-Api-Key, X-Amz-Security-Token, X-Amz-User-Agent');

    // Para 'Access-Control-Allow-Credentials', si es 'true', 'Access-Control-Allow-Origin' NO puede ser '*'.

    // Si no usas cookies/sesiones cross-origin, 'false' es más seguro.

    res.setHeader('Access-Control-Allow-Credentials', 'false');



    // Manejo específico para la petición pre-flight OPTIONS

    if (req.method === 'OPTIONS') {

        console.log(`[CORS Middleware] Handling OPTIONS preflight request from origin: ${origin}`);

        // Respondemos con éxito (204 No Content es común para OPTIONS).

        // Las cabeceras necesarias ya fueron establecidas arriba.

        return res.sendStatus(204);

    }



    // Continuar al siguiente middleware o ruta

    next();

});





// --- Servicios AWS y Mercado Pago ---

// Asegúrate de tener las variables de entorno configuradas en Lambda

const client = new MercadoPagoConfig({ accessToken: process.env.MP_ACCESS_TOKEN });

const s3 = new AWS.S3();

const route53 = new AWS.Route53();

const ses = new AWS.SES({ region: process.env.AWS_REGION || 'us-east-1' });



// --- Funciones Auxiliares (Completas) ---



// Función para enviar correos con SES (para emails de la aplicación, no de Cognito)

async function sendEmailWithSES({ toEmail, subject, textBody, htmlBody, fromEmail = process.env.EMAIL_FROM }) {

  if (!fromEmail) {

    console.error('Error: La variable de entorno EMAIL_FROM (remitente verificado en SES) no está configurada.');

    throw new Error('La configuración del servidor para enviar correos está incompleta.');

  }

  if (!toEmail || !subject || (!textBody && !htmlBody)) {

      throw new Error('Faltan parámetros requeridos para enviar el correo (destinatario, asunto, cuerpo).');

  }



  const params = {

    Destination: { ToAddresses: [toEmail] },

    Message: {

      Body: {},

      Subject: { Charset: 'UTF-8', Data: subject },

    },

    Source: fromEmail, // Remitente verificado en SES

    // ReplyToAddresses: [ fromEmail ], // Opcional

  };



  if (textBody) {

      params.Message.Body.Text = { Charset: 'UTF-8', Data: textBody };

  }

  if (htmlBody) {

      params.Message.Body.Html = { Charset: 'UTF-8', Data: htmlBody };

  }

  if (!params.Message.Body.Text && !params.Message.Body.Html) {

    throw new Error('Se debe proporcionar al menos un cuerpo de mensaje (textBody o htmlBody).');

  }



  try {

    console.log(`[SES Send] Intentando enviar correo a: ${toEmail}, Asunto: ${subject}`);

    const data = await ses.sendEmail(params).promise();

    console.log(`[SES Send] Correo enviado exitosamente a ${toEmail}. MessageId: ${data.MessageId}`);

    return data; // Devolver data por si es útil

  } catch (err) {

    console.error(`[SES Send] Error al enviar correo a ${toEmail}:`, err.message);

    console.error('[SES Send] Detalles del error:', err);

    throw new Error(`Error al enviar el correo: ${err.message}`);

  }

}



// Función para subir archivos a S3

async function uploadFileToS3(file, key, attempt = 1) {

    const MAX_RETRIES = 2; // Número de reintentos

    const bucketName = process.env.S3_BUCKET_NAME;

    if (!bucketName) {

        console.error('Error: La variable de entorno S3_BUCKET_NAME no está configurada.');

        throw new Error('Configuración de S3 incompleta.');

    }



    const params = {

      Bucket: bucketName,

      Key: key, // ej: csd/userId/timestamp_filename.ext

      Body: file.buffer,

      ContentType: file.mimetype,

      // ACL: 'private' // O 'public-read' si necesitas acceso público directo (menos seguro)

    };



    try {

      console.log(`[S3 Upload] Intentando subir archivo a: ${bucketName}/${key} (Intento ${attempt})`);

      await s3.putObject(params).promise();

      // Construir la URL manualmente puede ser frágil si cambian las convenciones.

      // Es más seguro usar el bucket y key, o generar URLs prefirmadas si es para descarga temporal.

      const fileUrl = `https://${bucketName}.s3.${process.env.AWS_REGION || 'us-east-1'}.amazonaws.com/${key}`;

      console.log(`[S3 Upload] Archivo subido exitosamente a: ${fileUrl}`);

      return fileUrl;

    } catch (err) {

      console.error(`[S3 Upload] Intento #${attempt} fallido para ${key}`, err);

      if (attempt <= MAX_RETRIES) {

        console.log(`[S3 Upload] Reintentando subida para ${key} (Intento ${attempt + 1})`);

        // Espera exponencial simple (opcional)

        await new Promise(resolve => setTimeout(resolve, 500 * attempt));

        return uploadFileToS3(file, key, attempt + 1);

      } else {

        console.error(`[S3 Upload] Fallaron todos los intentos para ${key}`);

        throw err; // Propaga el error final

      }

    }

  }



  const HOSTED_ZONE_ID = process.env.ROUTE53_HOSTED_ZONE_ID;

  const BASE_DOMAIN = process.env.BASE_DOMAIN;

  const CLOUDFRONT_DOMAIN_NAME = process.env.CLOUDFRONT_DOMAIN_NAME;





// Función para crear subdominios en Route53 (si todavía la necesitas)

async function createSubdomainInRoute53(subdomainPrefix) {

    console.log(`[Route53 Helper] Iniciando creación/actualización de CNAME para prefijo: ${subdomainPrefix}`);



    if (!subdomainPrefix || !HOSTED_ZONE_ID || !BASE_DOMAIN || !CLOUDFRONT_DOMAIN_NAME) {

        const missing = [

            !subdomainPrefix ? 'subdomainPrefix' : null,

            !HOSTED_ZONE_ID ? 'HOSTED_ZONE_ID' : null,

            !BASE_DOMAIN ? 'BASE_DOMAIN' : null,

            !CLOUDFRONT_DOMAIN_NAME ? 'CLOUDFRONT_DOMAIN_NAME' : null,

        ].filter(Boolean).join(', ');

        console.error(`[Route53 Helper] Faltan datos críticos: ${missing}. Verifica las variables de entorno.`);

        throw new Error('Configuración de Route53 incompleta en el servidor.');

    }



    // --- ¡LA CORRECCIÓN ES ESTA LÍNEA! ---

    const fullRecordName = `${subdomainPrefix}.${BASE_DOMAIN}.`; // Construir FQDN completo con punto final

    // --------------------------------------



    const params = {

        HostedZoneId: HOSTED_ZONE_ID,

        ChangeBatch: {

            Changes: [

                {

                    Action: 'UPSERT', // UPSERT es útil: crea si no existe, actualiza si ya existe.

                    ResourceRecordSet: {

                        Name: fullRecordName, // <<< Usar el nombre completo aquí

                        Type: 'CNAME',

                        TTL: 300, // Tiempo de vida del caché DNS (ej. 5 minutos)

                        ResourceRecords: [

                            {

                                Value: CLOUDFRONT_DOMAIN_NAME // Apunta al dominio de CloudFront

                            }

                        ],

                    },

                },

            ],

            Comment: `Upsert CNAME record for portal subdomain ${fullRecordName}` // Comentario útil para Route 53

        },

    };



    try {

        console.log(`[Route53 Helper] Ejecutando changeResourceRecordSets con parámetros: ${JSON.stringify(params)}`);

        const data = await route53.changeResourceRecordSets(params).promise();

        console.log('[Route53 Helper] Respuesta exitosa de changeResourceRecordSets:', JSON.stringify(data));

        return data; // Devuelve la respuesta de la API

    } catch (error) {

        console.error(`[Route53 Helper] Error al ejecutar changeResourceRecordSets para ${fullRecordName}:`, error);

        // Re-lanzar el error para que el handler principal lo capture, haga rollback, y devuelva 500

        throw new Error(`Error al crear/actualizar el registro DNS en Route53: ${error.message || error.code}`);

    }

}





// --- Helper para Obtener User ID (Cognito Sub) desde API Gateway ---

const getUserIdFromEvent = (req) => {

  try {

      const claims = req.apiGateway.event?.requestContext?.authorizer?.claims;

      const cognitoSub = claims?.sub;

      if (cognitoSub) {

          // console.log('[Auth Helper] Cognito Sub (UserID):', cognitoSub); // Evita loguear IDs en prod si es posible

          return cognitoSub;

      }

      console.warn('[Auth Helper] No se encontró "sub" de Cognito en requestContext.authorizer.claims.');

      return null;

  } catch (e) {

      console.error('[Auth Helper] Error extrayendo sub de Cognito:', e);

      return null;

  }

};



// --- Helper para verificar propiedad de restaurante (Opcional pero recomendado) ---

const checkRestaurantOwnership = async (userIdCognitoSub, restaurantId) => {

    if (!userIdCognitoSub || !restaurantId) return null;

    try {

        const restaurant = await Restaurant.findOne({

            where: {

                id: restaurantId, // Busca por PK de Restaurante

                user_id: userIdCognitoSub // Y verifica que pertenezca al usuario autenticado (FK a User.cognitoSub)

            }

        });

        return restaurant; // Devuelve el objeto restaurante si se encuentra y pertenece, null si no

    } catch (error) {

        console.error(`[Ownership Check] Error verificando propiedad de restaurante ${restaurantId} para usuario ${userIdCognitoSub}:`, error);

        return null; // Devuelve null en caso de error de BD

    }

};





// --- Endpoints de Negocio (Adaptados y Completos) ---

// Recuerda configurar el Cognito Authorizer en API Gateway para estos



// Endpoint Protegido: Configuración inicial de portal y restaurantes

app.post('/api/portal-and-restaurants-setup', upload.any(), async (req, res) => {

    const userIdCognitoSub = getUserIdFromEvent(req);

    if (!userIdCognitoSub) { return res.status(401).json({ success: false, message: 'No autenticado.' }); }

    console.log(`[Portal Setup] Iniciando para Sub: ${userIdCognitoSub}`);



    try {

        const portalConfigStr = req.body.portalConfig || '{}';

        const portalConfigParsed = JSON.parse(portalConfigStr);

        const restaurantsData = [];

        let index = 0;

        while (req.body[`restaurants[${index}][name]`] !== undefined) {

            restaurantsData.push({

              name: req.body[`restaurants[${index}][name]`],

              address: req.body[`restaurants[${index}][address]`],

              rfc: req.body[`restaurants[${index}][rfc]`],

              fiscal_address: req.body[`restaurants[${index}][fiscal_address]`],

              csd_password: req.body[`restaurants[${index}][csd_password]`],

              // Incluir connection data si viene del form

              connection_host: req.body[`restaurants[${index}][connection_host]`],

              connection_port: req.body[`restaurants[${index}][connection_port]`],

              connection_user: req.body[`restaurants[${index}][connection_user]`],

              connection_password: req.body[`restaurants[${index}][connection_password]`],

              connection_db_name: req.body[`restaurants[${index}][connection_db_name]`],

              vpn_username: req.body[`restaurants[${index}][vpn_username]`],

              vpn_password: req.body[`restaurants[${index}][vpn_password]`],

            });

            index++;

        }

        console.log(`[Portal Setup] Datos de restaurantes parseados: ${restaurantsData.length}`);



        // Manejo de archivos subidos

        const fileUploadPromises = req.files.map(async (file) => {

          const match = file.fieldname.match(/restaurants\[(\d+)\]\[(.*?)\]/);

          if (!match) return;

          const i = parseInt(match[1], 10);

          const field = match[2]; // csd_certificate, csd_key, logo

          const s3Key = `user_uploads/${userIdCognitoSub}/restaurant_${i}/${field}_${Date.now()}_${file.originalname}`;

          const s3Url = await uploadFileToS3(file, s3Key);

          if (restaurantsData[i]) { // Asegura que el índice exista

              restaurantsData[i][`${field}_url`] = s3Url;

          }

        });

        await Promise.all(fileUploadPromises);

        console.log(`[Portal Setup] Archivos S3 procesados.`);



        // Guardar PortalConfig

        const savedPortalConfig = await PortalConfig.create({

            user_id: userIdCognitoSub,

            portal_name: portalConfigParsed.portalName || 'Mi Portal', // Default

            custom_domain: portalConfigParsed.customDomain || '', // Validar este dominio?

            primary_color: portalConfigParsed.primaryColor || '#3B82F6', // Default blue

            secondary_color: portalConfigParsed.secondaryColor || '#6B7280', // Default gray

        });

        console.log(`[Portal Setup] PortalConfig guardado ID: ${savedPortalConfig.id}`);



        // Crear Restaurants y FiscalData

        const createdRestaurants = [];

        for (const rData of restaurantsData) {

            const restaurant = await Restaurant.create({

                user_id: userIdCognitoSub,

                name: rData.name,

                address: rData.address,

                logo_url: rData.logo_url || null,

                connection_host: rData.connection_host,

                connection_port: rData.connection_port,

                connection_user: rData.connection_user,

                connection_password: rData.connection_password,

                connection_db_name: rData.connection_db_name,

                vpn_username: rData.vpn_username,

                vpn_password: rData.vpn_password,

            });

            console.log(`[Portal Setup] Restaurant creado ID: ${restaurant.id}`);



            const fiscalData = await FiscalData.create({

                restaurant_id: restaurant.id, // FK al ID del restaurante recién creado

                rfc: rData.rfc,

                fiscal_address: rData.fiscal_address,

                csd_password: rData.csd_password, // Considerar cifrar esta contraseña

                csd_certificate_url: rData.csd_certificate_url || null,

                csd_key_url: rData.csd_key_url || null,

            });

            console.log(`[Portal Setup] FiscalData creada ID: ${fiscalData.id} para Restaurant ID: ${restaurant.id}`);

            createdRestaurants.push({ restaurant, fiscalData });

        }



        // Opcional: Crear subdominio en Route53 si se proporcionó un custom_domain para el portal

        if (savedPortalConfig.custom_domain) {

             try {

                 // await createSubdomainInRoute53(savedPortalConfig.custom_domain); // Descomentar si se necesita

                 console.log(`[Portal Setup] Creación de subdominio para ${savedPortalConfig.custom_domain} iniciada (si la función está habilitada).`);

             } catch (dnsError) {

                 console.error(`[Portal Setup] Falló la creación del subdominio ${savedPortalConfig.custom_domain}:`, dnsError);

                 // Considerar si este error debe impedir la respuesta exitosa

             }

        }



        console.log(`[Portal Setup] Proceso completado para Sub: ${userIdCognitoSub}`);

        return res.status(201).json({

            success: true,

            message: 'Portal y restaurantes configurados con éxito.',

            portalConfig: savedPortalConfig,

            restaurants: createdRestaurants,

        });



    } catch (err) {

        console.error(`[Portal Setup] Error para Sub: ${userIdCognitoSub}:`, err);

        return res.status(500).json({

            success: false,

            message: 'Error al configurar portal y restaurantes',

            details: err.message,

        });

    }

});



// Endpoint Público?: Obtener Marca del Portal

app.get('/api/portal/brand', async (req, res) => {

    const { domain } = req.query; // Asume que el dominio viene como query param

    if (!domain) {

      return res.status(400).json({ success: false, message: 'Falta parámetro domain' });

    }

    console.log(`[Portal Brand] Buscando config para dominio: ${domain}`);

    try {

      // Buscar por el dominio personalizado exacto

      const portal = await PortalConfig.findOne({ where: { custom_domain: domain } });

      if (!portal) {

        console.log(`[Portal Brand] No se encontró config para: ${domain}`);

        // Devolver éxito=false o quizás datos default? Depende del requerimiento.

        // Devolver 404 es apropiado si el portal no existe.

        return res.status(404).json({ success: false, message: 'Configuración del portal no encontrada.' });

      }

      console.log(`[Portal Brand] Config encontrada para: ${domain}, ID: ${portal.id}`);

      // Devolver solo los datos públicos de marca

      return res.json({

        success: true,

        data: {

          portalName: portal.portal_name,

          primaryColor: portal.primary_color,

          secondaryColor: portal.secondary_color,

          // Podrías añadir logo_url si lo guardas en PortalConfig también

        },

      });

    } catch (err) {

      console.error(`[Portal Brand] Error buscando config para ${domain}:`, err);

      return res.status(500).json({ success: false, message: 'Error interno del servidor.' });

    }

  });



// Endpoint Protegido: Crear Preferencia de Pago

app.post('/api/payment/create-payment', async (req, res) => {

    const userIdCognitoSub = getUserIdFromEvent(req); // Asegúrate que esta función esté definida y funcione

    if (!userIdCognitoSub) {

        return res.status(401).json({ success: false, message: 'No autenticado.' });

    }



    console.log('[Create Payment] Received req.body:', JSON.stringify(req.body, null, 2));

    const { plan, isMobile } = req.body; // isMobile es opcional, depende de tu lógica de frontend

    console.log('[Create Payment] Extracted plan object:', JSON.stringify(plan, null, 2));

    console.log('[Create Payment] typeof plan.price:', typeof plan?.price);



    let userEmail;

    let newPurchase; // Definir fuera para usar en catch y finally si es necesario



    try {

        const user = await User.findOne({ where: { cognitoSub: userIdCognitoSub } }); // Asumiendo que tu modelo User tiene cognitoSub como PK o un índice

        if (!user) {

            console.error(`[Create Payment] Usuario con Sub ${userIdCognitoSub} no encontrado en la BD local.`);

            return res.status(404).json({ success: false, message: 'Usuario no encontrado.' });

        }

        userEmail = user.email; // Asumiendo que el modelo User tiene un campo email



        if (!plan || !plan.name || typeof plan.price !== 'number' || plan.price <= 0) {

            console.warn('[Create Payment] Datos del plan inválidos:', plan);

            return res.status(400).json({ success: false, message: 'Datos del plan inválidos o incompletos.' });

        }



        console.log(`[Create Payment] Iniciando para Sub: ${userIdCognitoSub}, Plan: ${plan.name}, Precio: ${plan.price}`);

        newPurchase = await PlanPurchase.create({

            user_id: userIdCognitoSub,

            plan_name: plan.name,

            price: Number(plan.price),

            status: 'pending_payment_preference', // Estado inicial antes de crear la preferencia

            payment_provider: 'mercadopago',

            // purchase_date se establecerá cuando el pago se confirme

        });

        console.log(`[Create Payment] Registro de compra (PlanPurchase) ID: ${newPurchase.id} creado con estado 'pending_payment_preference'.`);



        // URLs base (ajusta según sea necesario o pásalas desde variables de entorno)

        const webProdUrl = process.env.CLIENT_URL_PROD || 'https://www.nextmanager.com.mx';

        const webDevUrl = process.env.CLIENT_URL_DEV || 'http://localhost:3000'; // URL de tu frontend en desarrollo

        const mobileScheme = process.env.MOBILE_APP_SCHEME || 'nextmanagerapp://'; // Esquema para tu app móvil si aplica

        const apiBaseUrl = process.env.API_GATEWAY_URL; // ej: https://sif0rw2qr9.execute-api.us-east-1.amazonaws.com/Prod



        if (!apiBaseUrl) {

            console.error('[Create Payment] API_GATEWAY_URL no está configurada en las variables de entorno.');

            throw new Error("API_GATEWAY_URL no configurada.");

        }



        // Determina la URL base para los callbacks.

        // 'isMobile' debería venir del frontend para decidir esto.

        // Si no, usa una URL web por defecto. Considera el entorno (dev/prod).

        // Para este ejemplo, asumimos que si no es mobile, es la URL de producción web.

        // Podrías querer una lógica más sofisticada para determinar la URL base correcta.

        const effectiveBaseUrl = isMobile ? mobileScheme + 'payment' : webProdUrl;



        // --- CORRECCIÓN DE back_urls ---

        const backUrls = {

            success: `${effectiveBaseUrl}/payment-success?purchaseId=${newPurchase.id}`,

            failure: `${effectiveBaseUrl}/payment-failure?purchaseId=${newPurchase.id}`,

            pending: `${effectiveBaseUrl}/payment-pending?purchaseId=${newPurchase.id}`,

        };

        // ------------------------------



        const notificationUrl = `${apiBaseUrl}/api/payment/confirm`; // Tu endpoint webhook para notificaciones de MP

        console.log(`[Create Payment] Callback URLs: ${JSON.stringify(backUrls)}`);

        console.log(`[Create Payment] Notification URL: ${notificationUrl}`);



        const preferencePayload = {

            items: [{

                id: plan.id || `plan-${newPurchase.id}`, // Un ID para el item

                title: plan.name,

                description: plan.description || `Suscripción al ${plan.name} de ${plan.product || 'NextManager'}`,

                quantity: 1,

                currency_id: 'MXN', // Moneda

                unit_price: Number(plan.price), // Precio unitario

            }],

            payer: {

                email: userEmail || undefined, // Email del pagador (opcional pero recomendado)

                // Puedes añadir más datos del pagador si los tienes y MP los soporta

                // name: user.name,

                // surname: user.lastName,

            },

            back_urls: backUrls,

            auto_return: 'approved', // Redirige automáticamente si el pago es aprobado

            notification_url: notificationUrl, // URL para notificaciones de estado del pago

            metadata: { // Datos adicionales que quieras asociar

                user_id_cognito: userIdCognitoSub,

                internal_purchase_id: newPurchase.id.toString(),

                plan_name: plan.name,

                product_name: plan.product || 'N/A'

            },

            external_reference: newPurchase.id.toString(), // Referencia externa (ID de tu compra)

            // statement_descriptor: "NEXTMANAGER", // Lo que aparecerá en el estado de cuenta (revisar restricciones de MP)

        };



        console.log('[Create Payment] Creando preferencia de Mercado Pago con payload:', JSON.stringify(preferencePayload, null, 2));

       

        // Asume que 'client' es tu cliente de Mercado Pago SDK ya inicializado

        // ej. const client = new MercadoPagoConfig({ accessToken: process.env.MERCADOPAGO_ACCESS_TOKEN });

        const preference = new Preference(client); // client debe ser tu MercadoPagoConfig

        const responseMP = await preference.create({ body: preferencePayload });



        console.log('[Create Payment] Preferencia de Mercado Pago creada. ID de Preferencia:', responseMP?.id);



        if (responseMP && responseMP.id) {

            newPurchase.preference_id = responseMP.id;

            newPurchase.status = 'preference_created'; // Actualiza el estado

            await newPurchase.save();

            console.log(`[Create Payment] PlanPurchase ID ${newPurchase.id} actualizado con preference_id y estado 'preference_created'.`);

        } else {

            // Esto sería un error inesperado si la llamada a MP no falló pero no devolvió ID

            throw new Error('Mercado Pago no devolvió un ID de preferencia válido.');

        }



        return res.status(201).json({

            success: true,

            message: 'Preferencia de pago creada exitosamente.',

            init_point: responseMP.init_point, // URL para redirigir al usuario a pagar

            preference_id: responseMP.id,

            purchase_id: newPurchase.id

        });



    } catch (error) {

        console.error(`[Create Payment] Error creando preferencia para Sub ${userIdCognitoSub}:`, error.message);

        if (error.cause) console.error(`[Create Payment] Causa del error de MP:`, error.cause);



        if (newPurchase && newPurchase.id) {

            try {

                await PlanPurchase.update(

                    {

                        status: 'failed_preference_creation',

                        notes: `Error creando preferencia MP: ${error.message || JSON.stringify(error.cause)}`

                    },

                    { where: { id: newPurchase.id } }

                );

                console.log(`[Create Payment] PlanPurchase ID ${newPurchase.id} actualizado a estado 'failed_preference_creation'.`);

            } catch (saveError) {

                console.error(`[Create Payment] Error al actualizar PlanPurchase ${newPurchase.id} a estado fallido:`, saveError);

            }

        }

       

        // Devuelve un error genérico al cliente, los detalles ya están en los logs

        return res.status(error.status || 500).json({ // Usar error.status si viene del SDK de MP (como el 400)

            success: false,

            message: error.message || 'Error al crear la preferencia de pago.',

            error_code: error.error || (error.cause ? error.cause.error_code || error.cause.status : 'UNKNOWN_ERROR'),

            // details: error.toString() // Evita exponer detalles excesivos al cliente

        });

    }

});



// Añade esto en app.js junto a tus otras rutas API



// Endpoint Protegido: Verificar disponibilidad de subdominio

app.get('/api/portal/check-subdomain', async (req, res) => {

    const userIdCognitoSub = getUserIdFromEvent(req); // Verifica que el usuario esté logueado

    if (!userIdCognitoSub) { return res.status(401).json({ success: false, message: 'No autenticado.' }); }



    const { subdomain } = req.query;



    // Validación básica del subdominio recibido

    if (!subdomain || !/^[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?$/.test(subdomain)) {

        return res.status(400).json({ available: false, message: 'Formato de subdominio inválido.' });

    }



    // Construir el dominio completo a buscar

    const fullDomain = `${subdomain}.nextmanager.com.mx`;

    console.log(`[Check Subdomain] Verificando disponibilidad para: ${fullDomain} (Usuario: ${userIdCognitoSub})`);



    try {

        const existingPortal = await PortalConfig.findOne({

            where: { custom_domain: fullDomain }

        });



        if (existingPortal) {

            console.log(`[Check Subdomain] Dominio ${fullDomain} YA EN USO por User ID: ${existingPortal.user_id}`);

            return res.json({ available: false, message: 'Subdominio no disponible.' });

        } else {

            console.log(`[Check Subdomain] Dominio ${fullDomain} DISPONIBLE.`);

            return res.json({ available: true, message: 'Subdominio disponible.' });

        }

    } catch (error) {

        console.error(`[Check Subdomain] Error verificando ${fullDomain}:`, error);

        // Devolver un error 500, pero indicar que no está disponible por precaución

        return res.status(500).json({ available: false, message: 'Error al verificar disponibilidad.' });

    }

});



// Endpoint Público: Webhook de Mercado Pago

app.post('/api/payment/confirm', async (req, res) => {

    // *** AÑADIR VALIDACIÓN DE WEBHOOK MP AQUÍ ***

    console.log('[Confirm MP] Webhook recibido.');

    // ... (lógica completa igual que antes para procesar notificación y actualizar PlanPurchase) ...

    try {

        const topic = req.body.topic || req.query.topic;

        let paymentId = req.body.data?.id || req.query.id;

        // ... (extraer ID si viene en resource) ...



        if (!topic || !paymentId) { /* ... log y return 200 ... */ return res.sendStatus(200); }

        console.log('[Confirm MP] Topic:', topic, 'Payment ID:', paymentId);



        if (topic === 'payment') {

            const paymentInstance = new Payment(client);

            const payment = await paymentInstance.get({ id: paymentId });

            if (payment && payment.status === 'approved') {

                 const confirmedPaymentId = payment.id.toString();

                 const userIdCognitoSub = payment.metadata?.user_id || payment.external_reference;

                 const planName = payment.metadata?.plan_name;

                 const price = payment.transaction_amount;

                 const purchaseId = payment.metadata?.purchase_id || payment.external_reference;



                 console.log(`[Confirm MP] Pago APROBADO. Sub: ${userIdCognitoSub}, Plan: ${planName}, CompraID (metadata): ${purchaseId}`);



                 if (userIdCognitoSub && planName && price !== undefined && confirmedPaymentId) {

                     let purchaseRecord;

                     if (purchaseId) { purchaseRecord = await PlanPurchase.findByPk(parseInt(purchaseId, 10)); }

                     // ... (lógica para buscar/crear/actualizar PlanPurchase a 'active') ...

                     if (!purchaseRecord) {

                         purchaseRecord = await PlanPurchase.create({ user_id: userIdCognitoSub, /*...*/ status: 'active', payment_id: confirmedPaymentId });

                     } else if (purchaseRecord.status !== 'active') {

                         purchaseRecord.status = 'active'; await purchaseRecord.save();

                     }

                     console.log(`[Confirm MP] Compra ${purchaseRecord.id} marcada/confirmada como activa.`);

                     // ---> Lógica post-pago <---

                 } else { console.warn('[Confirm MP] Faltan datos en metadata/pago.'); }

            } else if (payment) {

                console.log(`[Confirm MP] Pago NO aprobado. Estado: ${payment.status}. Payment ID: ${payment.id}`);

                 // ... (lógica para actualizar estado a failed/rejected/pending si existe) ...

            } else {

                console.warn('[Confirm MP] No se pudo obtener info del pago.');

                return res.sendStatus(500);

            }

        } else { console.warn(`[Confirm MP] Tópico no manejado: ${topic}.`); }

        return res.sendStatus(200); // OK a Mercado Pago

    } catch(error){

        console.error('[Confirm MP] Error GENERAL:', error);

        return res.sendStatus(500); // Pedir a MP que reintente

    }

});



// Endpoint Protegido: Obtener Estado del Usuario

app.get('/api/users/status', async (req, res) => {

    const userIdCognitoSub = getUserIdFromEvent(req);

    if (!userIdCognitoSub) { return res.status(401).json({ success: false, message: 'No autenticado.' }); }

    try {

        const userPlan = await PlanPurchase.findOne({ where: { user_id: userIdCognitoSub, status: 'active' } }); // Buscar solo activo?

        const userRestaurant = await Restaurant.findOne({ where: { user_id: userIdCognitoSub } });

        res.status(200).json({

            hasPlan: !!userPlan,

            hasRestaurant: !!userRestaurant,

            planStatus: userPlan?.status

        });

    } catch (error) {

        console.error(`[User Status] Error para Sub: ${userIdCognitoSub}`, error);

        res.status(500).json({ message: 'Error al obtener el estado del usuario.', details: error.message });

    }

});



// --- Endpoints POS Adaptados y Protegidos ---

// Añadir checkRestaurantOwnership a todos



app.get('/api/pos/products', async (req, res) => {

    const userIdCognitoSub = getUserIdFromEvent(req);

    if (!userIdCognitoSub) { return res.status(401).json({ success: false, message: 'No autenticado.' }); }

    const { restaurantId } = req.query;

    if (!restaurantId) { return res.status(400).json({ success: false, message: 'Falta restaurantId' }); }

    try {

        const restaurant = await checkRestaurantOwnership(userIdCognitoSub, restaurantId);

        if (!restaurant) { return res.status(403).json({ success: false, message: 'Acceso denegado.' }); }

        const sqlConfig = { /* ... usar restaurant.connection_... */ };

        let pool = await sql.connect(sqlConfig);

        const result = await pool.request().query('SELECT [id], [Code], [Name], [StartDate], [EndDate], [HasTransferredTax], [HasTransferredIEPS], [Complement] FROM [products] ORDER BY [id] ASC');

        await pool.close();

        return res.status(200).json({ success: true, data: result.recordset });

    } catch (error) {

         console.error('[GET /api/pos/products] Error:', error);

         return res.status(500).json({ success: false, message: 'Error al consultar products.', error: error.message });

    }

});



app.get('/api/pos/bitacoras', async (req, res) => {

    const userIdCognitoSub = getUserIdFromEvent(req);

    if (!userIdCognitoSub) { return res.status(401).json({ success: false, message: 'No autenticado.' }); }

    const { restaurantId } = req.query;

    if (!restaurantId) { return res.status(400).json({ success: false, message: 'Falta restaurantId' }); }

    try {

        const restaurant = await checkRestaurantOwnership(userIdCognitoSub, restaurantId);

        if (!restaurant) { return res.status(403).json({ success: false, message: 'Acceso denegado.' }); }

        const sqlConfig = { /* ... */ };

        let pool = await sql.connect(sqlConfig);

        const result = await pool.request().query('SELECT [fecha], [usuario], [evento], [valores], [estacion], [idempresa], [seriefolio], [numcheque], [usuariosolicita], [tipoalerta] FROM [bitacorasistema] ORDER BY [fecha] DESC');

        await pool.close();

        return res.status(200).json({ success: true, data: result.recordset });

    } catch (error) {

         console.error('[GET /api/pos/bitacoras] Error:', error);

         return res.status(500).json({ success: false, message: 'Error al consultar bitacorasistema.', error: error.message });

    }

});



app.get('/api/pos/cheqdet', async (req, res) => {

    const userIdCognitoSub = getUserIdFromEvent(req);

    if (!userIdCognitoSub) { return res.status(401).json({ success: false, message: 'No autenticado.' }); }

    const { restaurantId } = req.query;

    if (!restaurantId) { return res.status(400).json({ success: false, message: 'Falta restaurantId' }); }

    try {

        const restaurant = await checkRestaurantOwnership(userIdCognitoSub, restaurantId);

        if (!restaurant) { return res.status(403).json({ success: false, message: 'Acceso denegado.' }); }

        const sqlConfig = { /* ... */ };

        let pool = await sql.connect(sqlConfig);

        const result = await pool.request().query('SELECT [movimiento], [idproducto], [precio], [cantidad], [hora], [procesado] FROM [cheqdet] ORDER BY [hora] DESC');

        await pool.close();

        return res.status(200).json({ success: true, data: result.recordset });

    } catch (error) {

         console.error('[GET /api/pos/cheqdet] Error:', error);

         return res.status(500).json({ success: false, message: 'Error al consultar cheqdet.', error: error.message });

    }

});



app.get('/api/pos/cheques', async (req, res) => {

    const userIdCognitoSub = getUserIdFromEvent(req);

    if (!userIdCognitoSub) { return res.status(401).json({ success: false, message: 'No autenticado.' }); }

    const { restaurantId } = req.query;

    if (!restaurantId) { return res.status(400).json({ success: false, message: 'Falta restaurantId' }); }

    try {

        const restaurant = await checkRestaurantOwnership(userIdCognitoSub, restaurantId);

        if (!restaurant) { return res.status(403).json({ success: false, message: 'Acceso denegado.' }); }

        const sqlConfig = { /* ... */ };

        let pool = await sql.connect(sqlConfig);

        const result = await pool.request().query('SELECT [totalbebidas], [totalalimentos], [totalsindescuento], [efectivo], [tarjeta], [total], [totalarticulos], [estacion], [idturno], [tipodeservicio], [orden], [cambio], [impreso], [pagado], [mesa], [nopersonas], [cierre], [fecha], [numcheque], [folio] FROM [cheques] ORDER BY [fecha] DESC');

        await pool.close();

        return res.status(200).json({ success: true, data: result.recordset });

    } catch (error) {

         console.error('[GET /api/pos/cheques] Error:', error);

         return res.status(500).json({ success: false, message: 'Error al consultar cheques.', error: error.message });

    }

});



app.get('/api/pos/chequespagos', async (req, res) => {

    const userIdCognitoSub = getUserIdFromEvent(req);

    if (!userIdCognitoSub) { return res.status(401).json({ success: false, message: 'No autenticado.' }); }

    const { restaurantId } = req.query;

    if (!restaurantId) { return res.status(400).json({ success: false, message: 'Falta restaurantId' }); }

    try {

        const restaurant = await checkRestaurantOwnership(userIdCognitoSub, restaurantId);

        if (!restaurant) { return res.status(403).json({ success: false, message: 'Acceso denegado.' }); }

        const sqlConfig = { /* ... */ };

        let pool = await sql.connect(sqlConfig);

        const result = await pool.request().query('SELECT [folio], [idformadepago], [importe], [propina], [tipodecambio] FROM [chequespagos] ORDER BY [folio] DESC');

        await pool.close();

        return res.status(200).json({ success: true, data: result.recordset });

    } catch (error) {

         console.error('[GET /api/pos/chequespagos] Error:', error);

         return res.status(500).json({ success: false, message: 'Error al consultar chequespagos.', error: error.message });

    }

});



app.get('/api/pos/declaracioncajero', async (req, res) => {

    const userIdCognitoSub = getUserIdFromEvent(req);

    if (!userIdCognitoSub) { return res.status(401).json({ success: false, message: 'No autenticado.' }); }

    const { restaurantId } = req.query;

    if (!restaurantId) { return res.status(400).json({ success: false, message: 'Falta restaurantId' }); }

    try {

        const restaurant = await checkRestaurantOwnership(userIdCognitoSub, restaurantId);

        if (!restaurant) { return res.status(403).json({ success: false, message: 'Acceso denegado.' }); }

        const sqlConfig = { /* ... */ };

        let pool = await sql.connect(sqlConfig);

        const result = await pool.request().query('SELECT [idturno], [idformadepago], [importedeclarado] FROM [declaracioncajero] ORDER BY [importedeclarado] DESC');

        await pool.close();

        return res.status(200).json({ success: true, data: result.recordset });

    } catch (error) {

         console.error('[GET /api/pos/declaracioncajero] Error:', error);

         return res.status(500).json({ success: false, message: 'Error al consultar declaracioncajero.', error: error.message });

    }

});



app.get('/api/pos/estaciones', async (req, res) => {

    const userIdCognitoSub = getUserIdFromEvent(req);

    if (!userIdCognitoSub) { return res.status(401).json({ success: false, message: 'No autenticado.' }); }

    const { restaurantId } = req.query;

    if (!restaurantId) { return res.status(400).json({ success: false, message: 'Falta restaurantId' }); }

    try {

        const restaurant = await checkRestaurantOwnership(userIdCognitoSub, restaurantId);

        if (!restaurant) { return res.status(403).json({ success: false, message: 'Acceso denegado.' }); }

        const sqlConfig = { /* ... */ };

        let pool = await sql.connect(sqlConfig);

        const result = await pool.request().query('SELECT [idestacion], [descripcion], [serie], [ip], [directoriorespaldo], [mensajespera], [rutatemoral], [PostLastOnline] FROM [estaciones]');

        await pool.close();

        return res.status(200).json({ success: true, data: result.recordset });

    } catch (error) {

         console.error('[GET /api/pos/estaciones] Error:', error);

         return res.status(500).json({ success: false, message: 'Error al consultar estaciones.', error: error.message });

    }

});



// Endpoint Protegido: Crear Restaurantes (¿quizás parte de setup inicial?)

// Si es para añadir más restaurantes DESPUÉS del setup inicial.

app.post('/api/restaurants', async (req, res) => {

    const userIdCognitoSub = getUserIdFromEvent(req);

    if (!userIdCognitoSub) { return res.status(401).json({ message: 'No autenticado.' }); }

    try {

        // Asume que restaurantsData viene en el body, ya no como form-data parseado

        const restaurantsData = req.body.restaurants; // Array de objetos restaurant

        if (!Array.isArray(restaurantsData)) {

            return res.status(400).json({ message: 'Formato inválido para restaurantes.' });

        }

        const createdRestaurants = [];

        for (const restaurantData of restaurantsData) {

             const { name, address, rfc, fiscal_address, csd_password, connection } = restaurantData;

             // Validaciones básicas

             if(!name || !address || !rfc || !fiscal_address || !connection ) {

                 console.warn("Datos incompletos para restaurante:", restaurantData);

                 continue; // Saltar este restaurante

             }

             // Crear restaurante

             const restaurant = await Restaurant.create({

                 user_id: userIdCognitoSub,

                 name, address,

                 connection_host: connection.host,

                 connection_port: connection.port,

                 connection_user: connection.db_user,

                 connection_password: connection.db_password,

                 connection_db_name: connection.db_name,

                 // Faltan VPN creds si las necesitas aquí

             });

             // Crear datos fiscales

             const fiscalData = await FiscalData.create({

                 restaurant_id: restaurant.id,

                 rfc, fiscal_address, csd_password,

                 // CSD URLs serían null aquí, se subirían por separado

             });

             createdRestaurants.push({ restaurant, fiscalData });

        }

        res.status(201).json({ success: true, data: createdRestaurants });

    } catch (error) {

        console.error('Error en /api/restaurants (POST):', error);

        res.status(500).json({ message: 'Error al crear los restaurantes.' });

    }

});







// Endpoint PROTEGIDO para guardar la configuración del portal del cliente



// y crear el subdominio.



app.post('/api/portal/setup', upload.single('portalLogo'), async (req, res) => {



    // upload.single('portalLogo') espera un archivo con el fieldname 'portalLogo'



    const userIdCognitoSub = getUserIdFromEvent(req);



    if (!userIdCognitoSub) { return res.status(401).json({ success: false, message: 'No autenticado.' }); }







    console.log(`[Portal Setup API] Recibido para Sub: ${userIdCognitoSub}`);



    console.log('[Portal Setup API] req.body:', req.body);



    console.log('[Portal Setup API] req.file (portalLogo):', req.file); // Archivo del logo







    let portalConfigData;



    try {



        // El portalConfig viene como string JSON en FormData



        if (req.body.portalConfig && typeof req.body.portalConfig === 'string') {



            portalConfigData = JSON.parse(req.body.portalConfig);



        } else {



            // Si no viene como string (quizás en pruebas directas o si el frontend cambia)



            portalConfigData = req.body.portalConfig || req.body;



        }



        console.log('[Portal Setup API] PortalConfig parseado:', portalConfigData);



    } catch (e) {



        console.error('[Portal Setup API] Error parseando portalConfig:', e);



        return res.status(400).json({ success: false, message: 'Datos de portalConfig malformados.' });



    }







    const { portalName, customDomain, primaryColor, secondaryColor } = portalConfigData;







    // Validaciones básicas



    if (!portalName || !customDomain || !primaryColor || !secondaryColor) {



        return res.status(400).json({ success: false, message: 'Faltan datos para la configuración del portal.' });



    }



    if (!/^[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?$/.test(customDomain)) {



        return res.status(400).json({ success: false, message: 'Formato de subdominio inválido.' });



    }







    const fullCustomDomain = `${customDomain.toLowerCase()}.nextmanager.com.mx`;



    const transaction = await sequelize.transaction();







    try {



        // Verificar si ya existe un portal para este subdominio (que no sea del mismo usuario)



        const existingDomain = await PortalConfig.findOne({



            where: { custom_domain: fullCustomDomain, user_id: { [Op.ne]: userIdCognitoSub } },



            transaction



        });



        if (existingDomain) {



            await transaction.rollback();



            return res.status(400).json({ success: false, message: `El subdominio ${fullCustomDomain} ya está en uso.` });



        }







        let portalLogoS3Url = portalConfigData.existingLogoUrl || null; // Mantener logo existente si no se sube uno nuevo







        // Si se subió un nuevo logo para el portal



        if (req.file) {



            console.log('[Portal Setup API] Procesando portalLogo:', req.file.originalname);



            const s3Key = `portal_logos/${userIdCognitoSub}/logo_${Date.now()}_${req.file.originalname}`;



            portalLogoS3Url = await uploadFileToS3(req.file, s3Key); // Usa tu función auxiliar



            console.log(`[Portal Setup API] Logo del portal subido a S3: ${portalLogoS3Url}`);



        }







        // Crear o actualizar PortalConfig



        const [portal, created] = await PortalConfig.findOrCreate({



            where: { user_id: userIdCognitoSub }, // Asumimos un portal por usuario



            defaults: {



                user_id: userIdCognitoSub,



                portal_name: portalName,



                custom_domain: fullCustomDomain,



                primary_color: primaryColor,



                secondary_color: secondaryColor,



                portal_logo_url: portalLogoS3Url



            },



            transaction



        });







        if (!created) { // Si ya existía, actualizar



            console.log(`[Portal Setup API] Actualizando PortalConfig existente para ${userIdCognitoSub}`);



            portal.portal_name = portalName;



            portal.custom_domain = fullCustomDomain; // Permitir cambio de subdominio? Implica borrar el CNAME anterior?



            portal.primary_color = primaryColor;



            portal.secondary_color = secondaryColor;



            if (portalLogoS3Url) { // Solo actualiza si se subió un nuevo logo o se quiere limpiar



                 portal.portal_logo_url = portalLogoS3Url;



            }



            await portal.save({ transaction });



        }



        console.log(`[Portal Setup API] PortalConfig guardado/actualizado para ${userIdCognitoSub}, ID: ${portal.id}`);







        // Crear el CNAME en Route53 (esta función ya la tienes)



        // La función createSubdomainInRoute53 espera solo el prefijo del subdominio



        await createSubdomainInRoute53(customDomain); // Pasar solo el prefijo

        console.log(`[Portal Setup API] Solicitud CNAME enviada para el prefijo: ${customDomain}`);







        await transaction.commit();



        return res.status(201).json({



            success: true,



            message: 'Configuración del portal guardada y subdominio configurándose.',



            portalConfig: portal // Devuelve la configuración guardada



        });







    } catch (error) {



        await transaction.rollback();



        console.error(`[Portal Setup API] Error para Sub: ${userIdCognitoSub}:`, error);



        return res.status(500).json({



            success: false,



            message: error.message || 'Error al guardar la configuración del portal.',



            details: error.toString()



        });



    }



});



// Endpoint Protegido: Guardar Conexión POS

app.post('/api/pos/register-connection', async (req, res) => {

    const userIdCognitoSub = getUserIdFromEvent(req);

    if (!userIdCognitoSub) { return res.status(401).json({ success: false, message: 'No autenticado.' }); }

    const { restaurantId, host, port, db_user, db_password, db_name } = req.body;

    if (!restaurantId) { return res.status(400).json({ success: false, message: 'Falta restaurantId' }); }

    try {

        const restaurant = await checkRestaurantOwnership(userIdCognitoSub, restaurantId);

        if (!restaurant) { return res.status(403).json({ success: false, message: 'Acceso denegado.' }); }



        restaurant.connection_host = host;

        restaurant.connection_port = port;

        restaurant.connection_user = db_user;

        restaurant.connection_password = db_password; // Considera cifrar

        restaurant.connection_db_name = db_name;

        await restaurant.save();

        return res.json({ success: true, message: 'Conexión POS guardada.' });

    } catch (error) {

        console.error('Error guardando conexión POS:', error);

        return res.status(500).json({ success: false, message: 'Error interno.' });

    }

});



// Endpoint Protegido: Test Conexión Remota

app.post('/api/pos/test-remote-db', async (req, res) => {

    const userIdCognitoSub = getUserIdFromEvent(req);

    if (!userIdCognitoSub) { return res.status(401).json({ success: false, message: 'No autenticado.' }); }

    const { restaurantId } = req.body;

    if (!restaurantId) { return res.status(400).json({ success: false, message: 'Falta restaurantId' }); }

    try {

        const restaurant = await checkRestaurantOwnership(userIdCognitoSub, restaurantId);

        if (!restaurant) { return res.status(403).json({ success: false, message: 'Acceso denegado.' }); }



        const { connection_host, connection_port, connection_user, connection_password, connection_db_name } = restaurant;

        if (!connection_host || !connection_user || !connection_password || !connection_db_name) {

            return res.status(400).json({ success: false, message: 'Datos de conexión incompletos para este restaurante.' });

        }



        const sqlConfig = {

            user: connection_user,

            password: connection_password,

            database: connection_db_name,

            server: connection_host,

            port: parseInt(connection_port || '1433', 10),

            options: { trustServerCertificate: true },

            pool: { max: 1, min: 0, idleTimeoutMillis: 5000 }, // Pool pequeño para test

            requestTimeout: 15000 // Timeout más corto para test

        };

        console.log(`[Test DB] Intentando conectar a ${connection_host} DB ${connection_db_name}`);

        let pool = await sql.connect(sqlConfig);

        let result = await pool.request().query('SELECT 1 as TestResult');

        await pool.close();

        console.log(`[Test DB] Conexión exitosa para Restaurante ID: ${restaurantId}`);

        return res.json({ success: true, message: 'Conexión exitosa a la BD remota.' });



    } catch (error) {

        console.error(`[Test DB] Error para Restaurante ID: ${restaurantId}:`, error);

        return res.status(500).json({ success: false, message: 'No se pudo conectar a la BD remota.', error: error.message });

    }

});



// --- Endpoint de Status Simple (Público) ---

app.get('/api/status', (req, res) => {

    res.json({ message: 'API funcionando v3 - Cognito Auth Ready' });

});



// --- Sincronización Sequelize (Comentado - Usar Migraciones) ---

/*

(async () => {

  try {

    await sequelize.authenticate();

    await sequelize.sync({ alter: true });

    console.log('[DB Sync] Conectado y Sincronizado.');

  } catch (error) {

    console.error('[DB Sync] Error:', error);

  }

})();

*/



// --- Exportar Handler para Lambda ---

module.exports.handler = serverless(app);
