// --- CONFIGURACIÓN SEGURA DE ARCHIVOS ---

const path = require('path');
const fs = require('fs').promises;
const multer = require('multer');
const crypto = require('crypto');
const mime = require('mime-types');

// Crear directorios seguros
const createSecureDirectories = async () => {
    const baseDir = path.join(__dirname, 'secure_uploads');
    const publicDir = path.join(baseDir, 'public'); // Solo logos
    const privateDir = path.join(baseDir, 'private'); // Certificados CSD
    
    await fs.mkdir(baseDir, { recursive: true, mode: 0o750 });
    await fs.mkdir(publicDir, { recursive: true, mode: 0o750 });
    await fs.mkdir(privateDir, { recursive: true, mode: 0o700 }); // Más restrictivo
};

// Configuración de validación por tipo de archivo
const FILE_CONFIGS = {
    logo: {
        allowedTypes: ['image/jpeg', 'image/png', 'image/webp'],
        maxSize: 2 * 1024 * 1024, // 2MB
        isPublic: true,
        directory: 'public'
    },
    csdCertificate: {
        allowedTypes: ['application/x-x509-ca-cert', 'application/pkix-cert', 'text/plain'],
        maxSize: 10 * 1024, // 10KB
        isPublic: false,
        directory: 'private'
    },
    csdKey: {
        allowedTypes: ['application/pkcs8', 'application/x-pem-file', 'text/plain', 'application/octet-stream'],
        maxSize: 10 * 1024, // 10KB
        isPublic: false,
        directory: 'private'
    }
};

// Validador de archivos
const validateFile = (fieldName, file) => {
    const config = FILE_CONFIGS[fieldName];
    if (!config) {
        throw new Error(`Tipo de archivo no permitido: ${fieldName}`);
    }
    
    // Validar tipo MIME
    if (!config.allowedTypes.includes(file.mimetype)) {
        throw new Error(`Tipo de archivo inválido para ${fieldName}. Permitidos: ${config.allowedTypes.join(', ')}`);
    }
    
    // Validar tamaño
    if (file.size > config.maxSize) {
        throw new Error(`Archivo ${fieldName} excede el tamaño máximo de ${config.maxSize} bytes`);
    }
    
    // Validar extensión (doble verificación)
    const allowedExtensions = config.allowedTypes.map(type => mime.extension(type)).filter(Boolean);
    const fileExtension = path.extname(file.originalname).toLowerCase().slice(1);

    // ---> SOLUCIÓN: Añadir manualmente la extensión .key si el campo es csdKey <---
    if (fieldName === 'csdKey') {
        if (!allowedExtensions.includes('key')) {
            allowedExtensions.push('key');
        }
    }
    
    if (!allowedExtensions.includes(fileExtension)) {
        throw new Error(`Extensión de archivo inválida para ${fieldName}`);
    }
    
};

// Generador de nombres seguros
const generateSecureFilename = (originalname, fieldName) => {
    const timestamp = Date.now();
    const randomBytes = crypto.randomBytes(16).toString('hex');
    const extension = path.extname(originalname);
    return `${fieldName}_${timestamp}_${randomBytes}${extension}`;
};

// Storage personalizado y seguro
const secureStorage = multer.diskStorage({
    destination: function (req, file, cb) {
        const config = FILE_CONFIGS[file.fieldname];
        if (!config) {
            return cb(new Error(`Campo no permitido: ${file.fieldname}`));
        }
        
        const uploadPath = path.join(__dirname, 'secure_uploads', config.directory);
        cb(null, uploadPath);
    },
    filename: function (req, file, cb) {
        try {
            validateFile(file.fieldname, file);
            const secureFilename = generateSecureFilename(file.originalname, file.fieldname);
            cb(null, secureFilename);
        } catch (error) {
            cb(error);
        }
    }
});

// Configuración de multer con límites estrictos
const secureUpload = multer({
    storage: secureStorage,
    limits: {
        fileSize: 2 * 1024 * 1024, // 2MB máximo por archivo
        files: 3, // Máximo 3 archivos
        fields: 10, // Máximo 10 campos de texto
        fieldNameSize: 50, // Máximo 50 caracteres para nombres de campo
        fieldSize: 1024 * 1024 // 1MB para campos de texto
    },
    fileFilter: (req, file, cb) => {
        console.log(`[DEBUG] Archivo: ${file.fieldname}, MIME Type Recibido: ${file.mimetype}`); 
        try {
            validateFile(file.fieldname, file);
            cb(null, true);
        } catch (error) {
            cb(error, false);
        }
    }
});

// Middleware para servir archivos públicos de forma segura
const servePublicFile = async (req, res, next) => {
    try {
        const filename = req.params.filename;
        
        // Validar que el nombre de archivo sea seguro
        if (!/^[a-zA-Z0-9_\-\.]+$/.test(filename) || filename.includes('..')) {
            return res.status(400).json({ success: false, message: 'Nombre de archivo inválido' });
        }
        
        const filePath = path.join(__dirname, 'secure_uploads', 'public', filename);
        
        // Verificar que el archivo existe y está en el directorio correcto
        const realPath = await fs.realpath(filePath);
        const allowedDir = await fs.realpath(path.join(__dirname, 'secure_uploads', 'public'));
        
        if (!realPath.startsWith(allowedDir)) {
            return res.status(403).json({ success: false, message: 'Acceso denegado' });
        }
        
        // Servir el archivo con headers de seguridad
        res.setHeader('X-Content-Type-Options', 'nosniff');
        res.setHeader('Cache-Control', 'public, max-age=31536000'); // 1 año de cache para logos
        res.sendFile(realPath);
        
    } catch (error) {
        res.status(404).json({ success: false, message: 'Archivo no encontrado' });
    }
};

// Middleware para servir archivos privados (solo al dueño del restaurante)
const servePrivateFile = async (req, res) => {
    try {
        const { restaurantId, filename } = req.params;
        const userId = req.user.id;
        
        // Verificar que el usuario es dueño del restaurante
        const restaurant = await Restaurant.findOne({ where: { id: restaurantId, userId } });
        if (!restaurant) {
            return res.status(404).json({ success: false, message: 'Restaurante no encontrado' });
        }
        
        // Validar nombre de archivo
        if (!/^[a-zA-Z0-9_\-\.]+$/.test(filename) || filename.includes('..')) {
            return res.status(400).json({ success: false, message: 'Nombre de archivo inválido' });
        }
        
        const filePath = path.join(__dirname, 'secure_uploads', 'private', filename);
        const realPath = await fs.realpath(filePath);
        const allowedDir = await fs.realpath(path.join(__dirname, 'secure_uploads', 'private'));
        
        if (!realPath.startsWith(allowedDir)) {
            return res.status(403).json({ success: false, message: 'Acceso denegado' });
        }
        
        // Headers de seguridad para archivos privados
        res.setHeader('X-Content-Type-Options', 'nosniff');
        res.setHeader('Cache-Control', 'private, no-cache');
        res.setHeader('Content-Disposition', 'attachment'); // Forzar descarga
        res.sendFile(realPath);
        
    } catch (error) {
        console.error('Error sirviendo archivo privado:', error);
        res.status(404).json({ success: false, message: 'Archivo no encontrado' });
    }
};

// Función para limpiar archivos huérfanos
const cleanupOrphanFiles = async () => {
    try {
        const publicDir = path.join(__dirname, 'secure_uploads', 'public');
        const privateDir = path.join(__dirname, 'secure_uploads', 'private');
        
        const publicFiles = await fs.readdir(publicDir);
        const privateFiles = await fs.readdir(privateDir);
        
        // Obtener todos los archivos referenciados en la BD
        const restaurants = await Restaurant.findAll({ attributes: ['logoUrl'] });
        const fiscalData = await FiscalData.findAll({ attributes: ['csdCertificateUrl', 'csdKeyUrl'] });
        
        const referencedFiles = new Set();
        
        // Extraer nombres de archivos de las URLs
        restaurants.forEach(r => {
            if (r.logoUrl) {
                const filename = path.basename(r.logoUrl);
                referencedFiles.add(filename);
            }
        });
        
        fiscalData.forEach(f => {
            if (f.csdCertificateUrl) {
                referencedFiles.add(path.basename(f.csdCertificateUrl));
            }
            if (f.csdKeyUrl) {
                referencedFiles.add(path.basename(f.csdKeyUrl));
            }
        });
        
        // Eliminar archivos huérfanos públicos
        for (const file of publicFiles) {
            if (!referencedFiles.has(file)) {
                await fs.unlink(path.join(publicDir, file));
                console.log(`Archivo huérfano eliminado: ${file}`);
            }
        }
        
        // Eliminar archivos huérfanos privados
        for (const file of privateFiles) {
            if (!referencedFiles.has(file)) {
                await fs.unlink(path.join(privateDir, file));
                console.log(`Archivo privado huérfano eliminado: ${file}`);
            }
        }
        
    } catch (error) {
        console.error('Error en limpieza de archivos:', error);
    }
};

// Función para eliminar archivos de un restaurante
const deleteRestaurantFiles = async (restaurantId) => {
    try {
        const restaurant = await Restaurant.findByPk(restaurantId);
        const fiscalData = await FiscalData.findOne({ where: { restaurantId } });
        
        const filesToDelete = [];
        
        if (restaurant?.logoUrl) {
            filesToDelete.push({
                url: restaurant.logoUrl,
                directory: 'public'
            });
        }
        
        if (fiscalData?.csdCertificateUrl) {
            filesToDelete.push({
                url: fiscalData.csdCertificateUrl,
                directory: 'private'
            });
        }
        
        if (fiscalData?.csdKeyUrl) {
            filesToDelete.push({
                url: fiscalData.csdKeyUrl,
                directory: 'private'
            });
        }
        
        for (const file of filesToDelete) {
            const filename = path.basename(file.url);
            const filePath = path.join(__dirname, 'secure_uploads', file.directory, filename);
            
            try {
                await fs.unlink(filePath);
                console.log(`Archivo eliminado: ${filename}`);
            } catch (error) {
                console.error(`Error eliminando archivo ${filename}:`, error.message);
            }
        }
        
    } catch (error) {
        console.error('Error eliminando archivos del restaurante:', error);
    }
};

module.exports = {
    secureUpload,
    servePublicFile,
    servePrivateFile,
    createSecureDirectories,
    cleanupOrphanFiles,
    deleteRestaurantFiles,
    generateSecureFilename
};