// --- ACTUALIZACIÓN DEL SERVER.JS CON MANEJO SEGURO DE ARCHIVOS Y SUBDOMINIOS ---

// Importar el módulo de archivos seguros
const { 
    secureUpload, 
    servePublicFile, 
    servePrivateFile, 
    createSecureDirectories,
    deleteRestaurantFiles 
} = require('./secure-file-handler');
const express = require('express');


// Importar el módulo de cPanel para subdominios
const { createCpanelSubdomain } = require('./cpanelApi');
const app = express();
app.use(cors());
app.use(bodyParser.json());

// Inicializar directorios seguros al arrancar
createSecureDirectories().catch(console.error);

// ELIMINAR estas líneas inseguras:
// app.use('/uploads', express.static(uploadsDir));
// const upload = multer({ storage: storage });

// REEMPLAZAR con rutas seguras:

// Servir archivos públicos (solo logos) de forma segura
app.get('/public/:filename', servePublicFile);

// Servir archivos privados (certificados CSD) solo al dueño
app.get('/restaurants/:restaurantId/private/:filename', authenticateToken, servePrivateFile);

// Función auxiliar para construir URLs seguras
const buildSecureFileUrl = (filename, isPublic = true, restaurantId = null) => {
    if (!filename) return null;
    
    const baseUrl = process.env.BASE_URL || 'http://localhost:4002';
    
    if (isPublic) {
        return `${baseUrl}/public/${filename}`;
    } else {
        return `${baseUrl}/restaurants/${restaurantId}/private/${filename}`;
    }
};

// Función auxiliar para generar nombre de subdominio válido
const generateSubdomainName = (restaurantName, restaurantId) => {
    // Normalizar el nombre del restaurante
    let subdomain = restaurantName
        .toLowerCase()
        .normalize('NFD')
        .replace(/[\u0300-\u036f]/g, '') // Remover acentos
        .replace(/[^a-z0-9]/g, '-') // Reemplazar caracteres especiales con guiones
        .replace(/-+/g, '-') // Reemplazar múltiples guiones consecutivos con uno solo
        .replace(/^-|-$/g, '') // Remover guiones al inicio y final
        .substring(0, 20); // Limitar longitud
    
    // Si queda muy corto o vacío, usar el ID del restaurante
    if (subdomain.length < 3) {
        subdomain = `restaurant-${restaurantId}`;
    }
    
    // Asegurar que no empiece con número (algunos servidores no lo permiten)
    if (/^\d/.test(subdomain)) {
        subdomain = `r-${subdomain}`;
    }
    
    return subdomain;
};

// [POST] Crear un nuevo restaurante
app.post('/',
    authenticateToken,
    secureUpload.fields([
        { name: 'logo', maxCount: 1 },
        { name: 'csdCertificate', maxCount: 1 },
        { name: 'csdKey', maxCount: 1 }
    ]),
    async (req, res) => {
        const transaction = await sequelize.transaction();
        try {
            // 1. Validación de Plan (sin cambios)
            // ... (tu lógica de validación de plan)

            // 2. Procesar datos del body
            const { restaurantData, fiscalData } = req.body;
            const userId = req.user.id;

            if (!restaurantData || !fiscalData) {
                return res.status(400).json({ success: false, message: 'Faltan los objetos restaurantData o fiscalData.' });
            }
            
            const parsedRestaurantData = JSON.parse(restaurantData);
            const parsedFiscalData = JSON.parse(fiscalData);
            
            if (!parsedRestaurantData.name || parsedRestaurantData.name.trim().length === 0) {
                return res.status(400).json({ success: false, message: 'El nombre del restaurante es requerido.' });
            }

            // 3. Crear restaurante en la BD para obtener ID
            const newRestaurant = await Restaurant.create({ 
                ...parsedRestaurantData, 
                userId
            }, { transaction });
            const restaurantId = newRestaurant.id;

            // 4. Crear subdominio (con manejo de errores)
            let subdomain = null;
            let subdomainUrl = null;
            try {
                subdomain = generateSubdomainName(parsedRestaurantData.name, restaurantId);
                const subdomainCreated = await createCpanelSubdomain(subdomain);
                if (subdomainCreated) {
                    const rootDomain = process.env.ROOT_DOMAIN || 'nextfactura.com.mx';
                    subdomainUrl = `https://${subdomain}.${rootDomain}`;
                    await newRestaurant.update({ subdomain, subdomainUrl }, { transaction });
                }
            } catch (subdomainError) {
                console.error('[Restaurant-Service] Error al crear subdominio:', subdomainError);
                // La operación continúa aunque el subdominio falle
            }
            
            // 5. Construir URLs seguras y actualizar registros
            const logoFile = req.files?.logo?.[0];
            const csdCertificateFile = req.files?.csdCertificate?.[0];
            const csdKeyFile = req.files?.csdKey?.[0];

            const logoUrl = logoFile ? buildSecureFileUrl(logoFile.filename, true) : null;
            const csdCertificateUrl = csdCertificateFile ? buildSecureFileUrl(csdCertificateFile.filename, false, restaurantId) : null;
            const csdKeyUrl = csdKeyFile ? buildSecureFileUrl(csdKeyFile.filename, false, restaurantId) : null;
            
            if (logoUrl) {
                await newRestaurant.update({ logoUrl }, { transaction });
            }

            const newFiscalData = await FiscalData.create({ 
                ...parsedFiscalData, 
                restaurantId,
                csdCertificateUrl,
                csdKeyUrl
            }, { transaction });
            
            await transaction.commit();
            
            // 6. Enviar respuesta segura
            const safeRestaurant = newRestaurant.toJSON();
            const safeFiscalData = newFiscalData.toJSON();
            delete safeFiscalData.csdPassword;
            
            res.status(201).json({ 
                success: true, 
                restaurant: safeRestaurant, 
                fiscalData: safeFiscalData,
                subdomain: { name: subdomain, url: subdomainUrl, created: !!subdomainUrl }
            });

        } catch (error) {
            await transaction.rollback();
            // Limpiar archivos subidos en caso de error
            if (req.files) {
                for (const field in req.files) {
                    req.files[field].forEach(file => {
                        fs.unlink(file.path).catch(console.error);
                    });
                }
            }
            console.error('[Restaurant-Service /] Error:', error);
            res.status(500).json({ success: false, message: error.message || 'Error al crear el restaurante.' });
        }
    }
);

// [PUT] Actualizar un restaurante existente
app.put('/:id', 
    authenticateToken,
    secureUpload.fields([
        { name: 'logo', maxCount: 1 },
        { name: 'csdCertificate', maxCount: 1 },
        { name: 'csdKey', maxCount: 1 }
    ]),
    async (req, res) => {
        
    const { id } = req.params;
    const userId = req.user.id;

    const transaction = await sequelize.transaction();
    try {
        const restaurant = await Restaurant.findOne({ 
            where: { id, userId }, 
            transaction 
        });
        
        if (!restaurant) {
            await transaction.rollback();
            return res.status(404).json({ 
                success: false, 
                message: 'Restaurante no encontrado o no autorizado.' 
            });
        }

        // Procesar datos de texto
        let restaurantData = req.body.restaurantData;
        let fiscalData = req.body.fiscalData;
        
        if (typeof restaurantData === 'string') {
            restaurantData = JSON.parse(restaurantData);
        }
        if (typeof fiscalData === 'string') {
            fiscalData = JSON.parse(fiscalData);
        }

        // Manejar archivos nuevos
        const updates = { ...restaurantData };
        
        if (req.files?.logo) {
            // Eliminar logo anterior si existe
            if (restaurant.logoUrl) {
                const oldFilename = path.basename(restaurant.logoUrl);
                const oldPath = path.join(__dirname, 'secure_uploads', 'public', oldFilename);
                fs.unlink(oldPath).catch(console.error);
            }
            
            updates.logoUrl = buildSecureFileUrl(req.files.logo[0].filename, true);
        }

        // --- MANEJO DE ACTUALIZACIÓN DE SUBDOMINIO ---
        // Si se cambió el nombre del restaurante y no tiene subdominio, crear uno nuevo
        if (restaurantData.name && 
            restaurantData.name !== restaurant.name && 
            !restaurant.subdomain) {
            
            try {
                const newSubdomain = generateSubdomainName(restaurantData.name, id);
                const subdomainCreated = await createCpanelSubdomain(newSubdomain);
                
                if (subdomainCreated) {
                    const rootDomain = process.env.ROOT_DOMAIN || 'nextfactura.com.mx';
                    updates.subdomain = newSubdomain;
                    updates.subdomainUrl = `https://${newSubdomain}.${rootDomain}`;
                    
                    console.log(`[Restaurant-Service] Subdominio creado para restaurante existente: ${updates.subdomainUrl}`);
                }
                
            } catch (subdomainError) {
                console.error('[Restaurant-Service] Error al crear subdominio durante actualización:', subdomainError);
                // Continuar sin subdominio en caso de error
            }
        }

        await restaurant.update(updates, { transaction });
        
        // Actualizar datos fiscales
        if (fiscalData) {
            const fiscal = await FiscalData.findOne({ 
                where: { restaurantId: id }, 
                transaction 
            });
            
            const fiscalUpdates = { ...fiscalData };
            
            if (req.files?.csdCertificate) {
                // Eliminar certificado anterior
                if (fiscal?.csdCertificateUrl) {
                    const oldFilename = path.basename(fiscal.csdCertificateUrl);
                    const oldPath = path.join(__dirname, 'secure_uploads', 'private', oldFilename);
                    fs.unlink(oldPath).catch(console.error);
                }
                
                fiscalUpdates.csdCertificateUrl = buildSecureFileUrl(
                    req.files.csdCertificate[0].filename, false, id
                );
            }
            
            if (req.files?.csdKey) {
                // Eliminar llave anterior
                if (fiscal?.csdKeyUrl) {
                    const oldFilename = path.basename(fiscal.csdKeyUrl);
                    const oldPath = path.join(__dirname, 'secure_uploads', 'private', oldFilename);
                    fs.unlink(oldPath).catch(console.error);
                }
                
                fiscalUpdates.csdKeyUrl = buildSecureFileUrl(
                    req.files.csdKey[0].filename, false, id
                );
            }
            
            if (fiscal) {
                await fiscal.update(fiscalUpdates, { transaction });
            } else {
                await FiscalData.create({ 
                    ...fiscalUpdates, 
                    restaurantId: id 
                }, { transaction });
            }
        }
        
        await transaction.commit();
        
        // Obtener datos actualizados sin información sensible
        const updatedRestaurant = await Restaurant.findByPk(id, { 
            include: [{
                model: FiscalData,
                attributes: { exclude: ['csdPassword'] }
            }]
        });
        
        res.status(200).json({ 
            success: true, 
            restaurant: updatedRestaurant 
        });
        
    } catch (error) {
        await transaction.rollback();
        
        // Limpiar archivos subidos en caso de error
        if (req.files) {
            Object.values(req.files).flat().forEach(file => {
                fs.unlink(file.path).catch(console.error);
            });
        }
        
        console.error(`[Restaurant-Service PUT /${id}] Error:`, error);
        res.status(500).json({ 
            success: false, 
            message: error.message || 'Error al actualizar el restaurante.' 
        });
    }
});

// --- ENDPOINT ACTUALIZADO PARA ELIMINAR RESTAURANTE ---
app.delete('/:id', authenticateToken, async (req, res) => {
    const { id } = req.params;
    const userId = req.user.id;

    try {
        const restaurant = await Restaurant.findOne({ where: { id, userId } });
        if (!restaurant) {
            return res.status(404).json({ 
                success: false, 
                message: 'Restaurante no encontrado o no autorizado.' 
            });
        }
        
        // Eliminar archivos antes del borrado lógico
        await deleteRestaurantFiles(id);
        
        // NOTA: Aquí podrías agregar lógica para eliminar el subdominio de cPanel
        // si decides implementar esa funcionalidad
        if (restaurant.subdomain) {
            console.log(`[Restaurant-Service] NOTA: El subdominio ${restaurant.subdomain} del restaurante ${id} debe ser eliminado manualmente de cPanel`);
            // Implementar deleteSubdomain si es necesario
        }
        
        // Sequelize `destroy` con `paranoid: true` hará un borrado lógico
        await restaurant.destroy();
        
        res.status(200).json({ 
            success: true, 
            message: 'Restaurante desactivado exitosamente.' 
        });
        
    } catch (error) {
        console.error(`[Restaurant-Service DELETE /${id}] Error:`, error);
        res.status(500).json({ 
            success: false, 
            message: 'Error al desactivar el restaurante.' 
        });
    }
});

// --- ENDPOINT PARA OBTENER RESTAURANTES (ACTUALIZADO) ---
app.get('/', authenticateToken, async (req, res) => {
    const userId = req.user.id;
    try {
        const restaurants = await Restaurant.findAll({ 
            where: { userId },
            include: [{ 
                model: FiscalData, 
                attributes: { exclude: ['csdPassword'] } // Excluir campos sensibles
            }]
        });
        
        res.status(200).json({ success: true, restaurants });
    } catch (error) {
        console.error('[Restaurant-Service GET /] Error:', error);
        res.status(500).json({ 
            success: false, 
            message: 'Error al obtener los restaurantes.' 
        });
    }
});

// --- ENDPOINT PARA OBTENER UN RESTAURANTE (ACTUALIZADO) ---
app.get('/:id', authenticateToken, async (req, res) => {
    const { id } = req.params;
    const userId = req.user.id;
    
    try {
        const restaurant = await Restaurant.findOne({
            where: { id, userId },
            include: [{
                model: FiscalData,
                attributes: { exclude: ['csdPassword'] } // Excluir campos sensibles
            }]
        });
        
        if (!restaurant) {
            return res.status(404).json({ 
                success: false, 
                message: 'Restaurante no encontrado o no autorizado.' 
            });
        }
        
        res.status(200).json({ success: true, restaurant });
    } catch (error) {
        console.error(`[Restaurant-Service GET /${id}] Error:`, error);
        res.status(500).json({ 
            success: false, 
            message: 'Error al obtener el restaurante.' 
        });
    }
});

// --- ENDPOINT ADICIONAL PARA VERIFICAR DISPONIBILIDAD DE SUBDOMINIO ---
app.get('/subdomain/check/:name', authenticateToken, async (req, res) => {
    const { name } = req.params;
    
    try {
        // Normalizar el nombre propuesto
        const normalizedName = generateSubdomainName(name, 'temp');
        
        // Verificar si ya existe en la base de datos
        const existingRestaurant = await Restaurant.findOne({
            where: { subdomain: normalizedName }
        });
        
        const isAvailable = !existingRestaurant;
        
        res.status(200).json({
            success: true,
            subdomain: normalizedName,
            available: isAvailable,
            url: isAvailable ? `https://${normalizedName}.${process.env.ROOT_DOMAIN || 'nextfactura.com.mx'}` : null
        });
        
    } catch (error) {
        console.error('[Restaurant-Service GET /subdomain/check] Error:', error);
        res.status(500).json({
            success: false,
            message: 'Error al verificar disponibilidad del subdominio.'
        });
    }
});