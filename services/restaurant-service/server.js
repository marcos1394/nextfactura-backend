// --- ACTUALIZACIÓN DEL SERVER.JS CON MANEJO SEGURO DE ARCHIVOS ---

// Importar el módulo de archivos seguros
const { 
    secureUpload, 
    servePublicFile, 
    servePrivateFile, 
    createSecureDirectories,
    deleteRestaurantFiles 
} = require('./secure-file-handler');

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

// --- ENDPOINT ACTUALIZADO PARA CREAR RESTAURANTE ---
app.post('/',
    authenticateToken,
    secureUpload.fields([
        { name: 'logo', maxCount: 1 },
        { name: 'csdCertificate', maxCount: 1 },
        { name: 'csdKey', maxCount: 1 }
    ]),
    async (req, res) => {
        
    // --- 1. VALIDACIÓN DE PLAN (sin cambios) ---
    try {
        const paymentServiceUrl = process.env.PAYMENT_SERVICE_URL;
        if (!paymentServiceUrl) throw new Error("La URL del servicio de pagos no está configurada.");

        const planCheckResponse = await fetch(`${paymentServiceUrl}/subscription-check`, {
            headers: { 'Authorization': req.headers.authorization }
        });
        const planCheckData = await planCheckResponse.json();
        
        if (!planCheckResponse.ok || !planCheckData.canCreate) {
            return res.status(403).json({ 
                success: false, 
                message: planCheckData.reason || "No tienes permiso para crear un restaurante." 
            });
        }
    } catch (error) {
        console.error('[Restaurant-Service] Error al validar plan:', error);
        return res.status(500).json({ 
            success: false, 
            message: 'No se pudo verificar tu plan de suscripción.' 
        });
    }

    // --- 2. PROCESAR DATOS Y ARCHIVOS DE FORMA SEGURA ---
    try {
        const { restaurantData, fiscalData } = req.body;
        const userId = req.user.id;

        if (!restaurantData || !fiscalData) {
            return res.status(400).json({ 
                success: false, 
                message: 'Faltan los objetos restaurantData o fiscalData.' 
            });
        }
        
        const parsedRestaurantData = JSON.parse(restaurantData);
        const parsedFiscalData = JSON.parse(fiscalData);
        
        // Crear el restaurante primero para obtener el ID
        const transaction = await sequelize.transaction();
        
        try {
            // Crear restaurante sin URLs primero
            const newRestaurant = await Restaurant.create({ 
                ...parsedRestaurantData, 
                userId
            }, { transaction });

            const restaurantId = newRestaurant.id;
            
            // Construir URLs seguras con el ID del restaurante
            const logoUrl = req.files?.logo ? 
                buildSecureFileUrl(req.files.logo[0].filename, true) : null;
                
            const csdCertificateUrl = req.files?.csdCertificate ? 
                buildSecureFileUrl(req.files.csdCertificate[0].filename, false, restaurantId) : null;
                
            const csdKeyUrl = req.files?.csdKey ? 
                buildSecureFileUrl(req.files.csdKey[0].filename, false, restaurantId) : null;

            // Actualizar con las URLs
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
            
            // Respuesta sin datos sensibles
            const safeRestaurant = { ...newRestaurant.toJSON() };
            const safeFiscalData = { ...newFiscalData.toJSON() };
            
            // Eliminar campos sensibles de la respuesta
            delete safeFiscalData.csdPassword;
            
            res.status(201).json({ 
                success: true, 
                restaurant: safeRestaurant, 
                fiscalData: safeFiscalData 
            });

        } catch (error) {
            await transaction.rollback();
            
            // Limpiar archivos subidos en caso de error
            if (req.files) {
                Object.values(req.files).flat().forEach(file => {
                    fs.unlink(file.path).catch(console.error);
                });
            }
            
            throw error;
        }
        
    } catch (error) {
        console.error('[Restaurant-Service /] Error:', error);
        res.status(500).json({ 
            success: false, 
            message: error.message || 'Error al crear el restaurante.' 
        });
    }
});

// --- ENDPOINT ACTUALIZADO PARA ACTUALIZAR RESTAURANTE ---
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