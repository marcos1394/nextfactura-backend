const express = require('express');
const cors = require('cors');
const { Sequelize, DataTypes, Op } = require('sequelize');

// ------------------------------------------------------------------
// --- CONFIGURACIÓN E INICIALIZACIÓN ---
// ------------------------------------------------------------------

const app = express();
app.use(cors());
app.use(express.json());

// Conexión a la base de datos
const sequelize = new Sequelize(process.env.DATABASE_URL, {
    dialect: 'postgres',
    logging: false, // Evita imprimir cada consulta SQL en la consola
    dialectOptions: {
        ssl: process.env.NODE_ENV === 'production' ? { require: true, rejectUnauthorized: false } : false
    }
});

// ------------------------------------------------------------------
// --- MODELOS DE DATOS (SEQUELIZE) ---
// ------------------------------------------------------------------

const HelpCategory = sequelize.define('HelpCategory', {
    id: { type: DataTypes.INTEGER, primaryKey: true, autoIncrement: true },
    name: { type: DataTypes.STRING, allowNull: false },
    icon: { type: DataTypes.STRING },
}, { 
    tableName: 'help_categories',
    timestamps: true // Automáticamente añade createdAt y updatedAt
});

const HelpArticle = sequelize.define('HelpArticle', {
    id: { type: DataTypes.INTEGER, primaryKey: true, autoIncrement: true },
    categoryId: { type: DataTypes.INTEGER, allowNull: false },
    title: { type: DataTypes.STRING, allowNull: false },
    slug: { type: DataTypes.STRING, allowNull: false, unique: true },
    content: { type: DataTypes.TEXT },
    isPopular: { type: DataTypes.BOOLEAN, defaultValue: false }
}, { 
    tableName: 'help_articles',
    timestamps: true 
});

// Definimos las relaciones entre las tablas
HelpCategory.hasMany(HelpArticle, { foreignKey: 'categoryId' });
HelpArticle.belongsTo(HelpCategory, { foreignKey: 'categoryId' });

// ------------------------------------------------------------------
// --- ENDPOINTS DE LA API ---
// ------------------------------------------------------------------

// Endpoint de salud para Docker y monitoreo
app.get('/health', (req, res) => {
    res.status(200).json({ status: 'ok' });
});

// Endpoint principal que carga todo el contenido para la pantalla de inicio del Centro de Ayuda
app.get('/help-center/content', async (req, res) => {
    console.log('[Content-Service] Petición recibida para /help-center/content');
    try {
        // Hacemos las consultas en paralelo para mayor eficiencia
        const [categories, popularArticles] = await Promise.all([
            HelpCategory.findAll({ order: [['id', 'ASC']] }),
            HelpArticle.findAll({ 
                where: { isPopular: true }, 
                limit: 5,
                order: [['updatedAt', 'DESC']]
            })
        ]);
        
        // Las "acciones rápidas" pueden ser los 3 artículos más populares
        const quickActions = popularArticles.slice(0, 3).map(article => ({
            title: article.title,
            icon: 'zap' // Icono genérico para acciones rápidas
        }));

        res.status(200).json({
            success: true,
            data: {
                quickActions,
                categories,
                popularArticles,
            }
        });
    } catch (error) {
        console.error("[Content-Service /content] Error:", error);
        res.status(500).json({ success: false, message: 'Error al obtener el contenido de ayuda.' });
    }
});

// Endpoint para la barra de búsqueda del Centro de Ayuda
app.get('/help-center/search', async (req, res) => {
    const { q } = req.query;
    console.log(`[Content-Service] Petición de búsqueda recibida para: "${q}"`);
    
    if (!q || q.trim() === '') {
        return res.status(400).json({ success: false, message: 'Se requiere un término de búsqueda.' });
    }

    try {
        // Usamos Op.iLike para una búsqueda insensible a mayúsculas/minúsculas en PostgreSQL
        const results = await HelpArticle.findAll({
            where: {
                [Op.or]: [
                    { title: { [Op.iLike]: `%${q}%` } },
                    { content: { [Op.iLike]: `%${q}%` } }
                ]
            },
            limit: 10 // Limitamos a 10 resultados para no sobrecargar
        });

        console.log(`[Content-Service] Búsqueda para "${q}" encontró ${results.length} resultados.`);
        res.status(200).json({ success: true, results });

    } catch (error) {
        console.error("[Content-Service /search] Error:", error);
        res.status(500).json({ success: false, message: 'Error al realizar la búsqueda.' });
    }
});

// Endpoint para CREAR un nuevo artículo de ayuda
app.post('/help-center/articles', async (req, res) => {
    const { categoryId, title, slug, content, isPopular } = req.body;
    console.log(`[Content-Service] Petición recibida para CREAR artículo`);

    if (!categoryId || !title || !slug || !content) {
        return res.status(400).json({ success: false, message: 'Faltan campos requeridos: categoryId, title, slug, content.' });
    }

    try {
        const newArticle = await HelpArticle.create({
            categoryId,
            title,
            slug,
            content,
            isPopular: isPopular || false
        });
        console.log(`[Content-Service] Nuevo artículo creado: ${newArticle.id}`);
        res.status(201).json({ success: true, article: newArticle });
    } catch (error) {
        console.error("[Content-Service /articles POST] Error:", error);
        if (error.name === 'SequelizeUniqueConstraintError') {
            return res.status(409).json({ success: false, message: 'El "slug" (URL corta) ya existe.' });
        }
        res.status(500).json({ success: false, message: 'Error al crear el artículo.' });
    }
});

// ------------------------------------------------------------------
// --- ARRANQUE DEL SERVIDOR ---
// ------------------------------------------------------------------
const PORT = process.env.CONTENT_SERVICE_PORT || 4008;

const startServer = async () => {
    try {
        await sequelize.authenticate();
        console.log(`[Content-Service] Conexión con la base de datos establecida exitosamente.`);
        
        app.listen(PORT, () => {
            console.log(`🚀 Content-Service escuchando en el puerto ${PORT}`);
        });
    } catch (error) {
        console.error('Error catastrófico al iniciar Content-Service:', { 
            error: error.message, 
            stack: error.stack 
        });
        process.exit(1);
    }
};

startServer();