// cpanelApi.js - Módulo para manejo de subdominios en cPanel

const axios = require('axios');

/**
 * Crea un subdominio en HostGator usando la API de cPanel.
 * @param {string} subdomain - El nombre del subdominio a crear (ej. "mirestaurante").
 * @returns {Promise<boolean>} - Devuelve true si fue exitoso, de lo contrario lanza un error.
 */
const createCpanelSubdomain = async (subdomain) => {
  // --- CONFIGURACIÓN ---
  // ¡Asegúrate de poner estos valores en tu archivo .env por seguridad!
  const cpanelHost = process.env.CPANEL_HOST; // ej. 'nextfactura.com.mx'
  const cpanelUser = process.env.CPANEL_USER; // tu nombre de usuario de cPanel
  const cpanelApiKey = process.env.CPANEL_API_KEY; // la API Key que generaste
  const rootDomain = process.env.ROOT_DOMAIN; // ej. 'nextfactura.com.mx'
  
  // Validación de configuración
  if (!cpanelHost || !cpanelUser || !cpanelApiKey || !rootDomain) {
    console.error('[cPanel API] Configuración incompleta. Variables requeridas:', {
      CPANEL_HOST: !!cpanelHost,
      CPANEL_USER: !!cpanelUser,
      CPANEL_API_KEY: !!cpanelApiKey,
      ROOT_DOMAIN: !!rootDomain
    });
    throw new Error('Configuración de cPanel incompleta. Verifica las variables de entorno.');
  }

  // Validación del nombre del subdominio
  if (!subdomain || typeof subdomain !== 'string' || subdomain.trim().length === 0) {
    throw new Error('El nombre del subdominio es requerido y debe ser una cadena válida.');
  }

  // Limpiar el nombre del subdominio
  const cleanSubdomain = subdomain.trim().toLowerCase();
  
  // Validar formato del subdominio
  const subdomainRegex = /^[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?$/;
  if (!subdomainRegex.test(cleanSubdomain)) {
    throw new Error('El nombre del subdominio contiene caracteres inválidos o tiene un formato incorrecto.');
  }
  
  // El document root. Apunta a la carpeta donde está tu aplicación de React.
  // '/public_html' es el estándar en HostGator.
  const documentRoot = `public_html`; 
  
  // --- CONSTRUCCIÓN DE LA LLAMADA A LA API ---
  const apiUrl = `https://${cpanelHost}:2083/execute/SubDomain/addsubdomain`;
  
  try {
    console.log(`[cPanel API] Intentando crear subdominio: ${cleanSubdomain}.${rootDomain}`);
    
    // Configuración de timeout para evitar colgarse
    const axiosConfig = {
      headers: {
        'Authorization': `cpanel ${cpanelUser}:${cpanelApiKey}`,
        'Content-Type': 'application/json',
        'User-Agent': 'Restaurant-Service-SubdomainBot/1.0'
      },
      params: {
        rootdomain: rootDomain,
        domain: cleanSubdomain,
        dir: documentRoot, // Apunta el subdominio a la misma carpeta que el dominio principal
      },
      timeout: 30000, // 30 segundos de timeout
      validateStatus: function (status) {
        return status < 500; // Resolver solo si el status es menor a 500
      }
    };

    // Hacemos la petición con los parámetros requeridos
    const response = await axios.get(apiUrl, axiosConfig);
    
    // Manejar diferentes códigos de respuesta HTTP
    if (response.status >= 400 && response.status < 500) {
      throw new Error(`Error de autenticación o autorización (${response.status}): Verifica credenciales de cPanel.`);
    }
    
    if (response.status >= 500) {
      throw new Error(`Error del servidor cPanel (${response.status}): El servidor está experimentando problemas.`);
    }

    // La API de cPanel devuelve un objeto 'result' con 'status' y 'errors'
    const result = response.data?.result;
    
    if (!result) {
      console.error('[cPanel API] Respuesta inesperada:', response.data);
      throw new Error('Respuesta inválida de la API de cPanel.');
    }
    
    if (result.status === 1) {
      const message = result.data?.message || `Subdominio ${cleanSubdomain}.${rootDomain} creado exitosamente.`;
      console.log(`[cPanel API] Éxito: ${message}`);
      return true;
    } else {
      // Si hay un error, lo lanzamos para que el proceso principal se detenga
      const errorMsg = result.errors?.[0] || result.message || 'Error desconocido de cPanel.';
      throw new Error(errorMsg);
    }
  } catch (error) {
    // Manejo específico de diferentes tipos de errores
    if (error.code === 'ENOTFOUND') {
      throw new Error(`No se pudo conectar al servidor cPanel: ${cpanelHost}. Verifica la configuración del host.`);
    }
    
    if (error.code === 'ETIMEDOUT' || error.code === 'ECONNABORTED') {
      throw new Error('Timeout al conectar con cPanel. El servidor puede estar sobrecargado.');
    }
    
    if (error.response?.status === 401) {
      throw new Error('Credenciales de cPanel inválidas. Verifica el usuario y API key.');
    }
    
    if (error.response?.status === 403) {
      throw new Error('No tienes permisos para crear subdominios. Contacta a tu proveedor de hosting.');
    }
    
    // Captura errores de red o errores lanzados desde la respuesta de cPanel
    const errorMessage = error.response?.data?.result?.errors?.[0] || 
                         error.response?.data?.message || 
                         error.message;
    
    console.error(`[cPanel API] Fallo al crear el subdominio '${cleanSubdomain}':`, {
      error: errorMessage,
      status: error.response?.status,
      url: apiUrl,
      subdomain: cleanSubdomain
    });
    
    throw new Error(`No se pudo crear el subdominio: ${errorMessage}`);
  }
};

/**
 * Verifica si un subdominio existe en cPanel.
 * @param {string} subdomain - El nombre del subdominio a verificar.
 * @returns {Promise<boolean>} - Devuelve true si el subdominio existe, false si no existe.
 */
const checkSubdomainExists = async (subdomain) => {
  const cpanelHost = process.env.CPANEL_HOST;
  const cpanelUser = process.env.CPANEL_USER;
  const cpanelApiKey = process.env.CPANEL_API_KEY;
  
  if (!cpanelHost || !cpanelUser || !cpanelApiKey) {
    throw new Error('Configuración de cPanel incompleta para verificar subdominio.');
  }

  const apiUrl = `https://${cpanelHost}:2083/execute/SubDomain/listsubdomains`;
  
  try {
    console.log(`[cPanel API] Verificando existencia del subdominio: ${subdomain}`);
    
    const response = await axios.get(apiUrl, {
      headers: {
        'Authorization': `cpanel ${cpanelUser}:${cpanelApiKey}`,
      },
      timeout: 15000
    });

    const result = response.data?.result;
    
    if (result?.status === 1 && result.data) {
      // Buscar el subdominio en la lista
      const subdomains = result.data;
      const exists = subdomains.some(sub => sub.domain === subdomain);
      
      console.log(`[cPanel API] Subdominio ${subdomain} ${exists ? 'existe' : 'no existe'}`);
      return exists;
    }
    
    return false;
  } catch (error) {
    console.error(`[cPanel API] Error al verificar subdominio ${subdomain}:`, error.message);
    throw new Error(`No se pudo verificar la existencia del subdominio: ${error.message}`);
  }
};

/**
 * Elimina un subdominio de cPanel (opcional - usar con precaución).
 * @param {string} subdomain - El nombre del subdominio a eliminar.
 * @returns {Promise<boolean>} - Devuelve true si fue eliminado exitosamente.
 */
const deleteSubdomain = async (subdomain) => {
  const cpanelHost = process.env.CPANEL_HOST;
  const cpanelUser = process.env.CPANEL_USER;
  const cpanelApiKey = process.env.CPANEL_API_KEY;
  const rootDomain = process.env.ROOT_DOMAIN;
  
  if (!cpanelHost || !cpanelUser || !cpanelApiKey || !rootDomain) {
    throw new Error('Configuración de cPanel incompleta para eliminar subdominio.');
  }

  const fullDomain = `${subdomain}.${rootDomain}`;
  const apiUrl = `https://${cpanelHost}:2083/execute/SubDomain/delsubdomain`;
  
  try {
    console.log(`[cPanel API] Eliminando subdominio: ${fullDomain}`);
    
    const response = await axios.get(apiUrl, {
      headers: {
        'Authorization': `cpanel ${cpanelUser}:${cpanelApiKey}`,
      },
      params: {
        domain: fullDomain
      },
      timeout: 30000
    });

    const result = response.data?.result;
    
    if (result?.status === 1) {
      console.log(`[cPanel API] Subdominio ${fullDomain} eliminado exitosamente`);
      return true;
    } else {
      const errorMsg = result?.errors?.[0] || result?.message || 'Error desconocido al eliminar subdominio.';
      throw new Error(errorMsg);
    }
  } catch (error) {
    const errorMessage = error.response?.data?.result?.errors?.[0] || 
                         error.response?.data?.message || 
                         error.message;
    
    console.error(`[cPanel API] Error al eliminar subdominio ${fullDomain}:`, errorMessage);
    throw new Error(`No se pudo eliminar el subdominio: ${errorMessage}`);
  }
};

/**
 * Obtiene la lista de todos los subdominios existentes en cPanel.
 * @returns {Promise<Array>} - Devuelve un array con todos los subdominios.
 */
const listSubdomains = async () => {
  const cpanelHost = process.env.CPANEL_HOST;
  const cpanelUser = process.env.CPANEL_USER;
  const cpanelApiKey = process.env.CPANEL_API_KEY;
  
  if (!cpanelHost || !cpanelUser || !cpanelApiKey) {
    throw new Error('Configuración de cPanel incompleta para listar subdominios.');
  }

  const apiUrl = `https://${cpanelHost}:2083/execute/SubDomain/listsubdomains`;
  
  try {
    console.log('[cPanel API] Obteniendo lista de subdominios');
    
    const response = await axios.get(apiUrl, {
      headers: {
        'Authorization': `cpanel ${cpanelUser}:${cpanelApiKey}`,
      },
      timeout: 15000
    });

    const result = response.data?.result;
    
    if (result?.status === 1 && result.data) {
      console.log(`[cPanel API] Se encontraron ${result.data.length} subdominios`);
      return result.data;
    } else {
      const errorMsg = result?.errors?.[0] || result?.message || 'Error al obtener lista de subdominios.';
      throw new Error(errorMsg);
    }
  } catch (error) {
    const errorMessage = error.response?.data?.result?.errors?.[0] || 
                         error.response?.data?.message || 
                         error.message;
    
    console.error('[cPanel API] Error al listar subdominios:', errorMessage);
    throw new Error(`No se pudo obtener la lista de subdominios: ${errorMessage}`);
  }
};

/**
 * Valida la configuración de cPanel antes de realizar operaciones.
 * @returns {Promise<boolean>} - Devuelve true si la configuración es válida.
 */
const validateCpanelConfig = async () => {
  const cpanelHost = process.env.CPANEL_HOST;
  const cpanelUser = process.env.CPANEL_USER;
  const cpanelApiKey = process.env.CPANEL_API_KEY;
  const rootDomain = process.env.ROOT_DOMAIN;
  
  // Verificar variables de entorno
  const missingVars = [];
  if (!cpanelHost) missingVars.push('CPANEL_HOST');
  if (!cpanelUser) missingVars.push('CPANEL_USER');
  if (!cpanelApiKey) missingVars.push('CPANEL_API_KEY');
  if (!rootDomain) missingVars.push('ROOT_DOMAIN');
  
  if (missingVars.length > 0) {
    throw new Error(`Variables de entorno faltantes para cPanel: ${missingVars.join(', ')}`);
  }
  
  try {
    // Hacer una llamada simple para validar credenciales
    const testUrl = `https://${cpanelHost}:2083/execute/Fileman/get_disk_information`;
    
    const response = await axios.get(testUrl, {
      headers: {
        'Authorization': `cpanel ${cpanelUser}:${cpanelApiKey}`,
      },
      timeout: 10000
    });
    
    if (response.data?.result?.status === 1) {
      console.log('[cPanel API] Configuración validada exitosamente');
      return true;
    } else {
      throw new Error('Credenciales de cPanel inválidas o sin permisos');
    }
  } catch (error) {
    const errorMessage = error.response?.status === 401 
      ? 'Credenciales de cPanel inválidas'
      : error.message;
    
    console.error('[cPanel API] Error en validación de configuración:', errorMessage);
    throw new Error(`Configuración de cPanel inválida: ${errorMessage}`);
  }
};

/**
 * Función utilitaria para generar un nombre de subdominio válido y único.
 * @param {string} baseName - El nombre base para el subdominio.
 * @param {string|number} identifier - Identificador único (ej. ID del restaurante).
 * @param {Array} existingSubdomains - Array opcional de subdominios existentes para evitar duplicados.
 * @returns {string} - Nombre de subdominio válido y único.
 */
const generateUniqueSubdomain = async (baseName, identifier, existingSubdomains = null) => {
  // Normalizar el nombre base
  let subdomain = baseName
    .toLowerCase()
    .normalize('NFD')
    .replace(/[\u0300-\u036f]/g, '') // Remover acentos
    .replace(/[^a-z0-9]/g, '-') // Reemplazar caracteres especiales con guiones
    .replace(/-+/g, '-') // Reemplazar múltiples guiones consecutivos con uno solo
    .replace(/^-|-$/g, '') // Remover guiones al inicio y final
    .substring(0, 15); // Limitar longitud inicial
  
  // Si queda muy corto o vacío, usar el identificador
  if (subdomain.length < 3) {
    subdomain = `restaurant-${identifier}`;
  }
  
  // Asegurar que no empiece con número
  if (/^\d/.test(subdomain)) {
    subdomain = `r-${subdomain}`;
  }
  
  // Si no se proporcionó lista de existentes, obtenerla
  if (!existingSubdomains) {
    try {
      const allSubdomains = await listSubdomains();
      existingSubdomains = allSubdomains.map(sub => sub.domain);
    } catch (error) {
      console.warn('[cPanel API] No se pudo obtener lista de subdominios existentes:', error.message);
      existingSubdomains = [];
    }
  }
  
  // Verificar unicidad y agregar sufijo si es necesario
  let finalSubdomain = subdomain;
  let counter = 1;
  
  while (existingSubdomains.includes(finalSubdomain)) {
    finalSubdomain = `${subdomain}-${counter}`;
    counter++;
    
    // Evitar bucle infinito
    if (counter > 1000) {
      finalSubdomain = `${subdomain}-${Date.now()}`;
      break;
    }
  }
  
  return finalSubdomain;
};

/**
 * Función para verificar el estado de salud de la conexión con cPanel.
 * @returns {Promise<Object>} - Objeto con información del estado de salud.
 */
const healthCheck = async () => {
  const startTime = Date.now();
  
  try {
    await validateCpanelConfig();
    const responseTime = Date.now() - startTime;
    
    return {
      status: 'healthy',
      responseTime: `${responseTime}ms`,
      timestamp: new Date().toISOString(),
      message: 'Conexión con cPanel establecida correctamente'
    };
  } catch (error) {
    const responseTime = Date.now() - startTime;
    
    return {
      status: 'unhealthy',
      responseTime: `${responseTime}ms`,
      timestamp: new Date().toISOString(),
      error: error.message,
      message: 'Error en la conexión con cPanel'
    };
  }
};

// Exportar todas las funciones
module.exports = {
  createCpanelSubdomain,
  checkSubdomainExists,
  deleteSubdomain,
  listSubdomains,
  validateCpanelConfig,
  generateUniqueSubdomain,
  healthCheck
};