// services/auth-service/logger.js
const winston = require('winston');

const logger = winston.createLogger({
  // Nivel mínimo de log a procesar
  level: 'info',

  // Formato del log: timestamp + formato JSON
  format: winston.format.combine(
    winston.format.timestamp(),
    winston.format.json()
  ),

  // Dónde guardar los logs (los "transportes")
  transports: [
    // Guardar todos los logs de nivel 'error' en el archivo `errors.log`
    new winston.transports.File({ filename: 'logs/errors.log', level: 'error' }),

    // Guardar todos los logs de nivel 'info' (y superiores) en `combined.log`
    new winston.transports.File({ filename: 'logs/combined.log' }),

    // También mostrar los logs en la consola
    new winston.transports.Console({
      format: winston.format.combine(
        winston.format.colorize(),
        winston.format.simple()
      )
    })
  ],
});

module.exports = logger;
