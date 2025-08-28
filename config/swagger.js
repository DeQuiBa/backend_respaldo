const swaggerJsdoc = require("swagger-jsdoc");
const swaggerUi = require("swagger-ui-express");

const PORT = process.env.PORT || "3050"

const options = {
  definition: {
    openapi: "3.0.0",
    info: {
      title: "Documentación API Sistema Ingresos y Egresos",
      version: "1.0.0",
      description: "API Documentación",
    },
    tags: [
      {
        name: "Comite",              // 👈 título único
        description: "Operaciones sobre los comités", // 👈 se muestra arriba en Swagger UI
      },
    ],
    servers: [
      {
        url: `http://localhost:${PORT}/api`,
      },
    ],
  },
  apis: ["./routes/*.js"], 
};

const swaggerSpec = swaggerJsdoc(options);

module.exports = { swaggerUi, swaggerSpec };
