# Etapa base
FROM node:18-alpine

# Establecer directorio de trabajo
WORKDIR /app

# Copiar los archivos del proyecto
COPY package*.json ./

# Instalar dependencias
RUN npm install

# Copiar el resto del código
COPY . .

# Exponer el puerto del servidor (ajústalo si usas otro)
EXPOSE 3050

# Comando para iniciar la app
CMD ["npm", "start"]
