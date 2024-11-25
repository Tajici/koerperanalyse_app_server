# Verwenden Sie das Node.js 18 Image
FROM node:18

# Arbeitsverzeichnis festlegen
WORKDIR /usr/src/app

# Paketdateien kopieren und Abhängigkeiten installieren
COPY package*.json ./
RUN npm install --production

# Anwendungscode kopieren
COPY . .

# Port freigeben
EXPOSE 8080

# Startbefehl
CMD [ "npm", "start" ]
