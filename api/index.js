// api/index.js

const express = require('express');
const mysql = require('mysql2/promise');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const cors = require('cors');
const dotenv = require('dotenv');
const serverless = require('serverless-http');
const { Configuration, OpenAIApi } = require("openai");

dotenv.config();

const app = express();
app.use(express.json());
app.use(cors());

// Datenbankkonfiguration
const dbConfig = {
  host: process.env.DB_HOST,
  user: process.env.DB_USER,
  password: process.env.DB_PASSWORD, 
  database: process.env.DB_DATABASE, 
  port: process.env.DB_PORT ? parseInt(process.env.DB_PORT) : 3306,
  waitForConnections: true,
  connectionLimit: 10,
  queueLimit: 0,
  connectTimeout: 10000,
};

let pool = mysql.createPool(dbConfig);
console.log('Datenbank-Verbindungspool erstellt');

// OpenAI-Konfiguration
const configuration = new Configuration({
  apiKey: process.env.OPENAI_API_KEY, // Stelle sicher, dass dieser Schlüssel in deiner .env-Datei steht
});
const openai = new OpenAIApi(configuration);

// Registrierungs-Route
app.post('/register', async (req, res) => {
  console.log('Registrierungsanfrage erhalten');
  try {
    const { benutzername, passwort, email, alter, geschlecht, groesse } = req.body;

    if (!benutzername || !passwort || !email) {
      return res.status(400).json({ message: 'Bitte alle Pflichtfelder ausfüllen (benutzername, passwort, email).' });
    }

    const connection = await pool.getConnection();
    console.log('Datenbankverbindung für Registrierung erhalten');

    try {
      const [existingUser] = await connection.execute(
        'SELECT * FROM benutzer WHERE benutzername = ? OR email = ?',
        [benutzername, email]
      );

      if (existingUser.length > 0) {
        return res.status(409).json({ message: 'Benutzername oder E-Mail existiert bereits.' });
      }

      const hashedPassword = await bcrypt.hash(passwort, 10);
      await connection.execute(
        'INSERT INTO benutzer (benutzername, passwort, email, `alter`, geschlecht, groesse) VALUES (?, ?, ?, ?, ?, ?)',
        [benutzername, hashedPassword, email, alter || null, geschlecht || null, groesse || null]
      );

      res.status(201).json({ message: 'Registrierung erfolgreich!' });
    } finally {
      connection.release();
    }
  } catch (error) {
    console.error('Fehler bei der Registrierung:', error);
    res.status(500).json({ message: 'Serverfehler bei der Registrierung.' });
  }
});

// Login-Route
app.post('/login', async (req, res) => {
  console.log('Login-Anfrage erhalten');

  try {
    const { identifier, benutzername, email, passwort } = req.body;
    let loginIdentifier = identifier || benutzername || email;

    if (!loginIdentifier || !passwort) {
      console.log('Eingabevalidierung fehlgeschlagen');
      return res.status(400).json({ message: 'Bitte alle Felder ausfüllen.' });
    }

    const connection = await pool.getConnection();
    console.log('Datenbankverbindung erhalten für Login');

    try {
      const [users] = await connection.execute(
        'SELECT * FROM benutzer WHERE benutzername = ? OR email = ?',
        [loginIdentifier, loginIdentifier]
      );

      if (users.length === 0) {
        console.log('Benutzername oder E-Mail existiert nicht');
        return res.status(401).json({ message: 'Ungültiger Benutzername, E-Mail oder Passwort.' });
      }

      const user = users[0];
      console.log('Benutzer gefunden:', user);

      const isPasswordValid = await bcrypt.compare(passwort, user.passwort);
      console.log('Passwortvergleich abgeschlossen:', isPasswordValid);

      if (!isPasswordValid) {
        console.log('Passwort ungültig');
        return res.status(401).json({ message: 'Ungültiger Benutzername, E-Mail oder Passwort.' });
      }

      const token = jwt.sign(
        { userId: user.id, benutzername: user.benutzername },
        process.env.JWT_SECRET,
        { expiresIn: '1h' }
      );
      console.log('JWT-Token generiert:', token);

      res.status(200).json({
        message: 'Login erfolgreich!',
        token: token,
        userId: user.id,
        benutzername: user.benutzername,
      });
    } finally {
      connection.release();
      console.log('Datenbankverbindung für Login freigegeben');
    }
  } catch (error) {
    console.error('Fehler beim Login:', error);
    res.status(500).json({ message: 'Serverfehler beim Login.' });
  }
});

// Chat-Endpoint mit OpenAI-Integration
app.post('/chat', async (req, res) => {
  // Authentifizierung mittels JWT
  const authHeader = req.headers.authorization;
  if (!authHeader) {
    return res.status(401).json({ message: 'Kein Token vorhanden.' });
  }
  const token = authHeader.split(' ')[1];
  try {
    const decoded = jwt.verify(token, process.env.JWT_SECRET);
    console.log('Token validiert:', decoded);
  } catch (error) {
    return res.status(401).json({ message: 'Ungültiges Token.' });
  }

  // Nachricht und optionale Nutzerdaten entgegennehmen
  const { message, userData } = req.body;
  if (!message) {
    return res.status(400).json({ message: 'Keine Nachricht erhalten.' });
  }
  
  // Prompt erstellen, der Messdaten und Nutzerfrage integriert
  const prompt = `Der Nutzer hat folgende Messdaten: ${JSON.stringify(userData)}.
Nutzer: ${message}
Bot:`;

  try {
    const response = await openai.createCompletion({
      model: 'text-davinci-003', // Oder ein anderes Modell, falls gewünscht
      prompt: prompt,
      max_tokens: 150,
      temperature: 0.7,
    });
    const reply = response.data.choices[0].text.trim();
    res.status(200).json({ reply });
  } catch (error) {
    console.error('Fehler bei der Kommunikation mit OpenAI:', error);
    res.status(500).json({ message: 'Fehler bei der Kommunikation mit OpenAI' });
  }
});

// Testroute
app.get('/', (req, res) => {
  res.status(200).json({ message: 'Körperanalyse App Server läuft!' });
});

// Export für Vercel als Serverless Function
module.exports = serverless(app);

// Lokal starten, falls die Datei direkt mit `node index.js` ausgeführt wird
if (require.main === module) {
  const PORT = process.env.PORT || 8080;
  app.listen(PORT, () => {
    console.log(`Server läuft auf Port ${PORT}`);
  });
}
