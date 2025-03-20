// api/index.js

const express = require('express');
const mysql = require('mysql2/promise');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const cors = require('cors');
const dotenv = require('dotenv');
const serverless = require('serverless-http');
const fetch = require("node-fetch"); // Für Mistral API

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

// Mistral API Konfiguration
const MISTRAL_API_KEY = process.env.MISTRAL_API_KEY;
const MISTRAL_API_URL = "https://api.mistral.ai/v1/chat/completions";

// Registrierungs-Route
app.post('/register', async (req, res) => {
  try {
    const { benutzername, passwort, email, alter, geschlecht, groesse } = req.body;

    if (!benutzername || !passwort || !email) {
      return res.status(400).json({ message: 'Bitte alle Pflichtfelder ausfüllen (benutzername, passwort, email).' });
    }

    const connection = await pool.getConnection();
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

    connection.release();
    res.status(201).json({ message: 'Registrierung erfolgreich!' });
  } catch (error) {
    console.error('Fehler bei der Registrierung:', error);
    res.status(500).json({ message: 'Serverfehler bei der Registrierung.' });
  }
});

// Login-Route
app.post('/login', async (req, res) => {
  try {
    const { identifier, passwort } = req.body;

    if (!identifier || !passwort) {
      return res.status(400).json({ message: 'Bitte alle Felder ausfüllen.' });
    }

    const connection = await pool.getConnection();
    const [users] = await connection.execute(
      'SELECT * FROM benutzer WHERE benutzername = ? OR email = ?',
      [identifier, identifier]
    );

    if (users.length === 0) {
      return res.status(401).json({ message: 'Ungültiger Benutzername, E-Mail oder Passwort.' });
    }

    const user = users[0];
    const isPasswordValid = await bcrypt.compare(passwort, user.passwort);

    if (!isPasswordValid) {
      return res.status(401).json({ message: 'Ungültiger Benutzername, E-Mail oder Passwort.' });
    }

    const token = jwt.sign(
      { userId: user.id, benutzername: user.benutzername },
      process.env.JWT_SECRET,
      { expiresIn: '1h' }
    );

    connection.release();
    res.status(200).json({
      message: 'Login erfolgreich!',
      token: token,
      userId: user.id,
      benutzername: user.benutzername,
    });
  } catch (error) {
    console.error('Fehler beim Login:', error);
    res.status(500).json({ message: 'Serverfehler beim Login.' });
  }
});

// Chat-Endpoint mit Mistral AI
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

  // Nachricht empfangen
  const { message } = req.body;
  if (!message) {
    return res.status(400).json({ message: 'Keine Nachricht erhalten.' });
  }

  try {
    const response = await fetch(MISTRAL_API_URL, {
      method: "POST",
      headers: {
        "Authorization": `Bearer ${MISTRAL_API_KEY}`,
        "Content-Type": "application/json"
      },
      body: JSON.stringify({
        model: "mistral-medium",
        messages: [
          { role: "system", content: "Du bist ein hilfreicher KI-Assistent." },
          { role: "user", content: message }
        ],
        max_tokens: 150,
        temperature: 0.7
      })
    });

    const data = await response.json();

    if (!data.choices || data.choices.length === 0) {
      throw new Error("Keine Antwort von Mistral AI erhalten");
    }

    res.status(200).json({ reply: data.choices[0].message.content.trim() });
  } catch (error) {
    console.error("Fehler bei Mistral AI:", error);
    res.status(500).json({ message: "Fehler bei der Kommunikation mit Mistral AI", error: error.message });
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
