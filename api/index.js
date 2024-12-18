// api/index.js

const express = require('express');
const mysql = require('mysql2/promise');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const cors = require('cors');
const dotenv = require('dotenv');
const serverless = require('serverless-http');

// .env Variablen laden (nur lokal relevant)
dotenv.config();

const app = express();
app.use(express.json());
app.use(cors());

// Datenbankkonfiguration aus Umgebungsvariablen
const dbConfig = {
  host: process.env.DB_HOST,         // z.B. bodyarc.helioho.st
  user: process.env.DB_USER,         // z.B. flovhsr_bodyarc
  password: process.env.DB_PASSWORD, // z.B. BodyArc!0
  database: process.env.DB_DATABASE, // z.B. flovhsr_bodyarc
  port: process.env.DB_PORT ? parseInt(process.env.DB_PORT) : 3306,
  waitForConnections: true,
  connectionLimit: 10,
  queueLimit: 0,
  connectTimeout: 10000,
};

// Verbindungspool erstellen
let pool;
if (!pool) {
  pool = mysql.createPool(dbConfig);
  console.log('Datenbank-Verbindungspool erstellt');
}

// Registrierungs-Route
app.post('/register', async (req, res) => {
  console.log('Registrierungsanfrage erhalten');
  try {
    const { username, password, email } = req.body;

    if (!username || !password || !email) {
      console.log('Eingabevalidierung fehlgeschlagen');
      return res.status(400).json({ message: 'Bitte alle Felder ausfüllen.' });
    }

    const connection = await pool.getConnection();
    console.log('Datenbankverbindung für Registrierung erhalten');

    try {
      // Prüfen ob username oder email bereits existieren
      const [existingUser] = await connection.execute(
        'SELECT * FROM users WHERE username = ? OR email = ?',
        [username, email]
      );

      if (existingUser.length > 0) {
        console.log('Benutzername oder E-Mail existiert bereits');
        return res.status(409).json({ message: 'Benutzername oder E-Mail existiert bereits.' });
      }

      const hashedPassword = await bcrypt.hash(password, 10);
      console.log('Passwort gehasht');

      await connection.execute(
        'INSERT INTO users (username, password, email) VALUES (?, ?, ?)',
        [username, hashedPassword, email]
      );
      console.log('Neuer Benutzer in die Datenbank eingefügt');

      res.status(201).json({ message: 'Registrierung erfolgreich!' });
    } finally {
      connection.release();
      console.log('Datenbankverbindung für Registrierung freigegeben');
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
    const { username, password } = req.body;

    if (!username || !password) {
      console.log('Eingabevalidierung fehlgeschlagen');
      return res.status(400).json({ message: 'Bitte alle Felder ausfüllen.' });
    }

    const connection = await pool.getConnection();
    console.log('Datenbankverbindung für Login erhalten');

    try {
      const [users] = await connection.execute(
        'SELECT * FROM users WHERE username = ?',
        [username]
      );

      if (users.length === 0) {
        console.log('Benutzername existiert nicht');
        return res.status(401).json({ message: 'Ungültiger Benutzername oder Passwort.' });
      }

      const user = users[0];
      const isPasswordValid = await bcrypt.compare(password, user.password);
      console.log('Passwortvergleich abgeschlossen');

      if (!isPasswordValid) {
        console.log('Passwort ungültig');
        return res.status(401).json({ message: 'Ungültiger Benutzername oder Passwort.' });
      }

      const token = jwt.sign(
        { userId: user.id, username: user.username },
        process.env.JWT_SECRET,  // z.B. bodyarcSECURITY010101
        { expiresIn: '1h' }
      );
      console.log('JWT-Token generiert');

      res.status(200).json({
        message: 'Login erfolgreich!',
        token: token,
        userId: user.id,
        username: user.username,
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

// Testroute
app.get('/', (req, res) => {
  console.log('Testroute aufgerufen');
  res.status(200).json({ message: 'Körperanalyse App Server läuft!' });
});

// Neue einfache Test-Route ohne DB
app.get('/test', (req, res) => {
  console.log('Einfache Testroute aufgerufen');
  res.status(200).json({ message: 'Testroute funktioniert!' });
});

// Für Vercel als Serverless Function exportieren
module.exports = serverless(app);

// Lokal starten, falls die Datei direkt ausgeführt wird
if (require.main === module) {
  const PORT = process.env.PORT || 8080;
  app.listen(PORT, () => {
    console.log(`Server läuft auf Port ${PORT}`);
  });
}
