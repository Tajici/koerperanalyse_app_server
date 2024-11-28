// api/index.js

const express = require('express');
const mysql = require('mysql2/promise');
const bcrypt = require('bcrypt');
const jwt = require('jsonwebtoken');
const cors = require('cors');

const app = express();

// Middleware
app.use(express.json());
app.use(cors());

// Datenbankkonfiguration
const dbConfig = {
  host: process.env.DB_HOST,          // z.B. '34.65.223.142'
  user: process.env.DB_USER,          // z.B. 'root'
  password: process.env.DB_PASSWORD,  // Ihr Datenbankpasswort
  database: process.env.DB_DATABASE,  // z.B. 'koerperanalyse_app'
  waitForConnections: true,
  connectionLimit: 10, // Passen Sie dies je nach Bedarf an
  queueLimit: 0
};

// Verbindungspool erstellen
const pool = mysql.createPool(dbConfig);

// Registrierungsroute
app.post('/register', async (req, res) => {
  try {
    const { username, password, email } = req.body;

    // Eingabevalidierung
    if (!username || !password || !email) {
      return res.status(400).json({ message: 'Bitte alle Felder ausfüllen.' });
    }

    const connection = await pool.getConnection();

    try {
      // Überprüfen, ob der Benutzername oder die E-Mail bereits existiert
      const [existingUser] = await connection.execute(
        'SELECT * FROM users WHERE username = ? OR email = ?',
        [username, email]
      );

      if (existingUser.length > 0) {
        return res.status(409).json({ message: 'Benutzername oder E-Mail existiert bereits.' });
      }

      // Passwort hashen
      const hashedPassword = await bcrypt.hash(password, 10);

      // Neuen Benutzer in die Datenbank einfügen 
      await connection.execute(
        'INSERT INTO users (username, password, email) VALUES (?, ?, ?)',
        [username, hashedPassword, email]
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
  try {
    const { username, password } = req.body;

    // Eingabevalidierung
    if (!username || !password) {
      return res.status(400).json({ message: 'Bitte alle Felder ausfüllen.' });
    }

    const connection = await pool.getConnection();

    try {
      // Benutzer in der Datenbank suchen
      const [users] = await connection.execute(
        'SELECT * FROM users WHERE username = ?',
        [username]
      );

      if (users.length === 0) {
        return res.status(401).json({ message: 'Ungültiger Benutzername oder Passwort.' });
      }

      const user = users[0];

      // Passwort vergleichen
      const isPasswordValid = await bcrypt.compare(password, user.password);

      if (!isPasswordValid) {
        return res.status(401).json({ message: 'Ungültiger Benutzername oder Passwort.' });
      }

      // JWT-Token generieren
      const token = jwt.sign(
        { userId: user.id, username: user.username },
        process.env.JWT_SECRET,
        { expiresIn: '1h' }
      );

      res.status(200).json({
        message: 'Login erfolgreich!',
        token: token,
        userId: user.id,
        username: user.username,
      });
    } finally {
      connection.release();
    }
  } catch (error) {
    console.error('Fehler beim Login:', error);
    res.status(500).json({ message: 'Serverfehler beim Login.' });
  }
});

// Testroute
app.get('/', (req, res) => {
  res.status(200).json({ message: 'Körperanalyse App Server läuft!' });
});

// Express-App exportieren
module.exports = app;
