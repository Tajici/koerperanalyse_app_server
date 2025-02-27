// api/index.js

const express = require('express');
const mysql = require('mysql2/promise');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const cors = require('cors');
const dotenv = require('dotenv');
const serverless = require('serverless-http');

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

// Registrierungs-Route
app.post('/register', async (req, res) => {
  console.log('Registrierungsanfrage erhalten');
  try {
    // Hier werden die Spalten an die neue Struktur angepasst: benutzername, passwort, email und optionale Felder
    const { benutzername, passwort, email, alter, geschlecht, groesse } = req.body;

    if (!benutzername || !passwort || !email) {
      return res.status(400).json({ message: 'Bitte alle Pflichtfelder ausfüllen (benutzername, passwort, email).' });
    }

    const connection = await pool.getConnection();
    console.log('Datenbankverbindung für Registrierung erhalten');

    try {
      // Prüfen, ob benutzername oder email bereits existieren
      const [existingUser] = await connection.execute(
        'SELECT * FROM benutzer WHERE benutzername = ? OR email = ?',
        [benutzername, email]
      );

      if (existingUser.length > 0) {
        return res.status(409).json({ message: 'Benutzername oder E-Mail existiert bereits.' });
      }

      const hashedPassword = await bcrypt.hash(passwort, 10);
      await connection.execute(
        'INSERT INTO benutzer (benutzername, passwort, email, alter, geschlecht, groesse) VALUES (?, ?, ?, ?, ?, ?)',
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
    // Bei der Anmeldung wird ebenfalls auf die angepassten Spaltennamen zurückgegriffen:
    const { identifier, benutzername, email, passwort } = req.body;
    let loginIdentifier = identifier || benutzername || email;

    if (!loginIdentifier || !passwort) {
      console.log('Eingabevalidierung fehlgeschlagen');
      return res.status(400).json({ message: 'Bitte alle Felder ausfüllen.' });
    }

    const connection = await pool.getConnection();
    console.log('Datenbankverbindung erhalten für Login');

    try {
      // Suche in der Tabelle benutzer anhand von benutzername oder email
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

      // Passwortvergleich mit der Spalte passwort
      const isPasswordValid = await bcrypt.compare(passwort, user.passwort);
      console.log('Passwortvergleich abgeschlossen:', isPasswordValid);

      if (!isPasswordValid) {
        console.log('Passwort ungültig');
        return res.status(401).json({ message: 'Ungültiger Benutzername, E-Mail oder Passwort.' });
      }

      // JWT-Token generieren, hier wird der benutzername verwendet
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

// Testroute
app.get('/', (req, res) => {
  res.status(200).json({ message: 'Körperanalyse App Server läuft!' });
});

// Export für Vercel als Serverless Function
module.exports = serverless(app);

// Lokal starten, falls die Datei direkt mit `node api/index.js` ausgeführt wird
if (require.main === module) {
  const PORT = process.env.PORT || 8080;
  app.listen(PORT, () => {
    console.log(`Server läuft auf Port ${PORT}`);
  });
}
