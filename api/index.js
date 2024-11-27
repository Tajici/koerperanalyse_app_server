// api/index.js

// Notwendige Module importieren
const express = require('express');
const mysql = require('mysql2/promise');
const jwt = require('jsonwebtoken');
const cors = require('cors');
const crypto = require('crypto'); // Integriertes Modul

// Express-App erstellen
const app = express();

// Middleware
app.use(express.json());
app.use(cors());

// Datenbankkonfiguration
const dbConfig = {
  host: process.env.DB_HOST,          // z.B. '34.65.223.142'
  user: process.env.DB_USER,          // z.B. 'root'
  password: process.env.DB_PASSWORD,  // Dein Datenbankpasswort
  database: process.env.DB_DATABASE,  // z.B. 'koerperanalyse_app'
};

// Funktion zur Verbindung mit der Datenbank
let connection;

const connectDB = async () => {
  if (!connection || connection.state === 'disconnected') {
    connection = await mysql.createConnection(dbConfig);
    console.log('Mit der Datenbank verbunden');
  }
};

// Funktion zur Generierung eines Salt mit höherer Länge
const generateSalt = (length = 16) => {
  return crypto.randomBytes(length).toString('hex'); // 16 Bytes = 32 Hex-Zeichen
};

// Funktion zum Hashen des Passworts mit PBKDF2
const hashPassword = async (password) => {
  const salt = generateSalt(); // Generiere ein sicheres Salt
  const iterations = 600000;   // Anzahl der Iterationen
  const keyLength = 32;        // Länge des abgeleiteten Schlüssels (32 Bytes = 256 Bits)
  const digest = 'sha256';     // Hash-Funktion

  const derivedKey = await crypto.promises.pbkdf2(password, salt, iterations, keyLength, digest);
  const hash = derivedKey.toString('hex');
  
  return `pbkdf2:${digest}:${iterations}$${salt}$${hash}`;
};

// Funktion zum Verifizieren des Passworts
const verifyPassword = async (password, storedPassword) => {
  try {
    const [method, digest, iterationsAndSaltAndHash] = storedPassword.split(':');
    if (method !== 'pbkdf2' || digest !== 'sha256') {
      return false; // Unsupported method or digest
    }

    const [iterationsStr, salt, hash] = iterationsAndSaltAndHash.split('$');
    const iterations = parseInt(iterationsStr, 10);
    const keyLength = 32;
    
    const derivedKey = await crypto.promises.pbkdf2(password, salt, iterations, keyLength, digest);
    const derivedHash = derivedKey.toString('hex');

    // Verwende timingSafeEqual für sicheren Vergleich
    const hashBuffer = Buffer.from(hash, 'hex');
    const derivedHashBuffer = Buffer.from(derivedHash, 'hex');

    if (hashBuffer.length !== derivedHashBuffer.length) {
      return false;
    }

    return crypto.timingSafeEqual(hashBuffer, derivedHashBuffer);
  } catch (error) {
    console.error('Fehler bei der Passwortverifizierung:', error);
    return false;
  }
};

// Registrierungsroute
app.post('/register', async (req, res) => {
  try {
    await connectDB();

    const { username, password, email } = req.body;

    // Eingabevalidierung
    if (!username || !password || !email) {
      return res.status(400).json({ message: 'Bitte alle Felder ausfüllen.' });
    }

    // Überprüfen, ob der Benutzername oder die E-Mail bereits existiert
    const [existingUser] = await connection.execute(
      'SELECT * FROM users WHERE username = ? OR email = ?',
      [username, email]
    );

    if (existingUser.length > 0) {
      return res.status(409).json({ message: 'Benutzername oder E-Mail existiert bereits.' });
    }

    // Passwort hashen mit PBKDF2
    const hashedPassword = await hashPassword(password);

    // Neuen Benutzer in die Datenbank einfügen 
    await connection.execute(
      'INSERT INTO users (username, password, email) VALUES (?, ?, ?)',
      [username, hashedPassword, email]
    );

    res.status(201).json({ message: 'Registrierung erfolgreich!' });
  } catch (error) {
    console.error('Fehler bei der Registrierung:', error);
    res.status(500).json({ message: 'Serverfehler bei der Registrierung.' });
  }
});

// Login-Route
app.post('/login', async (req, res) => {
  try {
    await connectDB();

    const { username, password } = req.body;

    // Eingabevalidierung
    if (!username || !password) {
      return res.status(400).json({ message: 'Bitte alle Felder ausfüllen.' });
    }

    // Benutzer in der Datenbank suchen
    const [users] = await connection.execute(
      'SELECT * FROM users WHERE username = ?',
      [username]
    );

    if (users.length === 0) {
      return res.status(401).json({ message: 'Ungültiger Benutzername oder Passwort.' });
    }

    const user = users[0];

    // Passwort vergleichen mit PBKDF2
    const isPasswordValid = await verifyPassword(password, user.password);

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
