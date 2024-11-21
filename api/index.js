// api/index.js

const express = require('express');
const app = express();
const bodyParser = require('body-parser');
const cors = require('cors');
const bcrypt = require('bcrypt');
const mysql = require('mysql2/promise');
const jwt = require('jsonwebtoken');

// Middleware
app.use(bodyParser.json());
app.use(cors());

// Datenbankverbindung
const dbConfig = {
  host: process.env.DB_HOST,
  user: process.env.DB_USER,
  password: process.env.DB_PASSWORD,
  database: process.env.DB_DATABASE,
};

let connection;

// Verbindung zur Datenbank herstellen
const connectDB = async () => {
  if (!connection) {
    connection = await mysql.createConnection(dbConfig);
    console.log('Mit der Datenbank verbunden');
  }
};

// Middleware zur Authentifizierung
const authenticateToken = (req, res, next) => {
  const authHeader = req.headers['authorization'];
  const token = authHeader && authHeader.split(' ')[1];

  if (!token) {
    return res.status(401).json({ message: 'Kein Token bereitgestellt.' });
  }

  jwt.verify(token, process.env.JWT_SECRET, (err, user) => {
    if (err) {
      console.error('Token-Verifizierung fehlgeschlagen:', err);
      return res.status(403).json({ message: 'Ungültiges Token.' });
    }

    req.user = user;
    next();
  });
};

// Root-Route hinzufügen
app.get('/', (req, res) => {
  res.status(200).json({ message: 'Körperanalyse App Server läuft!' });
});

// Registrierung
app.post('/register', async (req, res) => {
  const { username, password, email } = req.body;

  if (!username || !password || !email) {
    return res.status(400).json({ message: 'Bitte alle Felder ausfüllen.' });
  }

  try {
    await connectDB();

    // Überprüfen, ob der Benutzer bereits existiert
    const [existingUser] = await connection.execute(
      'SELECT * FROM users WHERE username = ? OR email = ?',
      [username, email]
    );

    if (existingUser.length > 0) {
      return res.status(409).json({ message: 'Benutzername oder E-Mail existiert bereits.' });
    }

    // Passwort hashen
    const hashedPassword = await bcrypt.hash(password, 10);

    // Benutzer in die Datenbank einfügen
    await connection.execute(
      'INSERT INTO users (username, password, email) VALUES (?, ?, ?)',
      [username, hashedPassword, email]
    );

    res.status(200).json({ message: 'Benutzer erfolgreich registriert.' });
  } catch (err) {
    console.error('Fehler bei der Registrierung:', err);
    res.status(500).json({ message: 'Serverfehler' });
  }
});

// Login
app.post('/login', async (req, res) => {
  const { username, password } = req.body;

  if (!username || !password) {
    return res.status(400).json({ message: 'Bitte Benutzername und Passwort eingeben.' });
  }

  try {
    await connectDB();

    // Benutzer finden
    const [users] = await connection.execute('SELECT * FROM users WHERE username = ?', [username]);

    if (users.length === 0) {
      return res.status(401).json({ message: 'Ungültiger Benutzername oder Passwort.' });
    }

    const user = users[0];

    // Passwort überprüfen
    const match = await bcrypt.compare(password, user.password);

    if (!match) {
      return res.status(401).json({ message: 'Ungültiger Benutzername oder Passwort.' });
    }

    // Token generieren
    const token = jwt.sign(
      { id: user.id, username: user.username },
      process.env.JWT_SECRET,
      { expiresIn: '1h' }
    );

    res.status(200).json({
      message: 'Erfolgreich eingeloggt.',
      token: token,
      userId: user.id,
      username: user.username,
    });
  } catch (err) {
    console.error('Fehler beim Login:', err);
    res.status(500).json({ message: 'Serverfehler' });
  }
});

// Beispiel für einen geschützten Endpunkt
app.get('/profile', authenticateToken, async (req, res) => {
  try {
    await connectDB();
    const [users] = await connection.execute('SELECT id, username, email FROM users WHERE id = ?', [req.user.id]);

    if (users.length === 0) {
      return res.status(404).json({ message: 'Benutzer nicht gefunden.' });
    }

    const user = users[0];
    res.status(200).json({ user: user });
  } catch (err) {
    console.error('Fehler beim Abrufen des Profils:', err);
    res.status(500).json({ message: 'Serverfehler' });
  }
});

// Benutzer löschen
app.delete('/users/:id', authenticateToken, async (req, res) => {
  const userId = req.params.id;

  // Überprüfen, ob der angemeldete Benutzer der gleiche ist oder ob der Benutzer ein Administrator ist
  if (req.user.id !== parseInt(userId)) {
    return res.status(403).json({ message: 'Sie sind nicht berechtigt, diesen Benutzer zu löschen.' });
  }

  try {
    await connectDB();

    const deleteUserQuery = 'DELETE FROM users WHERE id = ?';
    await connection.execute(deleteUserQuery, [userId]);

    res.status(200).json({ message: 'Benutzer erfolgreich gelöscht.' });
  } catch (err) {
    console.error('Fehler beim Löschen des Benutzers:', err);
    res.status(500).json({ message: 'Serverfehler' });
  }
});

// Exportieren Sie die Express-App als Vercel-Serverless Function
module.exports = app;
