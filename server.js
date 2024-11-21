// server.js

const express = require('express');
const bodyParser = require('body-parser');
const cors = require('cors');
const app = express();
const bcrypt = require('bcrypt');
const mysql = require('mysql2');
const jwt = require('jsonwebtoken');
require('dotenv').config(); // Umgebungsvariablen laden

// Uncaught Exception und Unhandled Rejection behandeln
process.on('uncaughtException', (err) => {
  console.error('Uncaught Exception:', err.stack || err);
});

process.on('unhandledRejection', (reason, promise) => {
  console.error('Unhandled Rejection at:', promise, 'reason:', reason);
});

// Datenbankverbindung herstellen
const db = mysql.createConnection({
  host: process.env.DB_HOST,
  user: process.env.DB_USER, // Ihr MySQL-Benutzername
  password: process.env.DB_PASSWORD, // Ihr MySQL-Passwort
  database: process.env.DB_DATABASE,
});

db.connect((err) => {
  if (err) {
    console.error('Fehler beim Verbinden mit der Datenbank:', err);
    return;
  }
  console.log('Mit der Datenbank verbunden');
});

// Middleware einrichten
app.use(bodyParser.json());
app.use(cors());

// Test-Route
app.get('/', (req, res) => {
  res.send('Der Server läuft!');
});

// Registrierungs-Endpunkt
app.post('/register', (req, res) => {
  const { username, password, email } = req.body;

  // Eingaben validieren
  if (!username || !password || !email) {
    return res.status(400).json({ message: 'Bitte füllen Sie alle Felder aus.' });
  }

  // Prüfen, ob der Benutzer bereits existiert
  const checkUserQuery = 'SELECT * FROM users WHERE username = ? OR email = ?';
  db.query(checkUserQuery, [username, email], (err, results) => {
    if (err) {
      console.error('Fehler beim Überprüfen des Benutzers:', err);
      return res.status(500).json({ message: 'Serverfehler' });
    }
    if (results.length > 0) {
      return res.status(409).json({ message: 'Benutzername oder E-Mail existiert bereits.' });
    } else {
      // Passwort hashen
      const saltRounds = 10;
      bcrypt.hash(password, saltRounds, (err, hash) => {
        if (err) {
          console.error('Fehler beim Hashen des Passworts:', err);
          return res.status(500).json({ message: 'Serverfehler' });
        }

        // Neuen Benutzer einfügen
        const insertUserQuery = 'INSERT INTO users (username, password, email) VALUES (?, ?, ?)';
        db.query(insertUserQuery, [username, hash, email], (err, results) => {
          if (err) {
            console.error('Fehler beim Einfügen des Benutzers:', err);
            return res.status(500).json({ message: 'Serverfehler' });
          }
          res.status(200).json({ message: 'Benutzer erfolgreich registriert.' });
        });
      });
    }
  });
});

app.post('/login', (req, res) => {
  const { username, password } = req.body;

  // Eingaben validieren
  if (!username || !password) {
    return res.status(400).json({ message: 'Bitte geben Sie Benutzername und Passwort ein.' });
  }

  // Benutzer in der Datenbank suchen
  const findUserQuery = 'SELECT * FROM users WHERE username = ?';
  db.query(findUserQuery, [username], (err, results) => {
    if (err) {
      console.error('Fehler beim Suchen des Benutzers:', err);
      return res.status(500).json({ message: 'Serverfehler' });
    }

    if (results.length === 0) {
      return res.status(401).json({ message: 'Ungültiger Benutzername oder Passwort.' });
    }

    const user = results[0];

    // Passwort überprüfen
    bcrypt.compare(password, user.password, (err, isMatch) => {
      if (err) {
        console.error('Fehler beim Vergleichen der Passwörter:', err);
        return res.status(500).json({ message: 'Serverfehler' });
      }

      if (!isMatch) {
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
        username: user.username, // Benutzernamen hinzufügen
      });
    });
  });
});

// Authentifizierungs-Middleware
function authenticateToken(req, res, next) {
  const authHeader = req.headers['authorization'];
  const token = authHeader && authHeader.split(' ')[1];

  if (token == null) {
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
}

// Beispiel für einen geschützten Endpunkt
app.get('/profile', authenticateToken, (req, res) => {
  res.json({ message: `Willkommen, ${req.user.username}!`, user: req.user });
});

// Benutzer löschen
app.delete('/users/:id', authenticateToken, (req, res) => {
  const userId = req.params.id;

  // Überprüfen, ob der angemeldete Benutzer der gleiche ist oder ob der Benutzer ein Administrator ist
  if (req.user.id !== parseInt(userId)) {
    return res.status(403).json({ message: 'Sie sind nicht berechtigt, diesen Benutzer zu löschen.' });
  }

  const deleteUserQuery = 'DELETE FROM users WHERE id = ?';
  db.query(deleteUserQuery, [userId], (err, results) => {
    if (err) {
      console.error('Fehler beim Löschen des Benutzers:', err);
      return res.status(500).json({ message: 'Serverfehler' });
    }
    res.status(200).json({ message: 'Benutzer erfolgreich gelöscht.' });
  });
});


// Server starten
const PORT = process.env.PORT || 3000; // Ändern Sie 3000 in 3001
app.listen(PORT, () => {
  console.log(`Server läuft auf Port ${PORT}`);
});
