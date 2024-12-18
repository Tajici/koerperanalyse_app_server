// api/index.js

const express = require('express');
const cors = require('cors');
const serverless = require('serverless-http');

const app = express();
app.use(express.json());
app.use(cors());

app.get('/', (req, res) => {
  res.status(200).json({ message: 'Körperanalyse App Server läuft!' });
});

app.get('/test', (req, res) => {
  res.status(200).json({ message: 'Testroute funktioniert!' });
});

module.exports = serverless(app);

if (require.main === module) {
  const PORT = process.env.PORT || 8080;
  app.listen(PORT, () => {
    console.log(`Server läuft auf Port ${PORT}`);
  });
}
