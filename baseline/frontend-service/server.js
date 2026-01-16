/**
 * Frontend Service - Node.js Express with vulnerable dependencies
 */
const express = require('express');
const axios = require('axios');
const jwt = require('jsonwebtoken');
const bodyParser = require('body-parser');
const morgan = require('morgan');

const app = express();
const PORT = process.env.PORT || 3000;
const API_SERVICE = process.env.API_SERVICE || 'http://api-service:5000';

app.use(bodyParser.json());
app.use(morgan('combined'));

app.get('/health', (req, res) => {
  res.json({ status: 'healthy', service: 'frontend' });
});

app.get('/', (req, res) => {
  res.json({
    message: 'Vulnerable Microservices Demo - Frontend',
    version: '1.0.0',
    endpoints: ['/health', '/api/data', '/api/auth']
  });
});

app.get('/api/data', async (req, res) => {
  try {
    const response = await axios.get(`${API_SERVICE}/api/data`);
    res.json(response.data);
  } catch (error) {
    res.status(500).json({ error: error.message });
  }
});

app.post('/api/auth', (req, res) => {
  const { username, password } = req.body;

  // Vulnerable JWT signing
  const token = jwt.sign(
    { username, role: 'user' },
    'super-secret-key',
    { algorithm: 'HS256' }
  );

  res.json({ token });
});

app.listen(PORT, () => {
  console.log(`Frontend service listening on port ${PORT}`);
});
