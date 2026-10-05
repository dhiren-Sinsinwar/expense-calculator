const express = require('express');
const fs = require('fs');
const path = require('path');

const app = express();
const indexPath = path.join(__dirname, 'index.html');
const indexContent = fs.readFileSync(indexPath, 'utf8');

app.use(express.json());

// Serve static files from public folder if they exist
app.use(express.static(path.join(__dirname, 'public')));
app.use(express.static(__dirname));

// Root route
app.get('/', (req, res) => {
  res.setHeader('Content-Type', 'text/html; charset=utf-8');
  res.send(indexContent);
});

// Health check
app.get('/health', (req, res) => {
  res.json({ status: 'ok' });
});

// Catch-all for SPA routing
app.get('*', (req, res) => {
  res.setHeader('Content-Type', 'text/html; charset=utf-8');
  res.send(indexContent);
});

const PORT = process.env.PORT || 3000;
app.listen(PORT, '0.0.0.0', () => {
  console.log(`✅ Expense Calculator is LIVE on http://localhost:${PORT}`);
  console.log(`📄 Serving index.html from: ${indexPath}`);
});
