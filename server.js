const express = require('express');
const fs = require('fs');
const path = require('path');
const https = require('https');

const app = express();
const indexPath = path.join(__dirname, 'index.html');
const indexContent = fs.readFileSync(indexPath, 'utf8');

app.use(express.json());
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

// Google OAuth Callback
app.get('/auth/callback', async (req, res) => {
  const { code, error } = req.query;

  if (error) {
    return res.send(`
      <html>
        <body style="font-family: Arial; text-align: center; padding: 50px;">
          <h1>❌ Error</h1>
          <p>${error}</p>
          <a href="/">← Back to Home</a>
        </body>
      </html>
    `);
  }

  if (!code) {
    return res.send(`
      <html>
        <body style="font-family: Arial; text-align: center; padding: 50px;">
          <h1>❌ No code received</h1>
          <a href="/">← Back to Home</a>
        </body>
      </html>
    `);
  }

  try {
    // For now, just acknowledge successful auth
    // In production, exchange code for tokens here
    return res.send(`
      <html>
        <body style="font-family: Arial; text-align: center; padding: 50px;">
          <h1>✅ Login Successful!</h1>
          <p>Redirecting...</p>
          <script>
            // Store auth info
            localStorage.setItem('authCode', '${code}');
            localStorage.setItem('authTime', new Date().getTime());
            // Redirect to dashboard
            setTimeout(() => window.location.href = '/', 2000);
          </script>
        </body>
      </html>
    `);
  } catch (err) {
    console.error('OAuth error:', err);
    res.status(500).send(`
      <html>
        <body style="font-family: Arial; text-align: center; padding: 50px;">
          <h1>❌ Server Error</h1>
          <p>${err.message}</p>
          <a href="/">← Back to Home</a>
        </body>
      </html>
    `);
  }
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
