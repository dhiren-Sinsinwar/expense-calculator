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

// API endpoint to get Google Client ID (to avoid hardcoding in frontend)
app.get('/api/config', (req, res) => {
  const clientId = '529180440880-bi2adu90l55pooo5epebd6sh673pkdhe.apps.googleusercontent.com';
  const apiUrl = 'https://expense-calculator.fly.dev';
  console.log('📋 /api/config called');
  console.log('   Client ID being returned:', clientId);
  console.log('   API URL being returned:', apiUrl);
  res.json({ 
    googleClientId: clientId,
    apiUrl: apiUrl
  });
});

// Google OAuth Callback (token flow: token arrives in the URL #fragment,
// which only the browser can read, so this page handles it client-side)
app.get('/auth/callback', (req, res) => {
  res.setHeader('Content-Type', 'text/html; charset=utf-8');
  res.send(`<!DOCTYPE html>
<html><head><meta charset="utf-8"><title>Signing in…</title></head>
<body style="font-family: Arial, sans-serif; text-align: center; padding: 60px;">
  <h2 id="msg">Signing you in…</h2>
  <script>
    (async function () {
      const msg = document.getElementById('msg');
      const params = new URLSearchParams(window.location.hash.substring(1));
      const query = new URLSearchParams(window.location.search);
      const error = params.get('error') || query.get('error');
      const token = params.get('access_token');
      const state = params.get('state');
      const expected = sessionStorage.getItem('oauthState');

      if (error || !token) {
        msg.textContent = 'Login failed: ' + (error || 'no token received');
        setTimeout(() => window.location.href = '/', 3000);
        return;
      }
      if (!expected || state !== expected) {
        msg.textContent = 'Login failed: security check (state) did not match. Please try again.';
        setTimeout(() => window.location.href = '/', 3000);
        return;
      }
      sessionStorage.removeItem('oauthState');

      try {
        const r = await fetch('https://www.googleapis.com/oauth2/v3/userinfo', {
          headers: { Authorization: 'Bearer ' + token }
        });
        if (!r.ok) throw new Error('userinfo ' + r.status);
        const u = await r.json();
        const expiresIn = parseInt(params.get('expires_in') || '3600', 10);
        localStorage.setItem('fmeAuth', JSON.stringify({
          accessToken: token,
          scope: params.get('scope') || '',
          expiresAt: Date.now() + expiresIn * 1000,
          user: { name: u.name || u.email, email: u.email, picture: u.picture || '' }
        }));
        localStorage.removeItem('authCode');
        localStorage.removeItem('authTime');
        window.location.replace('/');
      } catch (e) {
        msg.textContent = 'Could not load your Google profile: ' + e.message;
        setTimeout(() => window.location.href = '/', 3000);
      }
    })();
  </script>
</body></html>`);
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
