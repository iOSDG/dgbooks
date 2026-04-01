const express = require('express');
const sqlite3 = require('sqlite3').verbose();
const { OAuth2Client } = require('google-auth-library');

const app = express();
const client = new OAuth2Client('REDACTED_GOOGLE_CLIENT_ID');

app.use(express.json());
app.use(express.static('.'));

// 初始化数据库
const db = new sqlite3.Database('./users.db');
db.run(`CREATE TABLE IF NOT EXISTS users (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  google_id TEXT UNIQUE,
  email TEXT,
  name TEXT,
  picture TEXT,
  created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
  last_login DATETIME DEFAULT CURRENT_TIMESTAMP
)`);

// 验证并保存用户
app.post('/api/auth/google', async (req, res) => {
  try {
    const { credential } = req.body;
    const ticket = await client.verifyIdToken({
      idToken: credential,
      audience: 'REDACTED_GOOGLE_CLIENT_ID'
    });
    
    const payload = ticket.getPayload();
    const { sub: google_id, email, name, picture } = payload;

    db.run(
      `INSERT INTO users (google_id, email, name, picture) 
       VALUES (?, ?, ?, ?)
       ON CONFLICT(google_id) DO UPDATE SET 
       last_login = CURRENT_TIMESTAMP`,
      [google_id, email, name, picture],
      function(err) {
        if (err) return res.status(500).json({ error: err.message });
        res.json({ success: true, user: { google_id, email, name, picture } });
      }
    );
  } catch (error) {
    res.status(401).json({ error: 'Invalid token' });
  }
});

app.listen(3000, () => console.log('Server running on http://localhost:3000'));
