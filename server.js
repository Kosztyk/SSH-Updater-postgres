/**
 * ssh-updater v2 — PostgreSQL storage + JWT (cookie) auth + SSE streaming
 * Same routes/JSON as your Mongo version.
 */
const express = require('express');
const path = require('path');
const cors = require('cors');
const cookieParser = require('cookie-parser');
const jwt = require('jsonwebtoken');
const bcrypt = require('bcryptjs');
const { Pool } = require('pg');
const crypto = require('crypto');
const { Client } = require('ssh2');
const { EventEmitter } = require('events');

const PORT = process.env.PORT || 8080;
const DATABASE_URL = process.env.DATABASE_URL || 'postgres://postgres:postgres@localhost:5432/sshupdaterdb';

const app = express();
app.use(cors({ origin: true, credentials: true }));
app.use(express.json({ limit: '11mb' })); // Increased from 1MB to 11MB for file uploads
app.use(cookieParser());

// ---- DB (pg) ----------------------------------------------------------------
const pool = new Pool({ connectionString: DATABASE_URL });

const SCHEMA_SQL = `
CREATE EXTENSION IF NOT EXISTS pgcrypto;

CREATE TABLE IF NOT EXISTS app_kv (
  k TEXT PRIMARY KEY,
  v JSONB NOT NULL,
  updated_at TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE TABLE IF NOT EXISTS app_user (
  id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  username TEXT UNIQUE NOT NULL,
  password_hash TEXT NOT NULL,
  created_at TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE TABLE IF NOT EXISTS host (
  id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  name TEXT NOT NULL,
  ip TEXT NOT NULL,
  "user" TEXT NOT NULL,
  password TEXT,             -- plaintext parity with your Mongo demo (consider encrypting later)
  port INT NOT NULL DEFAULT 22,
  is_root BOOLEAN NOT NULL DEFAULT FALSE,
  has_containers BOOLEAN NOT NULL DEFAULT FALSE,
  created_at TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE TABLE IF NOT EXISTS host_container_path (
  id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  host_id UUID NOT NULL REFERENCES host(id) ON DELETE CASCADE,
  path TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_host_path_host_id ON host_container_path(host_id);
`;

function toId(row) { const { id, ...rest } = row; return { _id: id, ...rest }; }
const q = (text, params=[]) => pool.query(text, params);

async function initDbAndSecret() {
  await q(SCHEMA_SQL);

// --- lightweight migration to add columns if the DB was created earlier ---
  await q(`
    ALTER TABLE host ADD COLUMN IF NOT EXISTS password TEXT;
    ALTER TABLE host ADD COLUMN IF NOT EXISTS port INT NOT NULL DEFAULT 22;
    ALTER TABLE host ADD COLUMN IF NOT EXISTS is_root BOOLEAN NOT NULL DEFAULT FALSE;
    ALTER TABLE host ADD COLUMN IF NOT EXISTS has_containers BOOLEAN NOT NULL DEFAULT FALSE;
  `);
  // -------------------------------------------------------------------------

  // Persisted JWT secret (so no .env secret needed)
  const r = await q('SELECT v FROM app_kv WHERE k=$1', ['jwt_secret']);
  if (r.rowCount) return Buffer.from(r.rows[0].v.secret, 'base64');

  const secret = crypto.randomBytes(32);
  await q(
    `INSERT INTO app_kv(k,v) VALUES ($1,$2::jsonb)
     ON CONFLICT (k) DO UPDATE SET v=EXCLUDED.v, updated_at=now()`,
    ['jwt_secret', JSON.stringify({ secret: secret.toString('base64') })]
  );
  return secret;
}

let JWT_SECRET; // Buffer
// -----------------------------------------------------------------------------

// ─── Auth middleware (cookie-based, same behavior) ───────────────────────────
function requireAuth(req, res, next) {
  const token = req.cookies?.token;
  if (!token) return res.status(401).json({ error: 'Auth required' });
  try {
    const payload = jwt.verify(token, JWT_SECRET);
    req.user = payload;
    next();
  } catch {
    return res.status(401).json({ error: 'Invalid token' });
  }
}

// ─── UI routes (same as Mongo build) ─────────────────────────────────────────
app.get('/', (req, res) => {
  const token = req.cookies?.token;
  if (!token) return res.redirect('/login.html');
  try {
    jwt.verify(token, JWT_SECRET);
    res.sendFile(path.join(__dirname, 'public', 'index.html'));
  } catch {
    res.clearCookie('token');
    res.redirect('/login.html');
  }
});
app.use('/public', express.static(path.join(__dirname, 'public')));
app.use(express.static(path.join(__dirname, 'public'))); // serve index/login/icons
app.get('/login.html', (_req, res) => res.sendFile(path.join(__dirname, 'public', 'login.html')));

// ─── Auth endpoints (same names/payloads) ────────────────────────────────────
app.post('/api/auth/register', async (req, res) => {
  try {
    const { username, password } = req.body || {};
    if (!username || !password) return res.status(400).json({ error: 'username and password are required' });

    const { rows } = await q('SELECT COUNT(*)::int AS n FROM app_user');
    if (rows[0].n > 0) {
      const token = req.cookies?.token;
      if (!token) return res.status(401).json({ error: 'Auth required to add users' });
      try { jwt.verify(token, JWT_SECRET); } catch { return res.status(401).json({ error: 'Invalid token' }); }
    }

    const exists = await q('SELECT 1 FROM app_user WHERE username=$1', [username]);
    if (exists.rowCount) return res.status(409).json({ error: 'username already exists' });

    const passwordHash = await bcrypt.hash(password, 12);
    const ins = await q(
      'INSERT INTO app_user(username,password_hash) VALUES ($1,$2) RETURNING id',
      [username, passwordHash]
    );
    res.json({ ok: true, id: ins.rows[0].id });
  } catch (error) {
    console.error('Register error:', error);
    res.status(500).json({ error: 'Internal server error' });
  }
});

app.post('/api/auth/login', async (req, res) => {
  try {
    const { username, password } = req.body || {};
    if (!username || !password) return res.status(400).json({ error: 'username and password are required' });

    const r = await q('SELECT id, username, password_hash FROM app_user WHERE username=$1', [username]);
    if (!r.rowCount) return res.status(401).json({ error: 'Invalid credentials' });

    const u = r.rows[0];
    const ok = await bcrypt.compare(password, u.password_hash);
    if (!ok) return res.status(401).json({ error: 'Invalid credentials' });

    const token = jwt.sign({ uid: u.id, u: u.username }, JWT_SECRET, { expiresIn: '12h' });
    res.cookie('token', token, { httpOnly: true, sameSite: 'lax', maxAge: 12 * 60 * 60 * 1000 });
    res.json({ ok: true });
  } catch (error) {
    console.error('Login error:', error);
    res.status(500).json({ error: 'Internal server error' });
  }
});

app.post('/api/auth/logout', (_req, res) => { res.clearCookie('token'); res.json({ ok: true }); });

app.get('/api/auth/hasUsers', async (_req, res) => {
  try {
    const r = await q('SELECT COUNT(*)::int AS n FROM app_user');
    res.json({ hasUsers: r.rows[0].n > 0 });
  } catch (error) {
    console.error('HasUsers error:', error);
    res.status(500).json({ error: 'Internal server error' });
  }
});

// ─── Helpers identical to your Mongo build ───────────────────────────────────
function normalizePaths(body) {
  let arr = [];
  if (Array.isArray(body.containerPaths)) arr = body.containerPaths;
  else if (typeof body.containerPaths === 'string') arr = body.containerPaths.split('\n');
  else if (typeof body.containerPath === 'string') arr = [body.containerPath];
  else if (typeof body.containerPathsText === 'string') arr = body.containerPathsText.split('\n');

  return [...new Set(arr.map(s => String(s).replace(/\r/g, '').trim()).filter(Boolean))];
}
function escForDoubleQuotes(s) { return String(s).replace(/(["\\])/g, '\\$1'); }
function escSingle(s) { return String(s).replace(/'/g, "'\\''"); }
const DEFAULT_ENV = { LC_ALL: 'C', PATH: '/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin' };

// ─── Hosts CRUD (same URLs/shape) ────────────────────────────────────────────
app.get('/api/hosts', requireAuth, async (_req, res) => {
  try {
    const hosts = (await q('SELECT * FROM host ORDER BY created_at DESC')).rows;

    let paths = [];
    if (hosts.length) {
      const ids = hosts.map(h => h.id);
      const placeholders = ids.map((_, i) => `$${i+1}`).join(',');
      const pr = await q(`SELECT host_id, path FROM host_container_path WHERE host_id IN (${placeholders})`, ids);
      paths = pr.rows;
    }

    const list = hosts.map(h => {
      const cp = paths.filter(p => p.host_id === h.id).map(p => p.path);
      const { is_root, has_containers, ...rest } = h;
      return toId({ ...rest, isRoot: is_root, hasContainers: has_containers, containerPaths: cp });
    });
    res.json(list);
  } catch (error) {
    console.error('Get hosts error:', error);
    res.status(500).json({ error: 'Internal server error' });
  }
});

app.post('/api/hosts', requireAuth, async (req, res) => {
  try {
    const { name, ip, user, password, port, isRoot, hasContainers } = req.body || {};
    if (!ip || !user || !password) return res.status(400).json({ error: 'ip, user, password are required' });

    const ins = await q(
      `INSERT INTO host(name,ip,"user",password,port,is_root,has_containers)
       VALUES ($1,$2,$3,$4,$5,$6,$7)
       RETURNING *`,
      [
        name || ip, ip, user, password,
        Number(port) || 22,
        !!isRoot,
        !!hasContainers
      ]
    );
    const hostId = ins.rows[0].id;

    const paths = normalizePaths(req.body);
    for (const p of paths) await q('INSERT INTO host_container_path(host_id,path) VALUES ($1,$2)', [hostId, p]);

    const fresh = (await q('SELECT * FROM host WHERE id=$1', [hostId])).rows[0];
    const cp = (await q('SELECT path FROM host_container_path WHERE host_id=$1', [hostId])).rows.map(r => r.path);

    res.json(toId({ ...fresh, isRoot: fresh.is_root, hasContainers: fresh.has_containers, containerPaths: cp }));
  } catch (error) {
    console.error('Create host error:', error);
    res.status(500).json({ error: 'Internal server error' });
  }
});

app.put('/api/hosts/:id', requireAuth, async (req, res) => {
  try {
    const id = req.params.id;
    const got = await q('SELECT * FROM host WHERE id=$1', [id]);
    if (!got.rowCount) return res.status(404).json({ error: 'Not found' });
    const cur = got.rows[0];

    const { name, ip, user, password, port, isRoot, hasContainers } = req.body || {};
    const next = {
      name: name ?? cur.name,
      ip: ip ?? cur.ip,
      user: user ?? cur.user,
      password: (password === '' || password === undefined) ? cur.password : password, // keep if not provided
      port: Number(port ?? cur.port) || 22,
      is_root: (isRoot ?? cur.is_root),
      has_containers: (hasContainers ?? cur.has_containers)
    };

    await q(
      `UPDATE host SET name=$1, ip=$2, "user"=$3, password=$4, port=$5, is_root=$6, has_containers=$7 WHERE id=$8`,
      [next.name, next.ip, next.user, next.password, next.port, next.is_root, next.has_containers, id]
    );

    // replace container paths if provided
    if ('containerPaths' in req.body || 'containerPathsText' in req.body || 'containerPath' in req.body) {
      await q('DELETE FROM host_container_path WHERE host_id=$1', [id]);
      for (const p of normalizePaths(req.body)) await q('INSERT INTO host_container_path(host_id,path) VALUES ($1,$2)', [id, p]);
    }

    const fresh = (await q('SELECT * FROM host WHERE id=$1', [id])).rows[0];
    const cp = (await q('SELECT path FROM host_container_path WHERE host_id=$1', [id])).rows.map(r => r.path);
    res.json(toId({ ...fresh, isRoot: fresh.is_root, hasContainers: fresh.has_containers, containerPaths: cp }));
  } catch (error) {
    console.error('Update host error:', error);
    res.status(500).json({ error: 'Internal server error' });
  }
});

app.delete('/api/hosts/:id', requireAuth, async (req, res) => {
  try {
    await q('DELETE FROM host WHERE id=$1', [req.params.id]);
    res.json({ ok: true });
  } catch (error) {
    console.error('Delete host error:', error);
    res.status(500).json({ error: 'Internal server error' });
  }
});

// ─── SSH helpers (unchanged) ─────────────────────────────────────────────────
function runAptOnHost(host) {
  return new Promise((resolve) => {
    const conn = new Client();
    const start = Date.now();
    let stdout = '', stderr = '';

    const nonInteractive = "export DEBIAN_FRONTEND=noninteractive; apt-get update -y && apt-get upgrade -y";
    const base = `bash -lc "${escForDoubleQuotes(nonInteractive)}"`;
    const cmd = (host.isRoot || host.user === 'root')
      ? base
      : `echo '${(host.password || '').replace(/'/g, "'\\''")}' | sudo -S -p '' ${base}`;

    conn.on('ready', () => {
      conn.exec(cmd, { env: { LC_ALL: 'C' } }, (err, stream) => {
        if (err) { conn.end(); return resolve({ host: host.name, ip: host.ip, ok: false, error: 'exec: ' + err.message }); }
        stream.on('close', (code, signal) => {
          conn.end();
          resolve({
            host: host.name, ip: host.ip, ok: code === 0, exitCode: code, signal,
            durationMs: Date.now() - start,
            stdout: stdout.slice(-20000), stderr: stderr.slice(-20000)
          });
        }).on('data', d => { stdout += d.toString(); })
          .stderr.on('data', d => { stderr += d.toString(); });
      });
    }).on('error', (err) => {
      resolve({ host: host.name, ip: host.ip, ok: false, error: 'ssh: ' + err.message, durationMs: Date.now() - start });
    }).connect({ host: host.ip, port: host.port || 22, username: host.user, password: host.password, readyTimeout: 20000 });
  });
}

function streamAptOnHost(host, onEvent) {
  const conn = new Client();
  const start = Date.now();

  const nonInteractive = "export DEBIAN_FRONTEND=noninteractive; apt-get update -y && apt-get upgrade -y";
  const base = `bash -lc "${escForDoubleQuotes(nonInteractive)}"`;
  const cmd = (host.isRoot || host.user === 'root')
    ? base
    : `echo '${(host.password || '').replace(/'/g, "'\\''")}' | sudo -S -p '' ${base}`;

  conn.on('ready', () => {
    onEvent({ type: 'hostStart', host: host.name, ip: host.ip });
    conn.exec(cmd, { env: { LC_ALL: 'C' } }, (err, stream) => {
      if (err) { onEvent({ type: 'hostEnd', host: host.name, ip: host.ip, ok: false, error: 'exec: ' + err.message, durationMs: Date.now() - start, exitCode: null }); conn.end(); return; }
      stream.on('close', (code) => { onEvent({ type: 'hostEnd', host: host.name, ip: host.ip, ok: code === 0, exitCode: code, durationMs: Date.now() - start }); conn.end(); })
        .on('data', d => onEvent({ type: 'log', host: host.name, ip: host.ip, chunk: d.toString() }))
        .stderr.on('data', d => onEvent({ type: 'log', host: host.name, ip: host.ip, chunk: d.toString() }));
    });
  }).on('error', (err) => {
    onEvent({ type: 'hostEnd', host: host.name, ip: host.ip, ok: false, error: 'ssh: ' + err.message, durationMs: Date.now() - start, exitCode: null });
  }).connect({ host: host.ip, port: host.port || 22, username: host.user, password: host.password, readyTimeout: 20000 });
}

function streamScriptOnHost(host, script, onEvent) {
  const conn = new Client();
  const start = Date.now();

  const b64 = Buffer.from(String(script), 'utf8').toString('base64');
  const remote = `TMP=$(mktemp) && printf '%s' '${b64}' | base64 -d > "$TMP" && chmod +x "$TMP" && bash "$TMP"; rc=$?; rm -f "$TMP"; exit $rc`;
  const remoteEsc = escSingle(remote);
  const pw = escSingle(host.password || '');

  const cmd = (host.isRoot || host.user === 'root')
    ? `bash -lc '${remoteEsc}'`
    : `echo '${pw}' | sudo -S -p '' bash -lc '${remoteEsc}'`;

  conn.on('ready', () => {
    onEvent({ type: 'hostStart', host: host.name, ip: host.ip });
    conn.exec(cmd, { env: DEFAULT_ENV }, (err, stream) => {
      if (err) { onEvent({ type: 'hostEnd', host: host.name, ip: host.ip, ok: false, error: 'exec: ' + err.message, durationMs: Date.now() - start, exitCode: null }); conn.end(); return; }
      stream.on('close', (code) => { onEvent({ type: 'hostEnd', host: host.name, ip: host.ip, ok: code === 0, exitCode: code, durationMs: Date.now() - start }); conn.end(); })
        .on('data', d => onEvent({ type: 'log', host: host.name, ip: host.ip, chunk: d.toString() }))
        .stderr.on('data', d => onEvent({ type: 'log', host: host.name, ip: host.ip, chunk: d.toString() }));
    });
  }).on('error', (err) => {
    onEvent({ type: 'hostEnd', host: host.name, ip: host.ip, ok: false, error: 'ssh: ' + err.message, durationMs: Date.now() - start, exitCode: null });
  }).connect({ host: host.ip, port: host.port || 22, username: host.user, password: host.password, readyTimeout: 20000 });
}

function streamContainersOnHost(host, onEvent) {
  const conn = new Client();
  const start = Date.now();

  const paths = (Array.isArray(host.containerPaths) ? host.containerPaths : [])
    .map(s => String(s).replace(/\r/g, '').trim())
    .filter(Boolean);

  if (!host.hasContainers || paths.length === 0) {
    process.nextTick(() => onEvent({ type: 'hostEnd', host: host.name, ip: host.ip, ok: true, exitCode: 0, durationMs: 0 }));
    return;
  }

  const cmds = paths.map((p, i) => {
    const qp = `'${p.replace(/'/g, `'\\''`)}'`;
    return `echo "=== PATH ${i + 1}/${paths.length}: ${p} ==="; cd ${qp} && docker compose pull && docker compose up -d`;
  }).join(' && ');

  const base = `bash -lc "${escForDoubleQuotes(cmds)}"`;
  const fullCmd = (host.isRoot || host.user === 'root')
    ? base
    : `echo '${(host.password || '').replace(/'/g, "'\\''")}' | sudo -S -p '' ${base}`;

  conn.on('ready', () => {
    onEvent({ type: 'hostStart', host: host.name, ip: host.ip });
    conn.exec(fullCmd, { env: { LC_ALL: 'C' } }, (err, stream) => {
      if (err) { onEvent({ type: 'hostEnd', host: host.name, ip: host.ip, ok: false, exitCode: null, durationMs: Date.now() - start, error: 'exec: ' + err.message }); conn.end(); return; }
      stream.on('close', (code) => { onEvent({ type: 'hostEnd', host: host.name, ip: host.ip, ok: code === 0, exitCode: code, durationMs: Date.now() - start }); conn.end(); })
        .on('data', d => onEvent({ type: 'log', host: host.name, ip: host.ip, chunk: d.toString() }))
        .stderr.on('data', d => onEvent({ type: 'log', host: host.name, ip: host.ip, chunk: d.toString() }));
    });
  }).on('error', (err) => {
    onEvent({ type: 'hostEnd', host: host.name, ip: host.ip, ok: false, exitCode: null, durationMs: Date.now() - start, error: 'ssh: ' + err.message });
  }).connect({ host: host.ip, port: host.port || 22, username: host.user, password: host.password, readyTimeout: 20000 });
}

// ─── File Upload & Management ────────────────────────────────────────────────
function streamFileToHost(host, fileB64, fileName, action, command, onEvent) {
  return new Promise((resolve) => {
    const conn = new Client();
    const start = Date.now();
    
    const safeFileName = fileName.replace(/[^a-zA-Z0-9._-]/g, '_');
    
    // Determine the appropriate upload path based on user privileges
    let remotePath;
    if (host.isRoot || host.user === 'root') {
      remotePath = `/root/${safeFileName}`;
    } else {
      // For non-root users, upload to their home directory or /tmp
      remotePath = `/home/${host.user}/${safeFileName}`;
    }

    conn.on('ready', () => {
      onEvent({ type: 'hostStart', host: host.name, ip: host.ip });
      onEvent({ type: 'log', host: host.name, ip: host.ip, chunk: `🚀 Starting ${action} operation for ${fileName}\n` });
      onEvent({ type: 'log', host: host.name, ip: host.ip, chunk: `👤 User: ${host.user} (${host.isRoot || host.user === 'root' ? 'root' : 'non-root'})\n` });
      onEvent({ type: 'log', host: host.name, ip: host.ip, chunk: `📁 Target path: ${remotePath}\n` });

      // Use SFTP for reliable file upload
      conn.sftp((err, sftp) => {
        if (err) {
          onEvent({ type: 'log', host: host.name, ip: host.ip, chunk: `❌ SFTP Error: ${err.message}\n` });
          onEvent({ type: 'hostEnd', host: host.name, ip: host.ip, ok: false, error: 'sftp: ' + err.message, durationMs: Date.now() - start, exitCode: null });
          conn.end();
          resolve();
          return;
        }

        const fileBuffer = Buffer.from(fileB64, 'base64');
        onEvent({ type: 'log', host: host.name, ip: host.ip, chunk: `📦 File size: ${fileBuffer.length} bytes\n` });
        onEvent({ type: 'log', host: host.name, ip: host.ip, chunk: `⬆️  Uploading file via SFTP...\n` });

        const writeStream = sftp.createWriteStream(remotePath);
        
        writeStream.on('close', () => {
          onEvent({ type: 'log', host: host.name, ip: host.ip, chunk: `✅ File uploaded successfully to ${remotePath}\n` });
          sftp.end();
          executeAction();
        });
        
        writeStream.on('error', (err) => {
          // If upload to home directory fails, try /tmp as fallback
          if (err.message.includes('Permission denied') && !remotePath.startsWith('/tmp/')) {
            onEvent({ type: 'log', host: host.name, ip: host.ip, chunk: `⚠️  Permission denied for ${remotePath}, trying /tmp/...\n` });
            const tmpPath = `/tmp/${safeFileName}`;
            remotePath = tmpPath;
            
            const tmpWriteStream = sftp.createWriteStream(tmpPath);
            tmpWriteStream.on('close', () => {
              onEvent({ type: 'log', host: host.name, ip: host.ip, chunk: `✅ File uploaded successfully to ${tmpPath}\n` });
              sftp.end();
              executeAction();
            });
            tmpWriteStream.on('error', (err2) => {
              onEvent({ type: 'log', host: host.name, ip: host.ip, chunk: `❌ Upload failed: ${err2.message}\n` });
              onEvent({ type: 'hostEnd', host: host.name, ip: host.ip, ok: false, error: 'upload: ' + err2.message, durationMs: Date.now() - start, exitCode: null });
              sftp.end();
              conn.end();
              resolve();
            });
            tmpWriteStream.write(fileBuffer);
            tmpWriteStream.end();
          } else {
            onEvent({ type: 'log', host: host.name, ip: host.ip, chunk: `❌ Upload failed: ${err.message}\n` });
            onEvent({ type: 'hostEnd', host: host.name, ip: host.ip, ok: false, error: 'upload: ' + err.message, durationMs: Date.now() - start, exitCode: null });
            sftp.end();
            conn.end();
            resolve();
          }
        });

        writeStream.write(fileBuffer);
        writeStream.end();
      });

      function executeAction() {
        onEvent({ type: 'log', host: host.name, ip: host.ip, chunk: `⚡ Executing ${action} action...\n` });
        
        let cmd = '';
        const isRootUser = host.isRoot || host.user === 'root';
        const escapedPassword = escSingle(host.password || '');
        
        if (action === 'install' && safeFileName.endsWith('.deb')) {
          onEvent({ type: 'log', host: host.name, ip: host.ip, chunk: `🔧 Installing .deb package: ${safeFileName}\n` });
          
          if (isRootUser) {
            // Root user can install directly
            cmd = `echo "=== INSTALLING .DEB PACKAGE AS ROOT ===" && ` +
                  `dpkg -i '${remotePath}' 2>&1 ; ` +
                  `INSTALL_RESULT=$? ; ` +
                  `echo "=== INSTALLATION EXIT CODE: $INSTALL_RESULT ===" ; ` +
                  `if [ $INSTALL_RESULT -ne 0 ]; then ` +
                  `  echo "=== ATTEMPTING DEPENDENCY FIX ===" && ` +
                  `  apt-get update && apt-get install -f -y ; ` +
                  `  echo "=== FIX COMPLETED ===" ; ` +
                  `fi ; ` +
                  `echo "=== INSTALLATION PROCESS FINISHED ==="`;
          } else {
            // Non-root user needs proper sudo with password
            cmd = `echo "=== INSTALLING .DEB PACKAGE WITH SUDO ===" && ` +
                  `echo '${escapedPassword}' | sudo -S -p '' dpkg -i '${remotePath}' 2>&1 ; ` +
                  `INSTALL_RESULT=$? ; ` +
                  `echo "=== INSTALLATION EXIT CODE: $INSTALL_RESULT ===" ; ` +
                  `if [ $INSTALL_RESULT -ne 0 ]; then ` +
                  `  echo "=== ATTEMPTING DEPENDENCY FIX WITH SUDO ===" && ` +
                  `  echo '${escapedPassword}' | sudo -S -p '' apt-get update && ` +
                  `  echo '${escapedPassword}' | sudo -S -p '' apt-get install -f -y ; ` +
                  `  echo "=== FIX COMPLETED ===" ; ` +
                  `fi ; ` +
                  `echo "=== INSTALLATION PROCESS FINISHED ==="`;
          }
        } else if (action === 'run' && command) {
          onEvent({ type: 'log', host: host.name, ip: host.ip, chunk: `💻 Executing command: ${command}\n` });
          
          // Replace {FILE_PATH} placeholder with the actual uploaded file path
          let processedCommand = command;
          if (command.includes('{FILE_PATH}')) {
            processedCommand = command.replace(/{FILE_PATH}/g, remotePath);
            onEvent({ type: 'log', host: host.name, ip: host.ip, chunk: `📝 Using file path: ${remotePath}\n` });
          } else {
            // If no placeholder, assume the command should reference the uploaded file
            // For common commands that need the file path, auto-append it
            if (command.trim() === 'dpkg -i' || command.trim().startsWith('dpkg -i ')) {
              processedCommand = `${command} '${remotePath}'`;
              onEvent({ type: 'log', host: host.name, ip: host.ip, chunk: `📝 Auto-appending file path to dpkg command\n` });
            } else if (command.trim() === 'chmod +x' || command.trim().startsWith('chmod +x ')) {
              processedCommand = `${command} '${remotePath}'`;
              onEvent({ type: 'log', host: host.name, ip: host.ip, chunk: `📝 Auto-appending file path to chmod command\n` });
            } else if (command.includes('.sh') && !command.includes(remotePath)) {
              // If command references a .sh file but not the uploaded path, replace it
              processedCommand = command.replace(/\.sh\b/g, `'${remotePath}'`);
              onEvent({ type: 'log', host: host.name, ip: host.ip, chunk: `📝 Auto-replacing .sh reference with uploaded file path\n` });
            } else if (command.includes('.deb') && !command.includes(remotePath)) {
              // If command references a .deb file but not the uploaded path, replace it
              processedCommand = command.replace(/\.deb\b/g, `'${remotePath}'`);
              onEvent({ type: 'log', host: host.name, ip: host.ip, chunk: `📝 Auto-replacing .deb reference with uploaded file path\n` });
            }
          }
          
          // Check if command requires root privileges
          const needsSudo = processedCommand.includes('dpkg') || processedCommand.includes('apt-get') || 
                           processedCommand.includes('install') || processedCommand.includes('systemctl') || 
                           processedCommand.includes('service ') || processedCommand.includes('/root/');
          
          if (isRootUser) {
            // Root user - execute command directly
            cmd = `echo "=== EXECUTING COMMAND AS ROOT ===" && ` +
                  `echo "Command: ${processedCommand}" && ` +
                  `echo "=== COMMAND OUTPUT ===" && ` +
                  `${processedCommand} 2>&1 ; ` +
                  `echo "=== COMMAND EXIT CODE: $? ==="`;
          } else if (needsSudo) {
            // Non-root user running privileged command - use sudo with password
            cmd = `echo "=== EXECUTING PRIVILEGED COMMAND WITH SUDO ===" && ` +
                  `echo "Command: ${processedCommand}" && ` +
                  `echo "=== COMMAND OUTPUT ===" && ` +
                  `echo '${escapedPassword}' | sudo -S -p '' ${processedCommand} 2>&1 ; ` +
                  `echo "=== COMMAND EXIT CODE: $? ==="`;
          } else {
            // Non-root user running non-privileged command - execute directly
            cmd = `echo "=== EXECUTING COMMAND ===" && ` +
                  `echo "Command: ${processedCommand}" && ` +
                  `echo "=== COMMAND OUTPUT ===" && ` +
                  `${processedCommand} 2>&1 ; ` +
                  `echo "=== COMMAND EXIT CODE: $? ==="`;
          }
        } else if (action === 'upload') {
          onEvent({ type: 'log', host: host.name, ip: host.ip, chunk: `📋 Verifying upload...\n` });
          cmd = `echo "=== UPLOAD VERIFICATION ===" && ` +
                `ls -la '${remotePath}' && ` +
                `echo "=== FILE INFO ===" && ` +
                `file '${remotePath}' && ` +
                `echo "=== FILE SIZE: \$(stat -c%s '${remotePath}') bytes ===" && ` +
                `echo "=== UPLOAD SUCCESSFUL ==="`;
        } else {
          onEvent({ type: 'log', host: host.name, ip: host.ip, chunk: `📁 Upload only - no additional action\n` });
          cmd = `echo "File uploaded to: ${remotePath}" && ` +
                `echo "Upload completed successfully"`;
        }

        onEvent({ type: 'log', host: host.name, ip: host.ip, chunk: `🔨 Executing remote command...\n` });

        conn.exec(cmd, { env: DEFAULT_ENV }, (err, stream) => {
          if (err) {
            onEvent({ type: 'log', host: host.name, ip: host.ip, chunk: `❌ Command execution failed: ${err.message}\n` });
            onEvent({ type: 'hostEnd', host: host.name, ip: host.ip, ok: false, error: 'exec: ' + err.message, durationMs: Date.now() - start, exitCode: null });
            conn.end();
            resolve();
            return;
          }

          stream.on('close', (code) => {
            onEvent({ type: 'log', host: host.name, ip: host.ip, chunk: `\n🏁 Operation completed with exit code: ${code}\n` });
            onEvent({ type: 'hostEnd', host: host.name, ip: host.ip, ok: code === 0, exitCode: code, durationMs: Date.now() - start });
            conn.end();
            resolve();
          })
          .on('data', d => onEvent({ type: 'log', host: host.name, ip: host.ip, chunk: d.toString() }))
          .stderr.on('data', d => onEvent({ type: 'log', host: host.name, ip: host.ip, chunk: d.toString() }));
        });
      }
    }).on('error', (err) => {
      onEvent({ type: 'log', host: host.name, ip: host.ip, chunk: `❌ SSH Connection failed: ${err.message}\n` });
      onEvent({ type: 'hostEnd', host: host.name, ip: host.ip, ok: false, error: 'ssh: ' + err.message, durationMs: Date.now() - start, exitCode: null });
      resolve();
    }).connect({
      host: host.ip,
      port: host.port || 22,
      username: host.user,
      password: host.password,
      readyTimeout: 45000  // Increased timeout for file operations
    });
  });
}

// ─── Non-stream JSON endpoints (compat) ──────────────────────────────────────
app.post('/api/run/:id', requireAuth, async (req, res) => {
  try {
    const r = await q('SELECT * FROM host WHERE id=$1', [req.params.id]);
    if (!r.rowCount) return res.status(404).json({ error: 'Host not found' });
    const h = r.rows[0];
    const cp = (await q('SELECT path FROM host_container_path WHERE host_id=$1', [h.id])).rows.map(r => r.path);
    const host = { ...h, isRoot: h.is_root, hasContainers: h.has_containers, containerPaths: cp };
    res.json(await runAptOnHost(host));
  } catch (error) {
    console.error('Run host error:', error);
    res.status(500).json({ error: 'Internal server error' });
  }
});

app.post('/api/runAll', requireAuth, async (_req, res) => {
  try {
    const hosts = (await q('SELECT * FROM host')).rows;
    const list = await Promise.all(hosts.map(async h => {
      const cp = (await q('SELECT path FROM host_container_path WHERE host_id=$1', [h.id])).rows.map(r => r.path);
      const host = { ...h, isRoot: h.is_root, hasContainers: h.has_containers, containerPaths: cp };
      return runAptOnHost(host);
    }));
    res.json({ count: list.length, results: await Promise.all(list) });
  } catch (error) {
    console.error('Run all error:', error);
    res.status(500).json({ error: 'Internal server error' });
  }
});

// ─── SSE utils ───────────────────────────────────────────────────────────────
function sseInit(res) {
  res.writeHead(200, { 'Content-Type': 'text/event-stream', 'Cache-Control': 'no-cache, no-transform', Connection: 'keep-alive' });
  res.write('\n');
}
function sseSend(res, event, data) { res.write(`event: ${event}\n`); res.write(`data: ${JSON.stringify(data)}\n\n`); }

// ─── Streaming: apt (single + all) ───────────────────────────────────────────
app.get('/api/stream/run/:id', requireAuth, async (req, res) => {
  try {
    const r = await q('SELECT * FROM host WHERE id=$1', [req.params.id]);
    if (!r.rowCount) return res.status(404).end();

    const h = r.rows[0];
    const cp = (await q('SELECT path FROM host_container_path WHERE host_id=$1', [h.id])).rows.map(r => r.path);
    const host = { ...h, isRoot: h.is_root, hasContainers: h.has_containers, containerPaths: cp };

    sseInit(res);
    streamAptOnHost(host, (ev) => {
      if (ev.type === 'hostStart') sseSend(res, 'hostStart', ev);
      else if (ev.type === 'log') sseSend(res, 'log', ev);
      else if (ev.type === 'hostEnd') { sseSend(res, 'hostEnd', ev); sseSend(res, 'done', {}); res.end(); }
    });
  } catch (error) {
    console.error('Stream run error:', error);
    res.status(500).end();
  }
});

app.get('/api/stream/runAll', requireAuth, async (_req, res) => {
  try {
    const hosts = (await q('SELECT * FROM host')).rows;

    sseInit(res);
    if (!hosts.length) { sseSend(res, 'done', { empty: true }); return res.end(); }

    let remaining = hosts.length;
    hosts.forEach(async (h) => {
      try {
        const cp = (await q('SELECT path FROM host_container_path WHERE host_id=$1', [h.id])).rows.map(r => r.path);
        const host = { ...h, isRoot: h.is_root, hasContainers: h.has_containers, containerPaths: cp };
        streamAptOnHost(host, (ev) => {
          if (ev.type === 'hostStart') sseSend(res, 'hostStart', ev);
          else if (ev.type === 'log') sseSend(res, 'log', ev);
          else if (ev.type === 'hostEnd') {
            sseSend(res, 'hostEnd', ev);
            if (--remaining === 0) { sseSend(res, 'done', {}); res.end(); }
          }
        });
      } catch (error) {
        console.error('Error processing host:', error);
        if (--remaining === 0) { sseSend(res, 'done', {}); res.end(); }
      }
    });
  } catch (error) {
    console.error('Stream run all error:', error);
    res.status(500).end();
  }
});

// ─── Streaming: custom (job + stream), same API ──────────────────────────────
const jobs = new Map(); // jobId -> EventEmitter
function newJob() {
  const id = Date.now().toString(36) + Math.random().toString(36).slice(2, 8);
  const ee = new EventEmitter(); ee.setMaxListeners(0);
  jobs.set(id, ee);
  setTimeout(() => jobs.delete(id), 60 * 60 * 1000);
  return { id, ee };
}

app.post('/api/runCustomStream', requireAuth, async (req, res) => {
  try {
    const { hostIds, scriptB64 } = req.body || {};
    if (!Array.isArray(hostIds) || hostIds.length === 0) return res.status(400).json({ error: 'hostIds is required' });
    if (!scriptB64) return res.status(400).json({ error: 'scriptB64 required' });

    const script = Buffer.from(String(scriptB64), 'base64').toString('utf8').replace(/\r/g, '');
    if (!script.trim()) return res.status(400).json({ error: 'Empty script' });
    if (script.length > 200 * 1024) return res.status(413).json({ error: 'Script too large (max 200 KB)' });

    // fetch hosts
    const ids = hostIds;
    const placeholders = ids.map((_, i) => `$${i+1}`).join(',');
    const r = await q(`SELECT * FROM host WHERE id IN (${placeholders})`, ids);

    const { id: jobId, ee } = newJob();
    process.nextTick(async () => {
      for (const h of r.rows) {
        try {
          const cp = (await q('SELECT path FROM host_container_path WHERE host_id=$1', [h.id])).rows.map(r => r.path);
          const host = { ...h, isRoot: h.is_root, hasContainers: h.has_containers, containerPaths: cp };
          streamScriptOnHost(host, script, (ev) => {
            if (ev.type === 'hostStart') ee.emit('hostStart', ev);
            else if (ev.type === 'log') ee.emit('log', ev);
            else if (ev.type === 'hostEnd') ee.emit('hostEnd', ev);
          });
        } catch (error) {
          console.error('Error processing host for custom script:', error);
        }
      }
    });

    res.json({ ok: true, jobId });
  } catch (error) {
    console.error('Run custom stream error:', error);
    res.status(500).json({ error: 'Internal server error' });
  }
});

app.get('/api/stream/runCustom', requireAuth, (req, res) => {
  try {
    const jobId = String(req.query.job || '');
    const ee = jobs.get(jobId);
    if (!ee) return res.status(404).end();

    sseInit(res);

    const onStart = (d) => sseSend(res, 'hostStart', d);
    const onLog = (d) => sseSend(res, 'log', d);
    const onEnd = (d) => sseSend(res, 'hostEnd', d);
    const onDone = (_d) => { sseSend(res, 'done', {}); cleanup(); res.end(); };

    ee.on('hostStart', onStart);
    ee.on('log', onLog);
    ee.on('hostEnd', onEnd);

    // simple timer to signal "done" when stream quiets for a bit
    let t; const poke = () => { clearTimeout(t); t = setTimeout(onDone, 1500); };
    ee.on('hostEnd', poke); ee.on('log', poke); poke();

    function cleanup() { ee.off('hostStart', onStart); ee.off('log', onLog); ee.off('hostEnd', onEnd); clearTimeout(t); }
    req.on('close', cleanup);
  } catch (error) {
    console.error('Stream run custom error:', error);
    res.status(500).end();
  }
});

// ─── File Upload Streaming ───────────────────────────────────────────────────
app.post('/api/uploadFileStream', requireAuth, async (req, res) => {
  try {
    const { hostIds, fileB64, fileName, action, command } = req.body || {};
    
    if (!Array.isArray(hostIds) || hostIds.length === 0) {
      return res.status(400).json({ error: 'hostIds is required' });
    }
    if (!fileB64 || !fileName) {
      return res.status(400).json({ error: 'fileB64 and fileName required' });
    }
    if (action === 'run' && !command) {
      return res.status(400).json({ error: 'command required for run action' });
    }

    // Validate file size (max 10MB)
    try {
      const fileSize = Buffer.from(fileB64, 'base64').length;
      if (fileSize > 10 * 1024 * 1024) {
        return res.status(413).json({ error: 'File too large (max 10 MB)' });
      }
    } catch (sizeError) {
      return res.status(400).json({ error: 'Invalid file data' });
    }

    // Fetch hosts
    const ids = hostIds;
    const placeholders = ids.map((_, i) => `$${i+1}`).join(',');
    const r = await q(`SELECT * FROM host WHERE id IN (${placeholders})`, ids);

    if (r.rows.length === 0) {
      return res.status(404).json({ error: 'No hosts found' });
    }

    const { id: jobId, ee } = newJob();
    
    // Process hosts asynchronously
    process.nextTick(async () => {
      try {
        for (const h of r.rows) {
          const cp = (await q('SELECT path FROM host_container_path WHERE host_id=$1', [h.id])).rows.map(r => r.path);
          const host = { ...h, isRoot: h.is_root, hasContainers: h.has_containers, containerPaths: cp };
          
          await streamFileToHost(host, fileB64, fileName, action, command, (ev) => {
            if (ev.type === 'hostStart') ee.emit('hostStart', ev);
            else if (ev.type === 'log') ee.emit('log', ev);
            else if (ev.type === 'hostEnd') ee.emit('hostEnd', ev);
          });
        }
      } catch (processError) {
        console.error('Error processing file upload:', processError);
        ee.emit('hostEnd', { 
          type: 'hostEnd', 
          host: 'system', 
          ip: '0.0.0.0', 
          ok: false, 
          error: 'Processing error: ' + processError.message,
          durationMs: 0,
          exitCode: null
        });
      }
    });

    res.json({ ok: true, jobId });
  } catch (error) {
    console.error('File upload endpoint error:', error);
    res.status(500).json({ error: 'Internal server error: ' + error.message });
  }
});

// ─── File Upload Streaming Endpoint ──────────────────────────────────────────
app.get('/api/stream/uploadFile', requireAuth, (req, res) => {
  try {
    const jobId = String(req.query.job || '');
    const ee = jobs.get(jobId);
    if (!ee) return res.status(404).end();

    sseInit(res);

    const onStart = (d) => sseSend(res, 'hostStart', d);
    const onLog = (d) => sseSend(res, 'log', d);
    const onEnd = (d) => sseSend(res, 'hostEnd', d);
    const onDone = (_d) => { sseSend(res, 'done', {}); cleanup(); res.end(); };

    ee.on('hostStart', onStart);
    ee.on('log', onLog);
    ee.on('hostEnd', onEnd);

    // simple timer to signal "done" when stream quiets for a bit
    let t; const poke = () => { clearTimeout(t); t = setTimeout(onDone, 1500); };
    ee.on('hostEnd', poke); ee.on('log', poke); poke();

    function cleanup() { ee.off('hostStart', onStart); ee.off('log', onLog); ee.off('hostEnd', onEnd); clearTimeout(t); }
    req.on('close', cleanup);
  } catch (error) {
    console.error('Stream upload file error:', error);
    res.status(500).end();
  }
});

// ─── Streaming: containers (all + single) ────────────────────────────────────
app.get('/api/stream/runContainersAll', requireAuth, async (_req, res) => {
  try {
    const hosts = (await q(
      `SELECT * FROM host WHERE has_containers = true AND id IN (
         SELECT host_id FROM host_container_path GROUP BY host_id HAVING COUNT(*) > 0
       )`
    )).rows;

    sseInit(res);
    if (!hosts.length) { sseSend(res, 'done', { empty: true }); return res.end(); }

    let remaining = hosts.length;
    hosts.forEach(async (h) => {
      try {
        const cp = (await q('SELECT path FROM host_container_path WHERE host_id=$1', [h.id])).rows.map(r => r.path);
        const host = { ...h, isRoot: h.is_root, hasContainers: h.has_containers, containerPaths: cp };
        streamContainersOnHost(host, ev => {
          if (ev.type === 'hostStart') sseSend(res, 'hostStart', ev);
          else if (ev.type === 'log') sseSend(res, 'log', ev);
          else if (ev.type === 'hostEnd') { sseSend(res, 'hostEnd', ev); if (--remaining === 0) { sseSend(res, 'done', {}); res.end(); } }
        });
      } catch (error) {
        console.error('Error processing host containers:', error);
        if (--remaining === 0) { sseSend(res, 'done', {}); res.end(); }
      }
    });
  } catch (error) {
    console.error('Stream run containers all error:', error);
    res.status(500).end();
  }
});

app.get('/api/stream/runContainers/:id', requireAuth, async (req, res) => {
  try {
    const r = await q('SELECT * FROM host WHERE id=$1', [req.params.id]);
    if (!r.rowCount) return res.status(404).end();

    const h = r.rows[0];
    const cp = (await q('SELECT path FROM host_container_path WHERE host_id=$1', [h.id])).rows.map(r => r.path);
    const host = { ...h, isRoot: h.is_root, hasContainers: h.has_containers, containerPaths: cp };

    sseInit(res);
    streamContainersOnHost(host, ev => {
      if (ev.type === 'hostStart') sseSend(res, 'hostStart', ev);
      else if (ev.type === 'log') sseSend(res, 'log', ev);
      else if (ev.type === 'hostEnd') { sseSend(res, 'hostEnd', ev); sseSend(res, 'done', {}); res.end(); }
    });
  } catch (error) {
    console.error('Stream run containers error:', error);
    res.status(500).end();
  }
});

// ─── Global error handler ────────────────────────────────────────────────────
app.use((err, req, res, next) => {
  console.error('Unhandled error:', err);
  res.status(500).json({ error: 'Internal server error' });
});

// ─── 404 handler ─────────────────────────────────────────────────────────────
app.use((req, res) => {
  res.status(404).json({ error: 'Not found' });
});

// ─── Start up (init schema + secret first) ───────────────────────────────────
(async () => {
  try {
    JWT_SECRET = await initDbAndSecret();
    console.log('Postgres schema ready. JWT secret loaded.');
    app.listen(PORT, () => console.log(`ssh-updater listening on http://0.0.0.0:${PORT}`));
  } catch (err) { 
    console.error('Fatal:', err); 
    process.exit(1); 
  }
})();
