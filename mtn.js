/**
 * mtn.js — MTN Congo Enterprise PKI + HSM backend (devops.js parity: HSM/PKI only)
 * -----------------------------------------------------------------------------
 * - Loads .env (PORT, PKCS11 paths, branding)
 * - Serves '/' -> views/pki.ejs (EJS), static /public, runtime /config.js
 * - Health: /api/health, /api/health/detailed
 * - HSM / PKCS#11 (OpenSC) endpoints (same shapes as devops.js):
 *     GET  /api/pkcs11/capabilities
 *     GET  /api/pkcs11/info
 *     GET  /api/pkcs11/mechanisms
 *     GET  /api/pkcs11/sc-hsm-status
 *     GET  /api/pkcs11/objects
 *     POST /api/pkcs11/objects                  (login w/ user PIN)
 *     POST /api/pkcs11/init                     (SC-HSM initialize w/ soPin,userPin)
 *     POST /api/pkcs11/sc-hsm-init             (alias)
 *     POST /api/pkcs11/set-user-pin
 *     POST /api/pkcs11/unblock-user-pin
 *     POST /api/pkcs11/keygen                   (RSA/EC)
 *     GET  /api/pkcs11/pubkey
 * - Canonical HSM status:
 *     GET  /api/pki/hsm/status                  (200, JSON, no-cache)
 *     GET  /api/pki/hsm/status/advanced
 * - PKI (enterprise store on disk):
 *     GET  /api/pki/certificates
 *     POST /api/pki/certificates/generate
 *     POST /api/pki/certificates/:id/revoke
 *     GET  /api/pki/certificates/:id/download
 *     GET  /api/pki/audit
 *     GET  /api/pki/dashboard/stats
 *     GET  /api/pki/signatures
 *     POST /api/pki/documents/sign              (demo sign -> produce file)
 *     POST /api/pki/documents/verify            (OpenSSL CMS verify + demo-stamp)
 *
 * Notes:
 * - No Ollama/AI endpoints here (kept independent).
 * - Graphene-PK11 optional: improves status if available; otherwise OpenSC probes.
 */

'use strict';

const path = require('path');
require('dotenv').config({ path: path.join(__dirname, '.env') });

const express   = require('express');
const fs        = require('fs').promises;
const fssync    = require('fs');
const { execFile, execSync } = require('child_process');
const multer    = require('multer');
const cors      = require('cors');
const crypto    = require('crypto');

let graphene = null;
try { graphene = require('graphene-pk11'); } catch (_) { /* optional */ }

const app  = express();
const PORT = Number(process.env.PORT || 8099);

// Paths
const VIEWS_PATH  = path.join(__dirname, 'views');
const PUBLIC_PATH = path.join(__dirname, 'public');
const DATA_DIR    = path.join(__dirname, 'public', 'data');
const PKI_DIR     = path.join(DATA_DIR, 'pki');
const MTN_DIR     = path.join(DATA_DIR, 'mtn');
const UPLOADS_DIR = path.join(__dirname, 'uploads');
for (const d of [DATA_DIR, PKI_DIR, MTN_DIR, UPLOADS_DIR]) {
  if (!fssync.existsSync(d)) fssync.mkdirSync(d, { recursive: true });
}

// Data files
const CERTS_FILE = path.join(PKI_DIR, 'certificates.json');
const AUDIT_FILE = path.join(PKI_DIR, 'audit.json');
const SIGS_FILE  = path.join(PKI_DIR, 'signatures.json');

// Initialize stores if missing
async function initStores() {
  if (!fssync.existsSync(CERTS_FILE)) {
    await fs.writeFile(CERTS_FILE, JSON.stringify({ total: 0, certificates: [] }, null, 2));
  }
  if (!fssync.existsSync(AUDIT_FILE)) {
    await fs.writeFile(AUDIT_FILE, JSON.stringify({ total: 0, events: [] }, null, 2));
  }
  if (!fssync.existsSync(SIGS_FILE)) {
    await fs.writeFile(SIGS_FILE, JSON.stringify({ total: 0, items: [] }, null, 2));
  }
}
initStores().catch(()=>{});

// Uploads + favicon
const upload = multer({ dest: UPLOADS_DIR });
app.get('/favicon.ico', (_req, res) => res.status(204).end());

// ----------------------------------------------------------------------------
// PKCS#11 (OpenSC) tools & module detection
// ----------------------------------------------------------------------------
const PKCS11_TOOL = process.env.PKCS11_TOOL || 'pkcs11-tool';
const SC_HSM_TOOL = process.env.SC_HSM_TOOL || 'sc-hsm-tool';
const PKCS15_TOOL = process.env.PKCS15_TOOL || 'pkcs15-tool';
const OPENSSL     = process.env.OPENSSL_BIN || 'openssl';

function detectPkcs11ModulePath() {
  if (process.env.PKCS11_MODULE && fssync.existsSync(process.env.PKCS11_MODULE)) return process.env.PKCS11_MODULE;
  const candidates = [
    '/usr/lib/x86_64-linux-gnu/opensc-pkcs11.so',
    '/usr/lib64/opensc-pkcs11.so',
    '/usr/lib/opensc-pkcs11.so',
    '/usr/local/lib/opensc-pkcs11.so',
  ];
  for (const p of candidates) if (fssync.existsSync(p)) return p;
  try {
    const found = execSync('sh -c \'find /usr/lib* -type f -name "opensc-pkcs11.so" 2>/dev/null | head -n1\'', { encoding: 'utf8' }).trim();
    if (found && fssync.existsSync(found)) return found;
  } catch (_) {}
  return candidates[0];
}
function currentModulePath() {
  const p = detectPkcs11ModulePath();
  if (!fssync.existsSync(p)) console.warn('[PKCS11] Module not found at "%s". Set PKCS11_MODULE in .env if needed.', p);
  return p;
}

// Optional graphene init
let grapheneModule = null;
let grapheneInitialized = false;
try {
  const modulePath = currentModulePath();
  if (graphene && fssync.existsSync(modulePath)) {
    grapheneModule = graphene.Module.load(modulePath, 'PKCS11 Module');
    grapheneModule.initialize();
    grapheneInitialized = true;
    console.log('[Graphene] Initialized: %s', modulePath);
  }
} catch (e) {
  console.warn('[Graphene] init failed:', e.message);
}
function finalizeGraphene() {
  try { if (grapheneModule) grapheneModule.finalize(); } catch (_) {}
}

// ----------------------------------------------------------------------------
// Middleware: CORS, parsers, static, views
// ----------------------------------------------------------------------------
const corsOrigins = (process.env.CORS_ORIGIN || '')
  .split(',').map(s => s.trim()).filter(Boolean);
app.use(cors(corsOrigins.length ? { origin: corsOrigins } : {}));

app.use(express.json({ limit: '25mb' }));
app.use(express.urlencoded({ extended: true }));

// No-cache for dynamic
app.set('etag', false);
function noCache(res) {
  res.setHeader('Cache-Control', 'no-store, no-cache, must-revalidate, proxy-revalidate');
  res.setHeader('Pragma', 'no-cache');
  res.setHeader('Expires', '0');
  res.setHeader('Surrogate-Control', 'no-store');
}

// Static & views
app.use(express.static(PUBLIC_PATH, { index: false, fallthrough: true }));
app.set('view engine', 'ejs');
app.set('views', VIEWS_PATH);

// Root  pki.ejs
app.get('/', (_req, res) => { noCache(res); res.render('pki', { error: null, env: process.env }); });

// Runtime config.js (for your front-end)
app.get('/config.js', (_req, res) => {
  noCache(res);
  const cfg = {
    appName: process.env.APP_NAME || 'FIntraX',
    orgName: process.env.ORG_NAME || 'Organisation',
    api: {
      base: process.env.API_BASE || process.env.API_BASE_URL || '',
      pki: {
        get: '/api/pki',
        put: '/api/pki',
        log: '/api/pki/history',
        state: '/api/pki/state',
        certificates: '/api/pki/certificates',
        generateCertificate: '/api/pki/certificates/generate',
        revokeCertificate: '/api/pki/certificates',
        signDocument: '/api/pki/documents/sign',
        verifyDocument: '/api/pki/documents/verify',
        signatures: '/api/pki/signatures',
        tsaConfig: '/api/pki/tsa/config',
        audit: '/api/pki/audit',
        dashboardStats: '/api/pki/dashboard/stats',
        users: '/api/pki/users',
        addUser: '/api/pki/users',
        deleteUser: '/api/pki/users',
        hsmStatus: '/api/pki/hsm/status'
      },
      pkcs11: {
        info: '/api/pkcs11/info',
        capabilities: '/api/pkcs11/capabilities',
        mechanisms: '/api/pkcs11/mechanisms',
        objects: '/api/pkcs11/objects',
        keygen: '/api/pkcs11/keygen',
        pubkey: '/api/pkcs11/pubkey',
        status: '/api/pkcs11/sc-hsm-status',
        init: '/api/pkcs11/init',
        setUserPin: '/api/pkcs11/set-user-pin',
        unblockUserPin: '/api/pkcs11/unblock-user-pin'
      },
      docs: process.env.DOCS_URL || ''
    },
    ui: {
      primary: process.env.UI_PRIMARY || '#0ea5e9',
      headerTitle: process.env.HEADER_TITLE || 'FintraX - PKI Platform',
      footerText: process.env.COPYRIGHT
        ? `© ${new Date().getFullYear()} ${process.env.COPYRIGHT}`
        : `© ${new Date().getFullYear()} FIntraX Congo`,
      sidebarTitle: process.env.SIDEBAR_TITLE || 'FIntraX',
      logoText: process.env.LOGO_TEXT || process.env.APP_NAME || 'FIntraX Congo',
      tagline: process.env.BRAND_TAGLINE || ''
    }
  };
  res.type('application/javascript; charset=utf-8')
     .send(`window.APP_CONFIG = ${JSON.stringify(cfg, null, 2)};`);
});

// ----------------------------------------------------------------------------
// Helpers / persistence
// ----------------------------------------------------------------------------
async function loadJSON(file, fallback) {
  try { return JSON.parse(await fs.readFile(file, 'utf8')); }
  catch { return fallback; }
}
async function saveJSON(file, data) {
  await fs.writeFile(file, JSON.stringify(data, null, 2), 'utf8');
}
function genId()    { return crypto.randomBytes(12).toString('hex'); }
function genSerial(){ return crypto.randomBytes(8).toString('hex').toUpperCase(); }
function addAudit(event) {
  (async () => {
    const audit = await loadJSON(AUDIT_FILE, { total: 0, events: [] });
    audit.events.unshift({ id: genId(), ts: new Date().toISOString(), ...event });
    audit.total = audit.events.length;
    if (audit.events.length > 5000) audit.events.length = 5000;
    await saveJSON(AUDIT_FILE, audit);
  })().catch(()=>{});
}

function execFileAsync(bin, args, opts = {}) {
  return new Promise((resolve) => {
    execFile(bin, args, { timeout: 180000, encoding: 'utf8', ...opts }, (err, stdout, stderr) => {
      resolve({ ok: !err, stdout: stdout || '', stderr: stderr || (err ? err.message : '') });
    });
  });
}
function execFileAsyncBuffer(bin, args, opts = {}) {
  return new Promise((resolve) => {
    execFile(bin, args, { timeout: 180000, encoding: 'buffer', ...opts }, (err, stdout, stderr) => {
      const stderrStr = Buffer.isBuffer(stderr) ? stderr.toString('utf8') : (stderr || (err ? err.message : ''));
      resolve({ ok: !err, stdout: stdout || Buffer.alloc(0), stderr: stderrStr });
    });
  });
}
function ensureModuleOr500(res) {
  const modulePath = currentModulePath();
  if (!fssync.existsSync(modulePath)) {
    res.status(500).json({ ok: false, error: `PKCS11 module not found at ${modulePath}. Install opensc or set PKCS11_MODULE.` });
    return null;
  }
  return modulePath;
}
function mapPkcs11Error(stderr) {
  if (/CKR_DATA_LEN_RANGE/i.test(stderr)) return 'Bad PIN length (User 6-15; SO 8 digits for SC-HSM)';
  if (/CKR_PIN_INCORRECT/i.test(stderr)) return 'Incorrect PIN.';
  if (/CKR_PIN_LOCKED/i.test(stderr)) return 'PIN is locked.';
  if (/CKR_USER_NOT_LOGGED_IN/i.test(stderr)) return 'Login required.';
  if (/CKR_DEVICE_MEMORY/i.test(stderr)) return 'Not enough space on token.';
  if (/CKR_ATTRIBUTE_VALUE_INVALID/i.test(stderr)) return 'Invalid attribute.';
  if (/CKR_KEY_SIZE_RANGE/i.test(stderr)) return 'Unsupported key size.';
  if (/CKR_GENERAL_ERROR/i.test(stderr)) return 'Token rejected operation.';
  return null;
}

// ----------------------------------------------------------------------------
// HSM status helpers
// ----------------------------------------------------------------------------
function parseTokenHints(text) {
  const t = String(text || '');
  const tokenLabel = (t.match(/token label\s*:\s*(.+)/i)?.[1] || '').trim();
  const serial     = (t.match(/serial (?:num|number)\s*:\s*([A-Z0-9]+)/i)?.[1] || '').trim();
  const present =
    /SmartCard-HSM/i.test(t) ||
    /token label\s*:/i.test(t) ||
    /PIN initialized/i.test(t) ||
    /token initialized/i.test(t) ||
    /PKCS#15/i.test(t) ||
    /slots?\s*:\s*\d+/i.test(t);
  return { tokenLabel, serial, present };
}
async function computeHsmSnapshot() {
  const modulePath = currentModulePath();
  const moduleExists = fssync.existsSync(modulePath);
  const snap = {
    ok: true,
    connected: false,
    cardPresent: false,
    tokenPresent: false,
    modulePath,
    moduleExists,
    grapheneInitialized,
    tokenLabel: '',
    serial: '',
    info: '',
    timestamp: new Date().toISOString()
  };

  // Graphene probe (optional)
  try {
    if (grapheneModule) {
      const slots = grapheneModule.getSlots(true);
      snap.connected = moduleExists && grapheneInitialized && Array.isArray(slots) && slots.length > 0;
      snap.cardPresent = slots.some(s => { try { return !!s.getToken(); } catch { return false; } });
      snap.tokenPresent = snap.cardPresent;
    }
  } catch (e) {
    snap.ok = false;
    snap.error = e.message;
  }

  // OpenSC textual probe
  try {
    const info = await execFileAsync(PKCS11_TOOL, ['--module', modulePath, '-L']);
    const sch  = await execFileAsync(SC_HSM_TOOL, ['-S']);
    snap.info = [info.stdout, sch.stdout].filter(Boolean).join('\n').trim();

    const hints = parseTokenHints(snap.info);
    if (hints.present) {
      snap.connected = true;
      snap.cardPresent = true;
      snap.tokenPresent = true;
    }
    snap.tokenLabel = hints.tokenLabel || snap.tokenLabel;
    snap.serial     = hints.serial     || snap.serial;
  } catch (_) {}

  return snap;
}

// ----------------------------------------------------------------------------
// Health
// ----------------------------------------------------------------------------
app.get('/api/health', async (_req, res) => {
  noCache(res);
  res.json({ ok: true, deps: { graphene_pkcs11: grapheneInitialized } });
});
async function checkHSMStatus() {
  try {
    const modulePath = currentModulePath();
    const moduleExists = fssync.existsSync(modulePath);
    if (!moduleExists) return { status: 'module_not_found', message: 'PKCS11 module not found' };
    if (!grapheneModule) return { status: 'graphene_not_initialized', message: 'Graphene not initialized (optional)' };
    const slots = grapheneModule.getSlots(true);
    const tokenPresent = slots.some(s => { try { return !!s.getToken(); } catch { return false; } });
    return { status: 'ok', moduleExists: true, grapheneInitialized: true, tokens: slots.length, tokenPresent, timestamp: new Date().toISOString() };
  } catch (e) {
    return { status: 'error', message: e.message, timestamp: new Date().toISOString() };
  }
}
app.get('/api/health/detailed', async (_req, res) => {
  noCache(res);
  const hsmStatus = await checkHSMStatus();
  res.json({ ok: true, timestamp: new Date().toISOString(), hsm: hsmStatus, system: { node: process.version, platform: process.platform, uptime: process.uptime() } });
});
app.get('/api/pki/hsm/status/advanced', async (_req, res) => {
  noCache(res);
  const status = await checkHSMStatus();
  res.status(status.status === 'ok' ? 200 : 500).json({ ok: status.status === 'ok', ...status });
});

// Canonical HSM status (200/no-cache)
app.get('/api/pki/hsm/status', async (_req, res) => {
  noCache(res);
  const snap = await computeHsmSnapshot();
  const status = snap.cardPresent ? 'connected' : (snap.connected ? 'pending' : 'disconnected');
  res.status(200).json({
    ok: true,
    status,
    connected: !!snap.connected,
    cardPresent: !!snap.cardPresent,
    tokenPresent: !!snap.tokenPresent,
    tokenLabel: snap.tokenLabel || (snap.cardPresent ? 'SmartCard-HSM (UserPIN)' : ''),
    serial: snap.serial || null,
    info: snap.info,
    timestamp: snap.timestamp
  });
});

// ----------------------------------------------------------------------------
// PKCS#11 Diagnostics (OpenSC parity)
// ----------------------------------------------------------------------------
app.get('/api/pkcs11/capabilities', async (_req, res) => {
  noCache(res);
  const modulePath = currentModulePath();
  const moduleExists = fssync.existsSync(modulePath);
  const pk11 = await execFileAsync(PKCS11_TOOL, ['--version']);
  const sch  = await execFileAsync(SC_HSM_TOOL, ['--version']);
  const pk15 = await execFileAsync(PKCS15_TOOL, ['--version']);
  res.json({
    modulePath,
    moduleExists,
    pkcs11Tool: { ok: pk11.ok, version: (pk11.stdout || pk11.stderr).trim() },
    scHsmTool: { ok: sch.ok,  version: (sch.stdout  || sch.stderr ).trim() },
    pkcs15Tool: { ok: pk15.ok, version: (pk15.stdout || pk15.stderr).trim() },
  });
});
app.get('/api/pkcs11/info', async (_req, res) => {
  noCache(res);
  const modulePath = ensureModuleOr500(res); if (!modulePath) return;
  const out = await execFileAsync(PKCS11_TOOL, ['--module', modulePath, '-L']);
  if (!out.ok) return res.status(500).json({ ok: false, error: out.stderr });
  res.json({ ok: true, stdout: out.stdout });
});
app.get('/api/pkcs11/mechanisms', async (_req, res) => {
  noCache(res);
  const modulePath = ensureModuleOr500(res); if (!modulePath) return;
  const out = await execFileAsync(PKCS11_TOOL, ['--module', modulePath, '-M']);
  if (!out.ok) return res.status(500).json({ ok: false, error: out.stderr });
  res.json({ ok: true, stdout: out.stdout });
});
app.get('/api/pkcs11/sc-hsm-status', async (_req, res) => {
  noCache(res);
  const modulePath = ensureModuleOr500(res); if (!modulePath) return;
  const info = await execFileAsync(PKCS11_TOOL, ['--module', modulePath, '-L']);
  const sch  = await execFileAsync(SC_HSM_TOOL, ['-S']);
  if (!info.ok && !sch.ok) return res.status(500).json({ ok: false, error: (info.stderr || sch.stderr || 'No status available') });
  res.status(200).json({ ok: true, stdout: [info.stdout, sch.stdout].filter(Boolean).join('\n') });
});
app.get('/api/pkcs11/objects', async (req, res) => {
  noCache(res);
  const modulePath = ensureModuleOr500(res); if (!modulePath) return;
  const { slot } = req.query || {};
  const args = ['--module', modulePath];
  if (slot !== undefined) args.push('--slot', String(slot));
  args.push('-O');
  const out = await execFileAsync(PKCS11_TOOL, args);
  if (!out.ok) return res.status(500).json({ ok: false, error: out.stderr });
  res.json({ ok: true, stdout: out.stdout });
});
app.post('/api/pkcs11/objects', async (req, res) => {
  noCache(res);
  const modulePath = ensureModuleOr500(res); if (!modulePath) return;
  const { pin, slot } = req.body || {};
  if (!/^[0-9]{6,15}$/.test(String(pin || ''))) return res.status(400).json({ ok: false, error: 'pin must be 6-15 digits' });
  const args = ['--module', modulePath];
  if (slot !== undefined) args.push('--slot', String(slot));
  args.push('--login', '--login-type', 'user', '--pin', String(pin), '-O');
  const out = await execFileAsync(PKCS11_TOOL, args);
  if (!out.ok) return res.status(500).json({ ok: false, error: mapPkcs11Error(out.stderr) || out.stderr, stdout: out.stdout });
  res.json({ ok: true, stdout: out.stdout });
});
app.post('/api/pkcs11/init', async (req, res) => {
  noCache(res);
  const soPin  = req.body?.soPin  ?? process.env.SC_HSM_SO_PIN;
  const userPin= req.body?.userPin?? process.env.SC_HSM_USER_PIN;
  if (!/^\d{8}$/.test(String(soPin || '')))      return res.status(400).json({ ok: false, error: 'soPin must be exactly 8 digits (SC-HSM)' });
  if (!/^\d{6,15}$/.test(String(userPin || ''))) return res.status(400).json({ ok: false, error: 'userPin must be 6-15 digits' });
  const out = await execFileAsync(SC_HSM_TOOL, ['--initialize', '--so-pin', String(soPin), '--pin', String(userPin)]);
  if (!out.ok) return res.status(500).json({ ok: false, error: mapPkcs11Error(out.stderr) || out.stderr, stdout: out.stdout });
  res.json({ ok: true, stdout: out.stdout || 'SC-HSM initialized' });
});
app.post('/api/pkcs11/sc-hsm-init', async (req, res) => {
  noCache(res);
  const { soPin, userPin } = req.body || {};
  if (!/^\d{8}$/.test(String(soPin || '')))      return res.status(400).json({ ok: false, error: 'soPin must be exactly 8 digits (SC-HSM)' });
  if (!/^\d{6,15}$/.test(String(userPin || ''))) return res.status(400).json({ ok: false, error: 'userPin must be 6-15 digits' });
  const out = await execFileAsync(SC_HSM_TOOL, ['--initialize', '--so-pin', String(soPin), '--pin', String(userPin)]);
  if (!out.ok) return res.status(500).json({ ok: false, error: mapPkcs11Error(out.stderr) || out.stderr });
  res.json({ ok: true, stdout: out.stdout || 'SC-HSM initialized' });
});
app.post('/api/pkcs11/set-user-pin', async (req, res) => {
  noCache(res);
  const { oldPin, newPin } = req.body || {};
  if (!/^\d{6,15}$/.test(String(newPin || ''))) return res.status(400).json({ ok: false, error: 'newPin must be 6-15 digits' });
  const modulePath = ensureModuleOr500(res); if (!modulePath) return;

  const tryUser = await execFileAsync(PKCS11_TOOL, ['--module', modulePath, '--pin', String(oldPin || ''), '--change-pin', '--new-pin', String(newPin)]);
  if (tryUser.ok) return res.json({ ok: true, mode: 'user', message: 'PIN changed (user)' });

  const trySO = await execFileAsync(PKCS11_TOOL, ['--module', modulePath, '--so-pin', String(oldPin || ''), '--change-pin', '--new-pin', String(newPin)]);
  if (trySO.ok) return res.json({ ok: true, mode: 'so', message: 'PIN changed (SO)' });

  res.status(500).json({ ok: false, error: mapPkcs11Error(trySO.stderr || tryUser.stderr) || (trySO.stderr || tryUser.stderr) });
});
app.post('/api/pkcs11/unblock-user-pin', async (req, res) => {
  noCache(res);
  const { soPin, newUserPin } = req.body || {};
  if (!/^\d{8}$/.test(String(soPin || ''))) return res.status(400).json({ ok: false, error: 'soPin must be exactly 8 digits (SC-HSM)' });
  if (!/^\d{6,15}$/.test(String(newUserPin || ''))) return res.status(400).json({ ok: false, error: 'newUserPin must be 6-15 digits' });
  const modulePath = ensureModuleOr500(res); if (!modulePath) return;
  const out = await execFileAsync(SC_HSM_TOOL, ['--so-pin', String(soPin), '--pin', String(newUserPin)]);
  if (!out.ok) return res.status(500).json({ ok: false, error: mapPkcs11Error(out.stderr) || out.stderr });
  res.json({ ok: true, stdout: out.stdout || 'User PIN unblocked' });
});
app.post('/api/pkcs11/keygen', async (req, res) => {
  noCache(res);
  const modulePath = ensureModuleOr500(res); if (!modulePath) return;

  const pin = String(req.body?.pin || '');
  if (!/^\d{6,15}$/.test(pin)) return res.status(400).json({ ok: false, error: 'pin must be 6-15 digits' });

  const type  = String(req.body?.type || 'rsa').toLowerCase();
  const id    = String(req.body?.id || '01');
  const label = String(req.body?.label || `FX-${type.toUpperCase()}-${id}`);

  let keyTypeArg = '';
  if (type === 'rsa') {
    const bits = Number(req.body?.bits || 2048);
    if (![1024, 2048, 3072, 4096].includes(bits)) return res.status(400).json({ ok: false, error: 'Unsupported RSA size. Use 1024, 2048, 3072, 4096.' });
    keyTypeArg = `rsa:${bits}`;
  } else if (type === 'ec' || type === 'ecdsa') {
    const curve = String(req.body?.curve || req.body?.param || 'P-256').toUpperCase();
    const map = { 'P-256': 'secp256r1', 'P-384': 'secp384r1', 'P-521': 'secp521r1' };
    keyTypeArg = `EC:${map[curve] || curve}`;
  } else {
    return res.status(400).json({ ok: false, error: 'type must be "rsa" or "ec"' });
  }

  const args = ['--module', modulePath, '--login', '--login-type', 'user', '--pin', pin, '--keypairgen', '--key-type', keyTypeArg, '--label', label, '--id', id];
  const out = await execFileAsync(PKCS11_TOOL, args);
  if (!out.ok) return res.status(500).json({ ok: false, error: mapPkcs11Error(out.stderr) || out.stderr, stdout: out.stdout });

  res.json({ ok: true, stdout: out.stdout || 'Key pair generated', key: { type, id, label, keyType: keyTypeArg } });
});
app.get('/api/pkcs11/pubkey', async (req, res) => {
  noCache(res);
  const modulePath = ensureModuleOr500(res); if (!modulePath) return;
  const id  = String(req.query?.id || '').trim();
  const pin = String(req.query?.pin || '').trim();
  if (!id) return res.status(400).json({ ok: false, error: 'id is required' });
  if (!/^\d{6,15}$/.test(pin)) return res.status(400).json({ ok: false, error: 'pin must be 6-15 digits' });

  const args = ['--module', modulePath, '--login', '--login-type', 'user', '--pin', pin, '--read-object', '--type', 'pubkey', '--id', id, '--output-file', '/proc/self/fd/1'];
  const out = await execFileAsyncBuffer(PKCS11_TOOL, args);
  if (!out.ok) return res.status(500).json({ ok: false, error: mapPkcs11Error(out.stderr) || out.stderr });

  const derB64 = Buffer.isBuffer(out.stdout) ? out.stdout.toString('base64') : Buffer.from(String(out.stdout || ''), 'binary').toString('base64');
  res.json({ ok: true, der_base64: derB64 });
});

// ----------------------------------------------------------------------------
// Minimal PKI: certificates + audit + dashboard
// ----------------------------------------------------------------------------
let CERT_CACHE = null;
async function getCertStore() {
  if (!CERT_CACHE) CERT_CACHE = await loadJSON(CERTS_FILE, { total: 0, certificates: [] });
  return CERT_CACHE;
}
async function persistCertStore() {
  if (!CERT_CACHE) return;
  CERT_CACHE.total = CERT_CACHE.certificates.length;
  await saveJSON(CERTS_FILE, CERT_CACHE);
}

app.get('/api/pki/certificates', async (_req, res) => {
  noCache(res);
  const store = await getCertStore();
  res.json({ ok: true, total: store.certificates.length, certificates: store.certificates });
});
app.post('/api/pki/certificates/generate', async (req, res) => {
  noCache(res);
  try {
    const body = req.body || {};
    const id   = genId();
    const now  = new Date();
    const validityDays = Number(body.validityDays || 365);
    const expires = new Date(now.getTime() + validityDays * 86400000);

    const subject = body.subject || {};
    const dn = [
      subject.CN && `CN=${subject.CN}`,
      subject.O  && `O=${subject.O}`,
      subject.OU && `OU=${subject.OU}`,
      subject.C  && `C=${subject.C}`,
      subject.L  && `L=${subject.L}`,
      subject.email && `emailAddress=${subject.email}`
    ].filter(Boolean).join(', ');

    const cert = {
      id,
      subject: dn || (subject.CN ? `CN=${subject.CN}` : 'CN=Unknown'),
      issuer: process.env.PKI_ISSUER || 'CN=FIntraX Demo CA, O=FIntraX Congo, C=CD',
      serial: genSerial(),
      issued: now.toISOString(),
      expires: expires.toISOString(),
      status: 'valid',
      type: body.type || 'server',
      keyType:  (body.key && body.key.algorithm) || 'RSA',
      keySize:  (body.key && body.key.param)     || '2048',
      algorithm: ((body.key && body.key.algorithm) || 'RSA') + '-' + ((body.key && body.key.param) || '2048'),
      email: subject.email || null
    };

    const store = await getCertStore();
    store.certificates.unshift(cert);
    await persistCertStore();
    addAudit({ type: 'certificate', action: 'generate', subject: cert.subject, serial: cert.serial, status: 'success' });

    res.json({ ok: true, certificate: cert });
  } catch (e) {
    addAudit({ type: 'certificate', action: 'generate', status: 'error', error: String(e) });
    res.status(500).json({ ok: false, error: String(e) });
  }
});
app.post('/api/pki/certificates/:id/revoke', async (req, res) => {
  noCache(res);
  try {
    const { id } = req.params;
    const reason = (req.body && req.body.reason) || 'unspecified';
    const store = await getCertStore();
    const idx = store.certificates.findIndex(c => c.id === id);
    if (idx === -1) return res.status(404).json({ ok: false, error: 'Certificate not found' });
    const cert = store.certificates[idx];
    cert.status = 'revoked';
    cert.revocationDate = new Date().toISOString();
    cert.revocationReason = reason;
    await persistCertStore();
    addAudit({ type: 'certificate', action: 'revoke', serial: cert.serial, reason, status: 'success' });
    res.json({ ok: true, certificate: cert });
  } catch (e) {
    addAudit({ type: 'certificate', action: 'revoke', status: 'error', error: String(e) });
    res.status(500).json({ ok: false, error: String(e) });
  }
});
app.get('/api/pki/certificates/:id/download', async (req, res) => {
  noCache(res);
  const { id } = req.params;
  const store = await getCertStore();
  const cert  = store.certificates.find(c => c.id === id);
  if (!cert) return res.status(404).json({ ok: false, error: 'Certificate not found' });
  const pem = [
    '-----BEGIN CERTIFICATE-----',
    Buffer.from(`DEMO CERT ${cert.serial}`).toString('base64'),
    '-----END CERTIFICATE-----'
  ].join('\n');
  res.setHeader('Content-Disposition', `attachment; filename="certificate-${cert.serial}.pem"`);
  res.type('application/x-pem-file').send(pem);
});

app.get('/api/pki/audit', async (_req, res) => {
  noCache(res);
  const audit = await loadJSON(AUDIT_FILE, { total: 0, events: [] });
  res.status(200).json({ ok: true, ...audit });
});
app.get('/api/pki/signatures', async (_req, res) => {
  noCache(res);
  const store = await loadJSON(SIGS_FILE, { total: 0, items: [] });
  res.json({ ok: true, total: store.items.length, items: store.items, signatures: store.items });
});
app.get('/downloads/signatures/:id', async (req, res) => {
  const sigs = await loadJSON(SIGS_FILE, { total: 0, items: [] });
  const item = sigs.items.find(s => s.id === req.params.id);
  if (!item || !item.outputPath) return res.status(404).json({ ok: false, error: 'Signed file not found' });
  if (!fssync.existsSync(item.outputPath)) return res.status(404).json({ ok: false, error: 'File missing on disk' });
  res.download(item.outputPath, item.outputName || path.basename(item.outputPath));
});
app.get('/api/pki/dashboard/stats', async (_req, res) => {
  noCache(res);
  const store = await getCertStore();
  const sigs  = await loadJSON(SIGS_FILE, { total: 0, items: [] });
  const now = Date.now();
  const activeCertificates = store.certificates.filter(c => c.status === 'valid').length;
  const expiringSoon = store.certificates.filter(c => {
    if (c.status !== 'valid') return false;
    const exp = new Date(c.expires).getTime();
    const days = Math.ceil((exp - now) / 86400000);
    return days > 0 && days <= 30;
  }).length;
  const signaturesThisMonth = sigs.items.filter(s => new Date(s.ts).getMonth() === new Date().getMonth()).length;
  const signaturesToday      = sigs.items.filter(s => new Date(s.ts).toDateString() === new Date().toDateString()).length;

  res.status(200).json({
    ok: true,
    activeCertificates,
    expiringSoon,
    signaturesThisMonth,
    signaturesToday,
    timestampsCount: 0,
    lastUpdate: new Date().toISOString()
  });
});

// Demo document signing (appends a visible stamp; mirrors devops.js)
app.post('/api/pki/documents/sign', upload.single('document'), async (req, res) => {
  noCache(res);
  try {
    if (!req.file) return res.status(400).json({ ok: false, error: 'No document uploaded' });

    const id = genId();
    const nowIso = new Date().toISOString();
    const originalName = req.file.originalname || 'document.bin';
    const ext = path.extname(originalName) || '';
    const outputName = `signed-${id}${ext || '.bin'}`;
    const outputPath = path.join(MTN_DIR, outputName);

    const stamp = Buffer.from(`\n--- SIGNATURE STAMP ---\n${JSON.stringify({
      id, when: nowIso,
      opts: {
        includeTimestamp: req.body?.includeTimestamp === 'true' || req.body?.includeTimestamp === true,
        visibleSignature: req.body?.visibleSignature === 'true' || req.body?.visibleSignature === true,
        padesSignature: req.body?.padesSignature === 'true' || req.body?.padesSignature === true,
        certificateId: req.body?.certificateId || null
      }
    })}\n`);
    await fs.copyFile(req.file.path, outputPath);
    await fs.appendFile(outputPath, stamp);

    const sigStore = await loadJSON(SIGS_FILE, { total: 0, items: [] });
    sigStore.items.unshift({
      id,
      ts: nowIso,
      document: originalName,
      inputSize: req.file.size,
      mimeType: req.file.mimetype || 'application/octet-stream',
      status: 'valid',
      algorithm: req.body?.algorithm || 'RSA-2048',
      certificateId: req.body?.certificateId || null,
      includeTimestamp: req.body?.includeTimestamp === 'true' || req.body?.includeTimestamp === true,
      visibleSignature: req.body?.visibleSignature === 'true' || req.body?.visibleSignature === true,
      padesSignature: req.body?.padesSignature === 'true' || req.body?.padesSignature === true,
      outputPath,
      outputName,
      downloadUrl: `/downloads/signatures/${id}`
    });
    sigStore.total = sigStore.items.length;
    await saveJSON(SIGS_FILE, sigStore);

    addAudit({ type: 'signature', action: 'sign', file: originalName, status: 'success', id });

    res.json({ ok: true, signature: sigStore.items[0], downloadUrl: sigStore.items[0].downloadUrl });
  } catch (e) {
    addAudit({ type: 'signature', action: 'sign', status: 'error', error: String(e) });
    res.status(500).json({ ok: false, error: String(e) });
  } finally {
    try { if (req.file?.path) await fs.unlink(req.file.path); } catch {}
  }
});

// CMS/PKCS#7 verification (OpenSSL) + demo-stamp fallback
app.post('/api/pki/documents/verify', upload.single('document'), async (req, res) => {
  noCache(res);
  try {
    if (!req.file) return res.status(400).json({ ok: false, error: 'No document uploaded' });

    const filePath = req.file.path;
    const fileName = req.file.originalname || 'document';
    const ext = (fileName.split('.').pop() || '').toLowerCase();

    const isCms = ['p7m', 'p7s', 'p7b'].includes(ext) ||
                  /application\/(pkcs7|x-pkcs7|cms)/i.test(req.file.mimetype || '');

    const makeResult = (valid, reason, extra = {}) => ({
      ok: true,
      verification: {
        valid: !!valid,
        reason: reason || undefined,
        chainTrusted: extra.chainTrusted ?? null,
        algorithm: extra.algorithm || null,
        timestamp: extra.timestamp || null,
        signer: extra.signer || { subject: null, issuer: null, serial: null }
      }
    });

    if (isCms) {
      const caFile = process.env.VERIFY_CAFILE;
      const smimeArgs = ['smime', '-verify', '-in', filePath];
      if (!caFile) smimeArgs.push('-noverify');

      const v = await execFileAsync(OPENSSL, smimeArgs);
      const verified = v.ok && /Verification successful/i.test((v.stdout || v.stderr || ''));

      // Extract signer info
      let signerInfo = { subject: null, issuer: null, serial: null };
      try {
        const pk7out = await execFileAsync(OPENSSL, ['smime', '-pk7out', '-in', filePath]);
        if (pk7out.ok) {
          const certDump = await execFileAsync(OPENSSL, ['pkcs7', '-print_certs', '-text', '-noout'], { input: pk7out.stdout });
          const lines = (certDump.stdout || '').split('\n');
          const subj = lines.find(l => /Subject:/i.test(l)) || '';
          const iss  = lines.find(l => /Issuer:/i.test(l))  || '';
          const ser  = lines.find(l => /Serial Number:/i.test(l)) || '';
          signerInfo = {
            subject: subj.replace(/^.*Subject:\s*/i,'').trim() || null,
            issuer:  iss.replace(/^.*Issuer:\s*/i,'').trim()  || null,
            serial:  ser.replace(/^.*Serial Number:\s*/i,'').trim() || null
          };
        }
      } catch (_) {}

      const algoMatch = (v.stderr || v.stdout || '').match(/(rsa|ecdsa|sha\d+|sha-\d+)/i);
      const algorithm = algoMatch ? algoMatch[1].toUpperCase() : null;

      if (verified) return res.json(makeResult(true, null, { signer: signerInfo, chainTrusted: !!caFile, algorithm }));
      return res.json(makeResult(false, v.stderr || 'Verification failed', { signer: signerInfo, chainTrusted: !!caFile, algorithm }));
    }

    // Demo stamp fallback
    const buf = await fs.readFile(filePath);
    const txt = buf.toString('utf8');
    const marker = '--- SIGNATURE STAMP ---';
    if (txt.includes(marker)) {
      const m = txt.lastIndexOf(marker);
      let info = {};
      try {
        const jsonPart = txt.slice(m + marker.length).trim();
        info = JSON.parse(jsonPart);
      } catch (_) {}
      return res.json({
        ok: true,
        verification: {
          valid: true,
          chainTrusted: false,
          algorithm: info?.opts?.padesSignature ? 'PAdES' : (info?.algorithm || 'DEMO'),
          timestamp: info?.when || null,
          signer: { subject: 'Demo signer', issuer: 'Local demo', serial: null }
        }
      });
    }

    return res.json({
      ok: true,
      verification: { valid: false, reason: 'Unknown/unsupported format', chainTrusted: null, algorithm: null, timestamp: null, signer: { subject: null, issuer: null, serial: null } }
    });

  } catch (e) {
    addAudit({ type: 'verification', action: 'verify', status: 'error', error: String(e) });
    res.status(500).json({ ok: false, error: String(e) });
  } finally {
    try { if (req.file?.path) await fs.unlink(req.file.path); } catch {}
  }
});

// ----------------------------------------------------------------------------
// 404 for unknown API, generic error handler
// ----------------------------------------------------------------------------
app.use((req, res, next) => {
  if (req.url.startsWith('/api/')) {
    return res.status(404).json({ ok: false, error: `Endpoint not found: ${req.method} ${req.url}` });
  }
  next();
});
app.use((err, _req, res, _next) => {
  console.error('Unhandled server error:', err.stack || err.message);
  if (!res.headersSent) res.status(500).json({ error: 'Unexpected server error', message: err.message });
});

// ----------------------------------------------------------------------------
// Boot
// ----------------------------------------------------------------------------
const server = app.listen(PORT, () => {
  console.log('\n MTN Congo PKI/HSM server started');
  console.log(`     Port: ${PORT}`);
  console.log(`     URL:  http://localhost:${PORT}`);
  console.log(`     Graphene PKCS11: ${grapheneInitialized ? 'Initialized' : 'Not initialized'}`);
  console.log('\n Key endpoints:');
  console.log('     GET  /api/health');
  console.log('     GET  /api/health/detailed');
  console.log('     GET  /api/pkcs11/capabilities');
  console.log('     GET  /api/pkcs11/sc-hsm-status            (200, no-cache)');
  console.log('     GET  /api/pki/hsm/status                  (200, no-cache)');
  console.log('     GET  /api/pkcs11/mechanisms');
  console.log('     GET  /api/pkcs11/objects');
  console.log('     POST /api/pkcs11/init                     (init via soPin/userPin)');
  console.log('     POST /api/pkcs11/keygen                   (RSA/EC)');
  console.log('     GET  /api/pkcs11/pubkey?id=..&pin=..      (DERbase64)');
  console.log('     GET  /api/pki/certificates                (200, no-cache)');
  console.log('     POST /api/pki/certificates/generate       (200)');
  console.log('     POST /api/pki/certificates/:id/revoke     (200)');
  console.log('     GET  /api/pki/dashboard/stats             (200, no-cache)');
  console.log('     GET  /api/pki/signatures                  (200, no-cache)');
  console.log('     POST /api/pki/documents/sign              (demo 200)');
  console.log('     POST /api/pki/documents/verify            (OpenSSL CMS verify)');
  console.log('     GET  /downloads/signatures/:id            (200)');
});
function shutdown() { try { finalizeGraphene(); } catch (_) {} process.exit(0); }
process.on('SIGINT', shutdown);
process.on('SIGTERM', shutdown);
