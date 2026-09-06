// Ndu backend — a minimal, zero-dependency starting point.
//
// Built with only Node's built-in modules (no npm install required) so it
// runs anywhere, including Termux with no internet access to fetch
// packages. Data is stored in a JSON file — fine for a prototype/demo, but
// must be swapped for a real database before this handles real public
// data at scale (see README.md "Next steps").
//
// SECURITY LAYERS IN THIS FILE:
//   1. Admin key required to change a report's status (PATCH)
//   2. Rate limiting on report submissions (per IP)
//   3. Input length limits + stripped HTML tags (prevents stored XSS)
//   4. Security response headers on every request
//   5. Constant-time admin key comparison (prevents timing attacks)
//   6. Request body size cap (already present, kept)
//   7. Path traversal protection on static files (already present, kept)

const http = require('http');
const fs = require('fs');
const path = require('path');
const crypto = require('crypto');
const url = require('url');

const PORT = process.env.PORT || 3000;
const DATA_FILE = path.join(__dirname, 'data', 'reports.json');
const PUBLIC_DIR = path.join(__dirname, 'public');

// Set this as a real environment variable in Render (and locally via
// `export ADMIN_KEY=...` before running) — never hard-code a real secret
// here. If it's not set, moderation actions are disabled entirely rather
// than left open, which is the safer default.
const ADMIN_KEY = process.env.ADMIN_KEY || null;

const CATEGORIES = [
  'Healthcare',
  'Agriculture',
  'Education & skills',
  'Employment access',
  'Financial inclusion',
  'Housing & infrastructure',
  'Transportation',
  'Digital access',
];

const MAX_LOCATION_LEN = 120;
const MAX_DESCRIPTION_LEN = 1000;

// ---------- tiny JSON-file "database" ----------

function readReports() {
  try {
    const raw = fs.readFileSync(DATA_FILE, 'utf8');
    return JSON.parse(raw);
  } catch (e) {
    return [];
  }
}

function writeReports(reports) {
  fs.writeFileSync(DATA_FILE, JSON.stringify(reports, null, 2));
}

// ---------- security helpers ----------

// Strip any HTML tags from user input before storing. This is a
// belt-and-suspenders measure: the current frontend pages already use
// textContent (safe), but this protects any future page that might render
// report text as HTML.
function stripTags(str) {
  return String(str).replace(/<[^>]*>/g, '');
}

function clamp(str, maxLen) {
  return String(str).slice(0, maxLen);
}

function sanitizeText(str, maxLen) {
  return clamp(stripTags(str), maxLen).trim();
}

// Constant-time comparison so an attacker can't guess the admin key one
// character at a time by measuring response speed.
function safeEqual(a, b) {
  const bufA = Buffer.from(String(a));
  const bufB = Buffer.from(String(b));
  if (bufA.length !== bufB.length) return false;
  return crypto.timingSafeEqual(bufA, bufB);
}

function isAuthorized(req) {
  if (!ADMIN_KEY) return false; // no key configured = moderation stays locked
  const provided = req.headers['x-admin-key'];
  if (!provided) return false;
  return safeEqual(provided, ADMIN_KEY);
}

// ---------- simple in-memory rate limiter ----------
// Per-IP limit on report submissions. Resets on redeploy (fine for a
// prototype). Not a substitute for a real rate-limiting layer (e.g. a CDN
// or reverse proxy) once this handles real traffic — see README.

const RATE_LIMIT_WINDOW_MS = 15 * 60 * 1000; // 15 minutes
const RATE_LIMIT_MAX = 5; // max reports per IP per window
const rateLimitMap = new Map(); // ip -> { count, resetAt }

function checkRateLimit(ip) {
  const now = Date.now();
  const entry = rateLimitMap.get(ip);
  if (!entry || now > entry.resetAt) {
    rateLimitMap.set(ip, { count: 1, resetAt: now + RATE_LIMIT_WINDOW_MS });
    return true;
  }
  if (entry.count >= RATE_LIMIT_MAX) return false;
  entry.count++;
  return true;
}

function getClientIp(req) {
  // Render (and most hosts) sit behind a proxy — the real client IP shows
  // up in this header. Falls back to the raw socket address locally.
  const forwarded = req.headers['x-forwarded-for'];
  if (forwarded) return forwarded.split(',')[0].trim();
  return req.socket.remoteAddress || 'unknown';
}

// ---------- response helpers ----------

function securityHeaders() {
  return {
    'X-Content-Type-Options': 'nosniff',
    'X-Frame-Options': 'DENY',
    'Referrer-Policy': 'no-referrer',
    'Content-Security-Policy': "default-src 'self'; style-src 'self' 'unsafe-inline'; script-src 'self' 'unsafe-inline'",
    'Strict-Transport-Security': 'max-age=63072000; includeSubDomains',
    'Access-Control-Allow-Origin': '*',
  };
}

function sendJSON(res, status, data) {
  const body = JSON.stringify(data);
  res.writeHead(status, {
    'Content-Type': 'application/json',
    ...securityHeaders(),
  });
  res.end(body);
}

function readBody(req) {
  return new Promise((resolve, reject) => {
    let chunks = '';
    req.on('data', (c) => {
      chunks += c;
      if (chunks.length > 1e6) req.destroy(); // 1MB safety cap
    });
    req.on('end', () => {
      if (!chunks) return resolve({});
      try {
        resolve(JSON.parse(chunks));
      } catch (e) {
        reject(new Error('Invalid JSON body'));
      }
    });
    req.on('error', reject);
  });
}

const MIME = {
  '.html': 'text/html',
  '.css': 'text/css',
  '.js': 'application/javascript',
  '.json': 'application/json',
};

function serveStatic(req, res, pathname) {
  let filePath = pathname === '/' ? '/index.html' : pathname;
  filePath = path.join(PUBLIC_DIR, filePath);
  // prevent path traversal outside public/
  if (!filePath.startsWith(PUBLIC_DIR)) {
    res.writeHead(403, securityHeaders());
    return res.end('Forbidden');
  }
  fs.readFile(filePath, (err, content) => {
    if (err) {
      res.writeHead(404, { 'Content-Type': 'text/plain', ...securityHeaders() });
      return res.end('Not found');
    }
    const ext = path.extname(filePath);
    res.writeHead(200, { 'Content-Type': MIME[ext] || 'application/octet-stream', ...securityHeaders() });
    res.end(content);
  });
}

// ---------- request handler ----------

const server = http.createServer(async (req, res) => {
  const parsed = url.parse(req.url, true);
  const pathname = parsed.pathname;

  // CORS preflight
  if (req.method === 'OPTIONS') {
    res.writeHead(204, {
      'Access-Control-Allow-Methods': 'GET,POST,PATCH,OPTIONS',
      'Access-Control-Allow-Headers': 'Content-Type, X-Admin-Key',
      ...securityHeaders(),
    });
    return res.end();
  }

  try {
    // GET /api/categories
    if (pathname === '/api/categories' && req.method === 'GET') {
      return sendJSON(res, 200, { categories: CATEGORIES });
    }

    // GET /api/reports?category=&status=
    if (pathname === '/api/reports' && req.method === 'GET') {
      let reports = readReports();
      const { category, status } = parsed.query;
      if (category) reports = reports.filter((r) => r.category === category);
      if (status) reports = reports.filter((r) => r.status === status);
      return sendJSON(res, 200, { reports });
    }

    // POST /api/reports  { category, location, description }
    if (pathname === '/api/reports' && req.method === 'POST') {
      const ip = getClientIp(req);
      if (!checkRateLimit(ip)) {
        return sendJSON(res, 429, { error: 'Too many reports submitted. Please try again later.' });
      }

      const body = await readBody(req);
      const { category, location, description } = body;

      if (!category || !CATEGORIES.includes(category)) {
        return sendJSON(res, 400, { error: 'A valid category is required.' });
      }
      if (!location || !String(location).trim()) {
        return sendJSON(res, 400, { error: 'Location is required.' });
      }
      if (!description || !String(description).trim()) {
        return sendJSON(res, 400, { error: 'Description is required.' });
      }

      const reports = readReports();
      const newReport = {
        id: crypto.randomUUID(),
        category,
        location: sanitizeText(location, MAX_LOCATION_LEN),
        description: sanitizeText(description, MAX_DESCRIPTION_LEN),
        status: 'unverified', // unverified -> verified -> resolved
        createdAt: new Date().toISOString(),
      };
      reports.push(newReport);
      writeReports(reports);
      return sendJSON(res, 201, { report: newReport });
    }

    // PATCH /api/reports/:id  { status }  — requires X-Admin-Key header
    const patchMatch = pathname.match(/^\/api\/reports\/([a-f0-9-]+)$/i);
    if (patchMatch && req.method === 'PATCH') {
      if (!isAuthorized(req)) {
        return sendJSON(res, 401, { error: 'Unauthorized. A valid X-Admin-Key header is required.' });
      }

      const id = patchMatch[1];
      const body = await readBody(req);
      const validStatuses = ['unverified', 'verified', 'resolved'];
      if (!validStatuses.includes(body.status)) {
        return sendJSON(res, 400, { error: `status must be one of ${validStatuses.join(', ')}` });
      }
      const reports = readReports();
      const report = reports.find((r) => r.id === id);
      if (!report) return sendJSON(res, 404, { error: 'Report not found.' });
      report.status = body.status;
      report.updatedAt = new Date().toISOString();
      writeReports(reports);
      return sendJSON(res, 200, { report });
    }

    // GET /api/stats  — counts by category and status, for the dashboard
    if (pathname === '/api/stats' && req.method === 'GET') {
      const reports = readReports();
      const byCategory = {};
      const byStatus = { unverified: 0, verified: 0, resolved: 0 };
      for (const cat of CATEGORIES) byCategory[cat] = 0;
      for (const r of reports) {
        if (byCategory[r.category] !== undefined) byCategory[r.category]++;
        if (byStatus[r.status] !== undefined) byStatus[r.status]++;
      }
      return sendJSON(res, 200, { total: reports.length, byCategory, byStatus });
    }

    // everything else -> try serving a static file from /public
    if (req.method === 'GET') {
      return serveStatic(req, res, pathname);
    }

    sendJSON(res, 404, { error: 'Not found' });
  } catch (err) {
    sendJSON(res, 500, { error: err.message || 'Server error' });
  }
});

server.listen(PORT, () => {
  console.log(`Ndu backend running at http://localhost:${PORT}`);
  console.log(`Try: http://localhost:${PORT}/report.html`);
  if (!ADMIN_KEY) {
    console.log('NOTE: ADMIN_KEY is not set — status-change (moderation) endpoint is locked until it is.');
  }
});
