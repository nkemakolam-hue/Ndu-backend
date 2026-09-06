// Ndu backend — a minimal, zero-dependency starting point.
//
// This is intentionally built with only Node's built-in modules (no npm
// install required) so it runs anywhere, including Termux on a phone with
// no internet access to fetch packages. It uses a JSON file as the
// database, which is fine for a prototype/demo but should be swapped for
// a real database (Postgres, SQLite, etc.) before this handles real
// public data — see README.md "Next steps."

const http = require('http');
const fs = require('fs');
const path = require('path');
const crypto = require('crypto');
const url = require('url');

const PORT = process.env.PORT || 3000;
const DATA_FILE = path.join(__dirname, 'data', 'reports.json');
const PUBLIC_DIR = path.join(__dirname, 'public');

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

// ---------- helpers ----------

function sendJSON(res, status, data) {
  const body = JSON.stringify(data);
  res.writeHead(status, {
    'Content-Type': 'application/json',
    'Access-Control-Allow-Origin': '*',
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
    res.writeHead(403);
    return res.end('Forbidden');
  }
  fs.readFile(filePath, (err, content) => {
    if (err) {
      res.writeHead(404, { 'Content-Type': 'text/plain' });
      return res.end('Not found');
    }
    const ext = path.extname(filePath);
    res.writeHead(200, { 'Content-Type': MIME[ext] || 'application/octet-stream' });
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
      'Access-Control-Allow-Origin': '*',
      'Access-Control-Allow-Methods': 'GET,POST,PATCH,OPTIONS',
      'Access-Control-Allow-Headers': 'Content-Type',
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
      const body = await readBody(req);
      const { category, location, description } = body;

      if (!category || !CATEGORIES.includes(category)) {
        return sendJSON(res, 400, { error: 'A valid category is required.' });
      }
      if (!location || !location.trim()) {
        return sendJSON(res, 400, { error: 'Location is required.' });
      }
      if (!description || !description.trim()) {
        return sendJSON(res, 400, { error: 'Description is required.' });
      }

      const reports = readReports();
      const newReport = {
        id: crypto.randomUUID(),
        category,
        location: location.trim(),
        description: description.trim(),
        status: 'unverified', // unverified -> verified -> resolved
        createdAt: new Date().toISOString(),
      };
      reports.push(newReport);
      writeReports(reports);
      return sendJSON(res, 201, { report: newReport });
    }

    // PATCH /api/reports/:id  { status }
    const patchMatch = pathname.match(/^\/api\/reports\/([a-f0-9-]+)$/i);
    if (patchMatch && req.method === 'PATCH') {
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
});
