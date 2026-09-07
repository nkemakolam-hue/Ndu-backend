// Ndu backend — a minimal, zero-dependency starting point.
//
// Built with only Node's built-in modules (no npm install required) so it
// runs anywhere, including Termux with no internet access to fetch
// packages. Data is stored in JSON files — fine for a prototype/demo, but
// must be swapped for a real database before this handles real public
// data at scale (see README.md "Next steps").
//
// SECURITY LAYERS IN THIS FILE:
//   1. Passwords hashed with scrypt + random salt (never stored plain)
//   2. Signed session tokens (HMAC-SHA256), not guessable or forgeable
//   3. Admin key OR admin-role login required to change a report's status
//   4. Rate limiting on report submissions AND on login/signup attempts
//   5. Input length limits + stripped HTML tags (prevents stored XSS)
//   6. Security response headers on every request
//   7. Constant-time comparisons for keys/signatures (prevents timing attacks)
//   8. Generic login error messages (prevents leaking which emails exist)
//   9. Request body size cap
//  10. Path traversal protection on static files

const http = require('http');
const fs = require('fs');
const path = require('path');
const crypto = require('crypto');
const url = require('url');

const PORT = process.env.PORT || 3000;
const DATA_DIR = path.join(__dirname, 'data');
const REPORTS_FILE = path.join(DATA_DIR, 'reports.json');
const USERS_FILE = path.join(DATA_DIR, 'users.json');
const JOBS_FILE = path.join(DATA_DIR, 'jobs.json');
const APPLICATIONS_FILE = path.join(DATA_DIR, 'applications.json');
const PUBLIC_DIR = path.join(__dirname, 'public');

// Admin key for moderation — set as a real env var, never hard-coded.
const ADMIN_KEY = process.env.ADMIN_KEY || null;

// Secret used to sign session tokens. If not set, a random one is
// generated at startup — sessions will all log out on every restart/
// redeploy, which is safe-by-default but inconvenient. Set a real
// SESSION_SECRET env var (like ADMIN_KEY) for persistent logins.
const SESSION_SECRET = process.env.SESSION_SECRET || crypto.randomBytes(32).toString('hex');
if (!process.env.SESSION_SECRET) {
  console.log('NOTE: SESSION_SECRET is not set — a temporary one was generated, so all logins will be invalidated on restart. Set SESSION_SECRET in your environment for persistent sessions.');
}

const CATEGORIES = [
  'Healthcare',
  'Agriculture, Business & Investment',
  'Education & skills',
  'Employment access',
  'Financial inclusion',
  'Housing & infrastructure',
  'Transportation',
  'Digital access',
];

const MAX_LOCATION_LEN = 120;
const MAX_DESCRIPTION_LEN = 1000;
const MAX_NAME_LEN = 80;
const MAX_TITLE_LEN = 100;
const MAX_COMPANY_LEN = 100;
const MAX_COVER_NOTE_LEN = 1500;
const JOB_TYPES = ['remote', 'physical'];
const MIN_PASSWORD_LEN = 8;
const SESSION_TTL_MS = 7 * 24 * 60 * 60 * 1000; // 7 days
const EMAIL_RE = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;

// ---------- tiny JSON-file "database" ----------

function readJSON(file) {
  try {
    return JSON.parse(fs.readFileSync(file, 'utf8'));
  } catch (e) {
    return [];
  }
}

function writeJSON(file, data) {
  fs.writeFileSync(file, JSON.stringify(data, null, 2));
}

const readReports = () => readJSON(REPORTS_FILE);
const writeReports = (r) => writeJSON(REPORTS_FILE, r);
const readUsers = () => readJSON(USERS_FILE);
const writeUsers = (u) => writeJSON(USERS_FILE, u);
const readJobs = () => readJSON(JOBS_FILE);
const writeJobs = (j) => writeJSON(JOBS_FILE, j);
const readApplications = () => readJSON(APPLICATIONS_FILE);
const writeApplications = (a) => writeJSON(APPLICATIONS_FILE, a);

// ---------- security helpers ----------

function stripTags(str) {
  return String(str).replace(/<[^>]*>/g, '');
}

function clamp(str, maxLen) {
  return String(str).slice(0, maxLen);
}

function sanitizeText(str, maxLen) {
  return clamp(stripTags(str), maxLen).trim();
}

function safeEqual(a, b) {
  const bufA = Buffer.from(String(a));
  const bufB = Buffer.from(String(b));
  if (bufA.length !== bufB.length) return false;
  return crypto.timingSafeEqual(bufA, bufB);
}

// ---------- password hashing (scrypt, built into Node — no bcrypt needed) ----------

function hashPassword(password) {
  const salt = crypto.randomBytes(16).toString('hex');
  const hash = crypto.scryptSync(password, salt, 64).toString('hex');
  return `${salt}:${hash}`;
}

function verifyPassword(password, stored) {
  const [salt, hash] = stored.split(':');
  const attempt = crypto.scryptSync(password, salt, 64).toString('hex');
  return safeEqual(attempt, hash);
}

// ---------- session tokens (self-contained, HMAC-signed — no server-side session store needed) ----------

function base64url(input) {
  return Buffer.from(input).toString('base64').replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');
}

function base64urlDecode(input) {
  input = input.replace(/-/g, '+').replace(/_/g, '/');
  while (input.length % 4) input += '=';
  return Buffer.from(input, 'base64').toString('utf8');
}

function createToken(payload) {
  const body = { ...payload, exp: Date.now() + SESSION_TTL_MS };
  const encoded = base64url(JSON.stringify(body));
  const sig = crypto.createHmac('sha256', SESSION_SECRET).update(encoded).digest('hex');
  return `${encoded}.${sig}`;
}

function verifyToken(token) {
  if (!token || typeof token !== 'string' || !token.includes('.')) return null;
  const [encoded, sig] = token.split('.');
  const expectedSig = crypto.createHmac('sha256', SESSION_SECRET).update(encoded).digest('hex');
  if (!sig || !safeEqual(sig, expectedSig)) return null;
  try {
    const payload = JSON.parse(base64urlDecode(encoded));
    if (!payload.exp || Date.now() > payload.exp) return null;
    return payload;
  } catch (e) {
    return null;
  }
}

function getBearerToken(req) {
  const header = req.headers['authorization'];
  if (!header || !header.startsWith('Bearer ')) return null;
  return header.slice('Bearer '.length).trim();
}

function getCurrentUser(req) {
  const token = getBearerToken(req);
  if (!token) return null;
  const payload = verifyToken(token);
  if (!payload) return null;
  const users = readUsers();
  const user = users.find((u) => u.id === payload.sub);
  return user || null;
}

function isAdminRequest(req) {
  // Two independent ways to be authorized as admin: the shared ADMIN_KEY
  // header (for scripts/curl), or a logged-in user with role 'admin'.
  if (ADMIN_KEY) {
    const provided = req.headers['x-admin-key'];
    if (provided && safeEqual(provided, ADMIN_KEY)) return true;
  }
  const user = getCurrentUser(req);
  return !!(user && user.role === 'admin');
}

function publicUser(user) {
  // Never send passwordHash to the client.
  const { passwordHash, ...safe } = user;
  return safe;
}

// ---------- simple in-memory rate limiter ----------
// Resets on redeploy (fine for a prototype). Not a substitute for a real
// rate-limiting layer once this handles real traffic — see README.

const RATE_LIMIT_WINDOW_MS = 15 * 60 * 1000; // 15 minutes
const rateLimitBuckets = new Map(); // "bucket:ip" -> { count, resetAt }

function checkRateLimit(bucket, ip, max) {
  const key = `${bucket}:${ip}`;
  const now = Date.now();
  const entry = rateLimitBuckets.get(key);
  if (!entry || now > entry.resetAt) {
    rateLimitBuckets.set(key, { count: 1, resetAt: now + RATE_LIMIT_WINDOW_MS });
    return true;
  }
  if (entry.count >= max) return false;
  entry.count++;
  return true;
}

function getClientIp(req) {
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

  if (req.method === 'OPTIONS') {
    res.writeHead(204, {
      'Access-Control-Allow-Methods': 'GET,POST,PATCH,OPTIONS',
      'Access-Control-Allow-Headers': 'Content-Type, X-Admin-Key, Authorization',
      ...securityHeaders(),
    });
    return res.end();
  }

  try {
    // ---------- AUTH ----------

    // POST /api/auth/signup  { name, email, password }
    if (pathname === '/api/auth/signup' && req.method === 'POST') {
      const ip = getClientIp(req);
      if (!checkRateLimit('signup', ip, 10)) {
        return sendJSON(res, 429, { error: 'Too many signup attempts. Please try again later.' });
      }

      const body = await readBody(req);
      const name = sanitizeText(body.name || '', MAX_NAME_LEN);
      const email = String(body.email || '').trim().toLowerCase();
      const password = String(body.password || '');

      if (!name) return sendJSON(res, 400, { error: 'Name is required.' });
      if (!EMAIL_RE.test(email)) return sendJSON(res, 400, { error: 'A valid email is required.' });
      if (password.length < MIN_PASSWORD_LEN) {
        return sendJSON(res, 400, { error: `Password must be at least ${MIN_PASSWORD_LEN} characters.` });
      }

      const users = readUsers();
      if (users.some((u) => u.email === email)) {
        return sendJSON(res, 409, { error: 'An account with that email already exists.' });
      }

      const newUser = {
        id: crypto.randomUUID(),
        name,
        email,
        passwordHash: hashPassword(password),
        role: users.length === 0 ? 'admin' : 'citizen', // first-ever signup becomes admin
        createdAt: new Date().toISOString(),
      };
      users.push(newUser);
      writeUsers(users);

      const token = createToken({ sub: newUser.id });
      return sendJSON(res, 201, { token, user: publicUser(newUser) });
    }

    // POST /api/auth/login  { email, password }
    if (pathname === '/api/auth/login' && req.method === 'POST') {
      const ip = getClientIp(req);
      if (!checkRateLimit('login', ip, 10)) {
        return sendJSON(res, 429, { error: 'Too many login attempts. Please try again later.' });
      }

      const body = await readBody(req);
      const email = String(body.email || '').trim().toLowerCase();
      const password = String(body.password || '');

      const users = readUsers();
      const user = users.find((u) => u.email === email);
      const GENERIC_ERROR = { error: 'Invalid email or password.' };

      if (!user) return sendJSON(res, 401, GENERIC_ERROR); // generic on purpose — don't reveal which emails exist
      if (!verifyPassword(password, user.passwordHash)) return sendJSON(res, 401, GENERIC_ERROR);

      const token = createToken({ sub: user.id });
      return sendJSON(res, 200, { token, user: publicUser(user) });
    }

    // GET /api/auth/me  (Authorization: Bearer <token>)
    if (pathname === '/api/auth/me' && req.method === 'GET') {
      const user = getCurrentUser(req);
      if (!user) return sendJSON(res, 401, { error: 'Not logged in.' });
      return sendJSON(res, 200, { user: publicUser(user) });
    }

    // ---------- REPORTS ----------

    if (pathname === '/api/categories' && req.method === 'GET') {
      return sendJSON(res, 200, { categories: CATEGORIES });
    }

    if (pathname === '/api/reports' && req.method === 'GET') {
      let reports = readReports();
      const { category, status, mine } = parsed.query;
      if (category) reports = reports.filter((r) => r.category === category);
      if (status) reports = reports.filter((r) => r.status === status);
      if (mine === 'true') {
        const user = getCurrentUser(req);
        if (!user) return sendJSON(res, 401, { error: 'Log in to view your own reports.' });
        reports = reports.filter((r) => r.reportedBy === user.id);
      }
      return sendJSON(res, 200, { reports });
    }

    if (pathname === '/api/reports' && req.method === 'POST') {
      const ip = getClientIp(req);
      if (!checkRateLimit('report', ip, 5)) {
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

      const user = getCurrentUser(req); // optional — anonymous reporting is still allowed
      const reports = readReports();
      const newReport = {
        id: crypto.randomUUID(),
        category,
        location: sanitizeText(location, MAX_LOCATION_LEN),
        description: sanitizeText(description, MAX_DESCRIPTION_LEN),
        status: 'unverified',
        reportedBy: user ? user.id : null,
        createdAt: new Date().toISOString(),
      };
      reports.push(newReport);
      writeReports(reports);
      return sendJSON(res, 201, { report: newReport });
    }

    const patchMatch = pathname.match(/^\/api\/reports\/([a-f0-9-]+)$/i);
    if (patchMatch && req.method === 'PATCH') {
      if (!isAdminRequest(req)) {
        return sendJSON(res, 401, { error: 'Unauthorized. Admin key or admin login required.' });
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

    // ---------- JOBS (Ndu as middleman between companies and applicants) ----------

    // POST /api/jobs — a logged-in user posts a job on behalf of a company.
    // Requires login so postings are always traceable to a real account,
    // not anonymous.
    if (pathname === '/api/jobs' && req.method === 'POST') {
      const user = getCurrentUser(req);
      if (!user) return sendJSON(res, 401, { error: 'Log in to post a job.' });

      const ip = getClientIp(req);
      if (!checkRateLimit('post-job', ip, 10)) {
        return sendJSON(res, 429, { error: 'Too many job postings submitted. Please try again later.' });
      }

      const body = await readBody(req);
      const title = sanitizeText(body.title || '', MAX_TITLE_LEN);
      const company = sanitizeText(body.company || '', MAX_COMPANY_LEN);
      const location = sanitizeText(body.location || '', MAX_LOCATION_LEN);
      const description = sanitizeText(body.description || '', MAX_DESCRIPTION_LEN);
      const type = String(body.type || '').toLowerCase();
      const category = body.category || null;

      if (!title) return sendJSON(res, 400, { error: 'Job title is required.' });
      if (!company) return sendJSON(res, 400, { error: 'Company name is required.' });
      if (!location) return sendJSON(res, 400, { error: 'Location is required.' });
      if (!description) return sendJSON(res, 400, { error: 'Description is required.' });
      if (!JOB_TYPES.includes(type)) {
        return sendJSON(res, 400, { error: `type must be one of ${JOB_TYPES.join(', ')}` });
      }
      if (category && !CATEGORIES.includes(category)) {
        return sendJSON(res, 400, { error: 'Invalid category.' });
      }

      const jobs = readJobs();
      const newJob = {
        id: crypto.randomUUID(),
        title,
        company,
        location,
        description,
        type,
        category,
        status: 'open', // open -> closed
        postedBy: user.id,
        postedByName: user.name,
        createdAt: new Date().toISOString(),
      };
      jobs.push(newJob);
      writeJobs(jobs);
      return sendJSON(res, 201, { job: newJob });
    }

    // GET /api/jobs?category=&type=&status=&mine=true
    if (pathname === '/api/jobs' && req.method === 'GET') {
      let jobs = readJobs();
      const { category, type, status, mine } = parsed.query;
      if (category) jobs = jobs.filter((j) => j.category === category);
      if (type) jobs = jobs.filter((j) => j.type === type);
      if (status) jobs = jobs.filter((j) => j.status === status);
      if (mine === 'true') {
        const user = getCurrentUser(req);
        if (!user) return sendJSON(res, 401, { error: 'Log in to view your posted jobs.' });
        jobs = jobs.filter((j) => j.postedBy === user.id);
      }
      return sendJSON(res, 200, { jobs });
    }

    // PATCH /api/jobs/:id  { status: 'open'|'closed' } — only the poster or an admin
    const jobPatchMatch = pathname.match(/^\/api\/jobs\/([a-f0-9-]+)$/i);
    if (jobPatchMatch && req.method === 'PATCH') {
      const user = getCurrentUser(req);
      if (!user) return sendJSON(res, 401, { error: 'Log in required.' });

      const jobs = readJobs();
      const job = jobs.find((j) => j.id === jobPatchMatch[1]);
      if (!job) return sendJSON(res, 404, { error: 'Job not found.' });
      if (job.postedBy !== user.id && user.role !== 'admin') {
        return sendJSON(res, 403, { error: 'Only the job poster or an admin can update this listing.' });
      }

      const body = await readBody(req);
      if (!['open', 'closed'].includes(body.status)) {
        return sendJSON(res, 400, { error: 'status must be open or closed.' });
      }
      job.status = body.status;
      job.updatedAt = new Date().toISOString();
      writeJobs(jobs);
      return sendJSON(res, 200, { job });
    }

    // POST /api/jobs/:id/apply  { coverNote } — requires login
    const applyMatch = pathname.match(/^\/api\/jobs\/([a-f0-9-]+)\/apply$/i);
    if (applyMatch && req.method === 'POST') {
      const user = getCurrentUser(req);
      if (!user) return sendJSON(res, 401, { error: 'Log in to apply for this job.' });

      const ip = getClientIp(req);
      if (!checkRateLimit('apply', ip, 15)) {
        return sendJSON(res, 429, { error: 'Too many applications submitted. Please try again later.' });
      }

      const jobs = readJobs();
      const job = jobs.find((j) => j.id === applyMatch[1]);
      if (!job) return sendJSON(res, 404, { error: 'Job not found.' });
      if (job.status !== 'open') return sendJSON(res, 400, { error: 'This job is no longer accepting applications.' });

      const applications = readApplications();
      const alreadyApplied = applications.some((a) => a.jobId === job.id && a.applicantId === user.id);
      if (alreadyApplied) return sendJSON(res, 409, { error: 'You already applied to this job.' });

      const body = await readBody(req);
      const newApplication = {
        id: crypto.randomUUID(),
        jobId: job.id,
        applicantId: user.id,
        applicantName: user.name,
        applicantEmail: user.email,
        coverNote: sanitizeText(body.coverNote || '', MAX_COVER_NOTE_LEN),
        status: 'submitted', // submitted -> reviewed -> accepted/rejected
        createdAt: new Date().toISOString(),
      };
      applications.push(newApplication);
      writeApplications(applications);
      return sendJSON(res, 201, { application: newApplication });
    }

    // GET /api/jobs/:id/applications — only the job poster or an admin can view applicants
    const jobAppsMatch = pathname.match(/^\/api\/jobs\/([a-f0-9-]+)\/applications$/i);
    if (jobAppsMatch && req.method === 'GET') {
      const user = getCurrentUser(req);
      if (!user) return sendJSON(res, 401, { error: 'Log in required.' });

      const jobs = readJobs();
      const job = jobs.find((j) => j.id === jobAppsMatch[1]);
      if (!job) return sendJSON(res, 404, { error: 'Job not found.' });
      if (job.postedBy !== user.id && user.role !== 'admin') {
        return sendJSON(res, 403, { error: 'Only the job poster or an admin can view applicants.' });
      }

      const applications = readApplications().filter((a) => a.jobId === job.id);
      return sendJSON(res, 200, { applications });
    }

    // GET /api/applications?mine=true — the logged-in user's own applications
    if (pathname === '/api/applications' && req.method === 'GET') {
      const user = getCurrentUser(req);
      if (!user) return sendJSON(res, 401, { error: 'Log in required.' });
      if (parsed.query.mine !== 'true') {
        return sendJSON(res, 400, { error: 'Add ?mine=true to view your own applications.' });
      }
      const jobs = readJobs();
      const applications = readApplications()
        .filter((a) => a.applicantId === user.id)
        .map((a) => {
          const job = jobs.find((j) => j.id === a.jobId);
          return { ...a, jobTitle: job ? job.title : '(job removed)', jobCompany: job ? job.company : '' };
        });
      return sendJSON(res, 200, { applications });
    }

    // PATCH /api/applications/:id  { status } — only the related job's poster or an admin
    const appPatchMatch = pathname.match(/^\/api\/applications\/([a-f0-9-]+)$/i);
    if (appPatchMatch && req.method === 'PATCH') {
      const user = getCurrentUser(req);
      if (!user) return sendJSON(res, 401, { error: 'Log in required.' });

      const applications = readApplications();
      const application = applications.find((a) => a.id === appPatchMatch[1]);
      if (!application) return sendJSON(res, 404, { error: 'Application not found.' });

      const jobs = readJobs();
      const job = jobs.find((j) => j.id === application.jobId);
      if (!job || (job.postedBy !== user.id && user.role !== 'admin')) {
        return sendJSON(res, 403, { error: 'Only the job poster or an admin can update this application.' });
      }

      const body = await readBody(req);
      const validStatuses = ['submitted', 'reviewed', 'accepted', 'rejected'];
      if (!validStatuses.includes(body.status)) {
        return sendJSON(res, 400, { error: `status must be one of ${validStatuses.join(', ')}` });
      }
      application.status = body.status;
      application.updatedAt = new Date().toISOString();
      writeApplications(applications);
      return sendJSON(res, 200, { application });
    }

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
  console.log(`Try: http://localhost:${PORT}/signup.html`);
  if (!ADMIN_KEY) {
    console.log('NOTE: ADMIN_KEY is not set — the shared-key path for moderation is disabled (admin-role login still works).');
  }
});
