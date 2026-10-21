// 99MS on Cloudflare: the app is served as static assets, and this Worker answers /api with
// passkey login and data sync, stored in D1. Paths below are under /api.
//
//   POST /auth/register/options  { email }            -> { challengeId, options }   new account (or a new passkey when logged in)
//   POST /auth/register/verify   { challengeId, response } -> { token, email }
//   POST /auth/login/options     {}                   -> { challengeId, options }   any passkey saved for 99ms.dk
//   POST /auth/login/verify      { challengeId, response } -> { token, email }
//   POST /auth/logout
//   GET  /me                                          -> { email }
//   GET  /data                                        -> { data, updated_at }
//   PUT  /data                   { data }
//
// Sessions are random bearer tokens; only their SHA-256 is stored.
import {
  generateRegistrationOptions,
  verifyRegistrationResponse,
  generateAuthenticationOptions,
  verifyAuthenticationResponse,
} from "@simplewebauthn/server";

const DAY = 86400000;
const CHALLENGE_TTL = 5 * 60000;
const SESSION_TTL = 365 * DAY;
const MAX_DATA = 4_000_000; // bytes of JSON per account
const EMAIL_RE = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;

const b64u = (bytes) => {
  let s = "";
  for (const b of bytes) s += String.fromCharCode(b);
  return btoa(s).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "");
};
const unb64u = (s) => Uint8Array.from(atob(s.replace(/-/g, "+").replace(/_/g, "/") + "===".slice((s.length + 3) % 4)), (c) => c.charCodeAt(0));
const randomId = (n = 16) => b64u(crypto.getRandomValues(new Uint8Array(n)));
const sha256 = async (s) => b64u(new Uint8Array(await crypto.subtle.digest("SHA-256", new TextEncoder().encode(s))));

// The tables are created on first use, so a deploy needs no database step.
const SCHEMA = [
  // Accounts log in with passkeys. Each account's app data is one JSON document.
  "CREATE TABLE IF NOT EXISTS users (id TEXT PRIMARY KEY, email TEXT NOT NULL UNIQUE, created INTEGER NOT NULL)",
  // id and public_key are base64url.
  "CREATE TABLE IF NOT EXISTS credentials (id TEXT PRIMARY KEY, user_id TEXT NOT NULL REFERENCES users(id) ON DELETE CASCADE, public_key TEXT NOT NULL, counter INTEGER NOT NULL DEFAULT 0, transports TEXT, created INTEGER NOT NULL, last_used INTEGER)",
  "CREATE INDEX IF NOT EXISTS credentials_user ON credentials(user_id)",
  // kind is 'reg' or 'auth'.
  "CREATE TABLE IF NOT EXISTS challenges (id TEXT PRIMARY KEY, challenge TEXT NOT NULL, kind TEXT NOT NULL, user_id TEXT, email TEXT, expires INTEGER NOT NULL)",
  // Only the SHA-256 of a session token is stored; the token itself stays on the device.
  "CREATE TABLE IF NOT EXISTS sessions (token_hash TEXT PRIMARY KEY, user_id TEXT NOT NULL REFERENCES users(id) ON DELETE CASCADE, created INTEGER NOT NULL, last_used INTEGER NOT NULL)",
  "CREATE INDEX IF NOT EXISTS sessions_user ON sessions(user_id)",
  "CREATE TABLE IF NOT EXISTS user_data (user_id TEXT PRIMARY KEY REFERENCES users(id) ON DELETE CASCADE, data TEXT NOT NULL, updated_at INTEGER NOT NULL)",
];
let schemaReady = null;
const ensureSchema = (env) => (schemaReady ||= env.DB.batch(SCHEMA.map((q) => env.DB.prepare(q))).catch((e) => { schemaReady = null; throw e; }));

class HttpError extends Error {
  constructor(status, code) { super(code); this.status = status; this.code = code; }
}

export default {
  async fetch(req, env) {
    const url = new URL(req.url);
    if (!url.pathname.startsWith("/api/")) return env.ASSETS.fetch(req);
    // Same-origin GETs carry no Origin header; the page then is this Worker's own address.
    const origin = req.headers.get("origin") || url.origin;
    const origins = env.ORIGINS.split(",").map((o) => o.trim());
    // The Worker's own workers.dev address is allowed too, for testing before 99ms.dk points here.
    const allowed = origins.includes(origin) || /^https:\/\/99ms\.[a-z0-9-]+\.workers\.dev$/.test(origin);
    const site = { origins: allowed ? [...new Set([...origins, origin])] : origins, rpID: rpFor(env, origin) };
    const cors = allowed
      ? { "access-control-allow-origin": origin, "access-control-allow-headers": "authorization, content-type", "access-control-allow-methods": "GET, PUT, POST, OPTIONS", "access-control-max-age": "86400", vary: "origin" }
      : {};
    const json = (data, status = 200) => new Response(JSON.stringify(data), { status, headers: { "content-type": "application/json", "cache-control": "no-store", ...cors } });
    if (req.method === "OPTIONS") return new Response(null, { status: allowed ? 204 : 403, headers: cors });
    const path = url.pathname.slice(4);
    try {
      if (path === "/health") return json({ ok: true });
      await ensureSchema(env);
      if (!allowed) throw new HttpError(403, "origin");
      const route = `${req.method} ${path}`;
      const body = req.method === "POST" || req.method === "PUT" ? await readJson(req) : null;
      switch (route) {
        case "POST /auth/register/options": return json(await registerOptions(env, site, req, body));
        case "POST /auth/register/verify": return json(await registerVerify(env, site, body));
        case "POST /auth/login/options": return json(await loginOptions(env, site));
        case "POST /auth/login/verify": return json(await loginVerify(env, site, body));
        case "POST /auth/logout": return json(await logout(env, req));
        case "GET /me": { const u = await requireUser(env, req); return json({ email: u.email }); }
        case "GET /data": return json(await getData(env, req));
        case "PUT /data": return json(await putData(env, req, body));
        default: throw new HttpError(404, "not_found");
      }
    } catch (e) {
      if (e instanceof HttpError) return json({ error: e.code }, e.status);
      console.error(e);
      return json({ error: "server" }, 500);
    }
  },
};

// Passkeys belong to a domain: 99ms.dk (and its subdomains) in production, otherwise the page's own host.
function rpFor(env, origin) {
  if (env.RP_ID === "localhost") return env.RP_ID;
  let host = "";
  try { host = new URL(origin).hostname; } catch {}
  return host === env.RP_ID || host.endsWith("." + env.RP_ID) || !host ? env.RP_ID : host;
}

async function readJson(req) {
  const text = await req.text();
  if (text.length > MAX_DATA + 10000) throw new HttpError(413, "too_large");
  try { return text ? JSON.parse(text) : {}; } catch { throw new HttpError(400, "bad_json"); }
}

async function sessionUser(env, req) {
  const m = (req.headers.get("authorization") || "").match(/^Bearer ([A-Za-z0-9_-]{20,100})$/);
  if (!m) return null;
  const hash = await sha256(m[1]);
  const row = await env.DB.prepare("SELECT s.user_id, s.last_used, u.email FROM sessions s JOIN users u ON u.id = s.user_id WHERE s.token_hash = ?").bind(hash).first();
  if (!row) return null;
  const now = Date.now();
  if (now - row.last_used > SESSION_TTL) { await env.DB.prepare("DELETE FROM sessions WHERE token_hash = ?").bind(hash).run(); return null; }
  if (now - row.last_used > DAY) await env.DB.prepare("UPDATE sessions SET last_used = ? WHERE token_hash = ?").bind(now, hash).run();
  return { id: row.user_id, email: row.email, hash };
}
async function requireUser(env, req) {
  const u = await sessionUser(env, req);
  if (!u) throw new HttpError(401, "not_logged_in");
  return u;
}
async function newSession(env, userId) {
  const token = randomId(32), now = Date.now();
  await env.DB.prepare("INSERT INTO sessions (token_hash, user_id, created, last_used) VALUES (?, ?, ?, ?)").bind(await sha256(token), userId, now, now).run();
  return token;
}

async function saveChallenge(env, c) {
  const id = randomId(), now = Date.now();
  await env.DB.batch([
    env.DB.prepare("DELETE FROM challenges WHERE expires < ?").bind(now),
    env.DB.prepare("INSERT INTO challenges (id, challenge, kind, user_id, email, expires) VALUES (?, ?, ?, ?, ?, ?)").bind(id, c.challenge, c.kind, c.userId || null, c.email || null, now + CHALLENGE_TTL),
  ]);
  return id;
}
async function takeChallenge(env, id, kind) {
  if (typeof id !== "string" || id.length > 64) throw new HttpError(400, "bad_challenge");
  const row = await env.DB.prepare("DELETE FROM challenges WHERE id = ? RETURNING challenge, kind, user_id, email, expires").bind(id).first();
  if (!row || row.kind !== kind || row.expires < Date.now()) throw new HttpError(400, "challenge_expired");
  return row;
}

// A new account needs an email nobody uses yet. Logged in, the same call adds a passkey to your account.
async function registerOptions(env, site, req, body) {
  const me = await sessionUser(env, req);
  let userId, email;
  if (me) { userId = me.id; email = me.email; }
  else {
    email = String((body && body.email) || "").trim().toLowerCase();
    if (!EMAIL_RE.test(email) || email.length > 120) throw new HttpError(400, "bad_email");
    if (await env.DB.prepare("SELECT 1 FROM users WHERE email = ?").bind(email).first()) throw new HttpError(409, "exists");
    userId = randomId();
  }
  const existing = (await env.DB.prepare("SELECT id, transports FROM credentials WHERE user_id = ?").bind(userId).all()).results;
  const options = await generateRegistrationOptions({
    rpName: "99MS",
    rpID: site.rpID,
    userName: email,
    userDisplayName: email,
    userID: unb64u(userId),
    attestationType: "none",
    excludeCredentials: existing.map((c) => ({ id: c.id, transports: c.transports ? JSON.parse(c.transports) : undefined })),
    authenticatorSelection: { residentKey: "required", userVerification: "preferred" },
  });
  const challengeId = await saveChallenge(env, { challenge: options.challenge, kind: "reg", userId, email });
  return { challengeId, options };
}

async function registerVerify(env, site, body) {
  const c = await takeChallenge(env, body && body.challengeId, "reg");
  let v;
  try {
    v = await verifyRegistrationResponse({ response: body.response, expectedChallenge: c.challenge, expectedOrigin: site.origins, expectedRPID: site.rpID, requireUserVerification: false });
  } catch { throw new HttpError(400, "not_verified"); }
  if (!v.verified) throw new HttpError(400, "not_verified");
  const cred = v.registrationInfo.credential, now = Date.now();
  const user = await env.DB.prepare("SELECT id FROM users WHERE id = ?").bind(c.user_id).first();
  const stmts = [];
  if (!user) {
    if (await env.DB.prepare("SELECT 1 FROM users WHERE email = ?").bind(c.email).first()) throw new HttpError(409, "exists");
    stmts.push(env.DB.prepare("INSERT INTO users (id, email, created) VALUES (?, ?, ?)").bind(c.user_id, c.email, now));
  }
  stmts.push(env.DB.prepare("INSERT INTO credentials (id, user_id, public_key, counter, transports, created, last_used) VALUES (?, ?, ?, ?, ?, ?, ?)")
    .bind(cred.id, c.user_id, b64u(cred.publicKey), cred.counter, cred.transports ? JSON.stringify(cred.transports) : null, now, now));
  await env.DB.batch(stmts);
  return { token: await newSession(env, c.user_id), email: c.email };
}

// No email needed to log in: the phone offers the passkeys it has for 99ms.dk.
async function loginOptions(env, site) {
  const options = await generateAuthenticationOptions({ rpID: site.rpID, userVerification: "preferred" });
  return { challengeId: await saveChallenge(env, { challenge: options.challenge, kind: "auth" }), options };
}

async function loginVerify(env, site, body) {
  const c = await takeChallenge(env, body && body.challengeId, "auth");
  const id = body && body.response && body.response.id;
  if (typeof id !== "string" || id.length > 1400) throw new HttpError(400, "bad_response");
  const row = await env.DB.prepare("SELECT c.id, c.user_id, c.public_key, c.counter, c.transports, u.email FROM credentials c JOIN users u ON u.id = c.user_id WHERE c.id = ?").bind(id).first();
  if (!row) throw new HttpError(404, "unknown_passkey");
  let v;
  try {
    v = await verifyAuthenticationResponse({
      response: body.response, expectedChallenge: c.challenge, expectedOrigin: site.origins, expectedRPID: site.rpID, requireUserVerification: false,
      credential: { id: row.id, publicKey: unb64u(row.public_key), counter: row.counter, transports: row.transports ? JSON.parse(row.transports) : undefined },
    });
  } catch { throw new HttpError(400, "not_verified"); }
  if (!v.verified) throw new HttpError(400, "not_verified");
  await env.DB.prepare("UPDATE credentials SET counter = ?, last_used = ? WHERE id = ?").bind(v.authenticationInfo.newCounter, Date.now(), row.id).run();
  return { token: await newSession(env, row.user_id), email: row.email };
}

async function logout(env, req) {
  const u = await sessionUser(env, req);
  if (u) await env.DB.prepare("DELETE FROM sessions WHERE token_hash = ?").bind(u.hash).run();
  return { ok: true };
}

async function getData(env, req) {
  const u = await requireUser(env, req);
  const row = await env.DB.prepare("SELECT data, updated_at FROM user_data WHERE user_id = ?").bind(u.id).first();
  return row ? { data: JSON.parse(row.data), updated_at: row.updated_at } : { data: null, updated_at: 0 };
}

async function putData(env, req, body) {
  const u = await requireUser(env, req);
  if (!body || typeof body.data !== "object" || body.data === null) throw new HttpError(400, "bad_data");
  const text = JSON.stringify(body.data);
  if (text.length > MAX_DATA) throw new HttpError(413, "too_large");
  const now = Date.now();
  await env.DB.prepare("INSERT INTO user_data (user_id, data, updated_at) VALUES (?, ?, ?) ON CONFLICT(user_id) DO UPDATE SET data = excluded.data, updated_at = excluded.updated_at").bind(u.id, text, now).run();
  return { ok: true, updated_at: now };
}
