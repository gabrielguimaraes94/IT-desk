// IT Desk — Cloudflare Worker
//   D1 binding: DB
//   secret:     SYNC_KEY (PC sync script; also the one-time code to create the first account)
//   optional:   TEAM_DOMAIN + ACCESS_AUD (Cloudflare Access, if it stays in front of the worker)
//   Login: own e-mail + password screen (/login). Passwords are stored only as PBKDF2-SHA256 hashes.
//   Sessions: random token in an HttpOnly, Secure, SameSite=Strict cookie, 30 days.
//   The PC script writes with X-Sync-Key.
const J = (o, s = 200, h = {}) => new Response(JSON.stringify(o), { status: s, headers: { "content-type": "application/json; charset=utf-8", "cache-control": "no-store", ...h } });

async function init(db) {
  await db.prepare("CREATE TABLE IF NOT EXISTS kv (k TEXT PRIMARY KEY, v TEXT NOT NULL, ver INTEGER NOT NULL DEFAULT 0)").run();
}
async function getKV(db, k) { return await db.prepare("SELECT v, ver FROM kv WHERE k = ?").bind(k).first(); }
async function putKV(db, k, v, ver) {
  await db.prepare("INSERT INTO kv (k, v, ver) VALUES (?1, ?2, ?3) ON CONFLICT(k) DO UPDATE SET v = ?2, ver = ?3").bind(k, v, ver).run();
}

function sortLog(l) { return l.sort((a, b) => (a.d + (a.h || "")).localeCompare(b.d + (b.h || ""))); }

// merge a full list coming from the PC (Claude's rounds) into the cloud copy, item by item
function merge(cloud, incoming) {
  const dead = new Set(cloud._deleted || []);
  const map = new Map((cloud.items || []).map(i => [i.id, i]));
  for (const it of incoming.items || []) {
    if (dead.has(it.id)) continue;
    const c = map.get(it.id);
    if (!c) { map.set(it.id, it); continue; }
    const newer = (it.atualizado || "") > (c.atualizado || "") ? it : c;
    const other = newer === it ? c : it;
    const logs = new Map();
    // Gabriel's own lines: the newest version of the item wins (he may have edited/deleted them)
    // lines written from email/Teams: union of both copies
    for (const l of [...(other.log || []), ...(newer.log || [])]) {
      if (l.por === "Gabriel") continue;
      logs.set(l.d + "|" + (l.h || "") + "|" + l.t, l);
    }
    for (const l of newer.log || []) if (l.por === "Gabriel") logs.set("G|" + l.d + "|" + (l.h || "") + "|" + l.t, l);
    map.set(it.id, { ...newer, log: sortLog([...logs.values()]) });
  }
  const out = { ...cloud };
  const inNewer = (incoming.conciliadoEm || "") > (cloud.conciliadoEm || "");
  if (inNewer) { out.conciliadoEm = incoming.conciliadoEm; out.agenda = incoming.agenda || cloud.agenda; }
  out.items = [...map.values()];
  // notes: newest copy of each note wins; notes deleted on the page stay deleted
  const deadN = new Set(cloud._deletedNotas || []), nm = new Map((cloud.notas || []).map(n => [n.id, n]));
  for (const n of incoming.notas || []) { if (deadN.has(n.id)) continue; const c = nm.get(n.id); if (!c || (n.atualizado || "") > (c.atualizado || "")) nm.set(n.id, n); }
  out.notas = [...nm.values()];
  out.atualizado = new Date().toISOString();
  return out;
}


// ---------- Cloudflare Access (login with Google / e-mail code) ----------
// Every request reaches the worker only after Cloudflare Access. We still verify the Access token
// (signature, audience, expiry) so the worker is never open even if Access is switched off by mistake.
const enc = new TextEncoder();
function sameText(a, b) { const x = enc.encode(a), y = enc.encode(b); let d = x.length ^ y.length;
  for (let i = 0; i < Math.max(x.length, y.length); i++) d |= (x[i] || 0) ^ (y[i] || 0); return d === 0; }
const b64uDec = s => Uint8Array.from(atob(s.replace(/-/g, "+").replace(/_/g, "/").padEnd(Math.ceil(s.length / 4) * 4, "=")), c => c.charCodeAt(0));
let CERTS = null, CERTS_AT = 0;
async function accessUser(req, env) {
  const tok = req.headers.get("Cf-Access-Jwt-Assertion");
  if (!tok || !env.TEAM_DOMAIN || !env.ACCESS_AUD) return null;
  const [h, p, s] = tok.split(".");
  if (!h || !p || !s) return null;
  const head = JSON.parse(new TextDecoder().decode(b64uDec(h))), pay = JSON.parse(new TextDecoder().decode(b64uDec(p)));
  if (Date.now() - CERTS_AT > 3600e3 || !CERTS) { CERTS = (await (await fetch(`https://${env.TEAM_DOMAIN}/cdn-cgi/access/certs`)).json()).keys; CERTS_AT = Date.now(); }
  const jwk = CERTS.find(k => k.kid === head.kid); if (!jwk) return null;
  const key = await crypto.subtle.importKey("jwk", jwk, { name: "RSASSA-PKCS1-v1_5", hash: "SHA-256" }, false, ["verify"]);
  const ok = await crypto.subtle.verify("RSASSA-PKCS1-v1_5", key, b64uDec(s), enc.encode(h + "." + p));
  const aud = Array.isArray(pay.aud) ? pay.aud : [pay.aud];
  if (!ok || !aud.includes(env.ACCESS_AUD) || pay.exp * 1000 < Date.now()) return null;
  return pay.email || pay.common_name || "service";
}

// ---------- own login: e-mail + password ----------
const ITER = 100000, SESSION_DAYS = 30, MAX_FAILS = 5, LOCK_MIN = 15;
const hex = b => [...new Uint8Array(b)].map(x => x.toString(16).padStart(2, "0")).join("");
const rnd = n => hex(crypto.getRandomValues(new Uint8Array(n)));
async function pbkdf2(pw, salt, iter) {
  const k = await crypto.subtle.importKey("raw", enc.encode(pw), "PBKDF2", false, ["deriveBits"]);
  return hex(await crypto.subtle.deriveBits({ name: "PBKDF2", hash: "SHA-256", salt: enc.encode(salt), iterations: iter }, k, 256));
}
const sha = async t => hex(await crypto.subtle.digest("SHA-256", enc.encode(t)));
async function initAuth(db) {
  await db.batch([
    db.prepare("CREATE TABLE IF NOT EXISTS users (email TEXT PRIMARY KEY, hash TEXT NOT NULL, salt TEXT NOT NULL, iter INTEGER NOT NULL, created TEXT NOT NULL)"),
    db.prepare("CREATE TABLE IF NOT EXISTS sessions (tok TEXT PRIMARY KEY, email TEXT NOT NULL, exp INTEGER NOT NULL)"),
    db.prepare("CREATE TABLE IF NOT EXISTS fails (k TEXT PRIMARY KEY, n INTEGER NOT NULL, until INTEGER NOT NULL)"),
  ]);
}
const normEmail = e => String(e || "").trim().toLowerCase();
const goodEmail = e => /^[^@\s]+@[^@\s]+\.[^@\s]+$/.test(e) && e.length <= 200;
const pwProblem = p => typeof p !== "string" || p.length < 10 ? "Password must have at least 10 characters." : p.length > 200 ? "Password is too long." : null;
function cookie(req, name) {
  const c = req.headers.get("Cookie") || ""; for (const part of c.split(/;\s*/)) { const i = part.indexOf("="); if (part.slice(0, i) === name) return part.slice(i + 1); } return null;
}
const SC = (v, age) => `itd_s=${v}; Path=/; HttpOnly; Secure; SameSite=Strict; Max-Age=${age}`;
async function sessionUser(req, db) {
  const t = cookie(req, "itd_s"); if (!t || !/^[0-9a-f]{64}$/.test(t)) return null;
  const r = await db.prepare("SELECT email, exp FROM sessions WHERE tok = ?").bind(await sha(t)).first();
  if (!r || r.exp < Date.now()) return null;
  return r.email;
}
async function newSession(db, email) {
  const t = rnd(32);
  await db.prepare("DELETE FROM sessions WHERE exp < ?").bind(Date.now()).run();
  await db.prepare("INSERT INTO sessions (tok, email, exp) VALUES (?, ?, ?)").bind(await sha(t), email, Date.now() + SESSION_DAYS * 864e5).run();
  return SC(t, SESSION_DAYS * 86400);
}
async function locked(db, k) { const r = await db.prepare("SELECT n, until FROM fails WHERE k = ?").bind(k).first(); return r && r.n >= MAX_FAILS && r.until > Date.now() ? r.until : 0; }
async function fail(db, k) {
  const r = await db.prepare("SELECT n, until FROM fails WHERE k = ?").bind(k).first();
  const n = r && r.until > Date.now() ? r.n + 1 : 1;
  await db.prepare("INSERT INTO fails (k, n, until) VALUES (?1, ?2, ?3) ON CONFLICT(k) DO UPDATE SET n = ?2, until = ?3").bind(k, n, Date.now() + LOCK_MIN * 6e4).run();
}
const userCount = async db => (await db.prepare("SELECT COUNT(*) AS c FROM users").first()).c;

async function authRoutes(req, env, url) {
  const db = env.DB, p = url.pathname, ip = req.headers.get("CF-Connecting-IP") || "?";
  if (p === "/logout") {
    const t = cookie(req, "itd_s"); if (t) await db.prepare("DELETE FROM sessions WHERE tok = ?").bind(await sha(t)).run();
    return new Response(null, { status: 302, headers: { Location: "/login", "Set-Cookie": SC("", 0) } });
  }
  if (p === "/api/auth/state") return J({ setup: (await userCount(db)) === 0 });
  if (req.method !== "POST" || !p.startsWith("/api/auth/")) return null;
  // same-origin check for every auth POST
  const o = req.headers.get("Origin"); if (o && o !== url.origin) return J({ error: "Wrong origin." }, 403);
  let b; try { b = await req.json(); } catch (e) { return J({ error: "Bad request." }, 400); }
  const email = normEmail(b.email);

  if (p === "/api/auth/setup") { // first account only; needs the sync key as a one-time code
    if ((await userCount(db)) > 0) return J({ error: "An account already exists. Sign in instead." }, 409);
    if (await locked(db, "setup|" + ip)) return J({ error: "Too many attempts. Try again later." }, 429);
    if (!sameText(String(b.code || ""), env.SYNC_KEY)) { await fail(db, "setup|" + ip); return J({ error: "Setup code is not right." }, 403); }
    if (!goodEmail(email)) return J({ error: "Enter a valid e-mail." }, 400);
    const pr = pwProblem(b.password); if (pr) return J({ error: pr }, 400);
    const salt = rnd(16);
    await db.prepare("INSERT INTO users (email, hash, salt, iter, created) VALUES (?, ?, ?, ?, ?)").bind(email, await pbkdf2(b.password, salt, ITER), salt, ITER, new Date().toISOString()).run();
    return J({ ok: true }, 200, { "Set-Cookie": await newSession(db, email) });
  }
  if (p === "/api/auth/login") {
    const until = Math.max(await locked(db, "u|" + email), await locked(db, "ip|" + ip));
    if (until) return J({ error: `Too many attempts. Try again in ${Math.ceil((until - Date.now()) / 6e4)} min.` }, 429);
    const u = await db.prepare("SELECT hash, salt, iter FROM users WHERE email = ?").bind(email).first();
    const h = await pbkdf2(String(b.password || ""), u ? u.salt : "x", u ? u.iter : ITER); // same work whether or not the user exists
    if (!u || !sameText(h, u.hash)) { await fail(db, "u|" + email); await fail(db, "ip|" + ip); return J({ error: "E-mail or password is not right." }, 401); }
    await db.prepare("DELETE FROM fails WHERE k IN (?, ?)").bind("u|" + email, "ip|" + ip).run();
    return J({ ok: true }, 200, { "Set-Cookie": await newSession(db, email) });
  }
  if (p === "/api/auth/password") { // change password (signed in)
    const me = await sessionUser(req, db); if (!me) return J({ error: "Sign in first." }, 401);
    const u = await db.prepare("SELECT hash, salt, iter FROM users WHERE email = ?").bind(me).first();
    if (!u || !sameText(await pbkdf2(String(b.current || ""), u.salt, u.iter), u.hash)) return J({ error: "Current password is not right." }, 403);
    const pr = pwProblem(b.password); if (pr) return J({ error: pr }, 400);
    const salt = rnd(16);
    await db.prepare("UPDATE users SET hash = ?, salt = ?, iter = ? WHERE email = ?").bind(await pbkdf2(b.password, salt, ITER), salt, ITER, me).run();
    await db.prepare("DELETE FROM sessions WHERE email = ?").bind(me).run(); // sign out everywhere
    return J({ ok: true }, 200, { "Set-Cookie": await newSession(db, me) });
  }
  return J({ error: "Not found." }, 404);
}
const PUBLIC = new Set(["/login", "/login.html", "/wordmark.png", "/favicon.ico"]);

export default {
  async fetch(req, env) {
    const url = new URL(req.url);
    if (!env.SYNC_KEY) return new Response("IT Desk setup: add SYNC_KEY (secret) to this worker.", { status: 503 });
    await init(env.DB); await initAuth(env.DB);
    const isSync = () => sameText(req.headers.get("X-Sync-Key") || "", env.SYNC_KEY);

    // public: login page, its logo, and the auth endpoints
    if (PUBLIC.has(url.pathname)) return asset(env, req, url.pathname);
    const ar = await authRoutes(req, env, url); if (ar) return ar;

    // PC sync script: the sync key is its credential
    const syncOnly = url.pathname === "/api/sync" || (url.pathname === "/api/data" && req.method === "GET" && req.headers.get("X-Sync-Key"));
    let user = null;
    if (syncOnly) { if (!isSync()) return J({ error: "bad sync key" }, 403); user = "pc-sync"; }
    else user = (await sessionUser(req, env.DB)) || (await accessUser(req, env).catch(() => null));
    if (!user) {
      if (url.pathname.startsWith("/api/")) return J({ error: "login" }, 401);
      return new Response(null, { status: 302, headers: { Location: "/login" } });
    }
    if (url.pathname === "/api/me") return J({ user });

    // PC sync script
    if (url.pathname === "/api/sync" && req.method === "POST") {
      if (!isSync()) return J({ error: "bad sync key" }, 403);
      const { base, data } = await req.json();
      const cur = await getKV(env.DB, "data");
      const ver = cur ? cur.ver : 0;
      let merged;
      if (!cur) merged = data;
      else if (Number(base) === ver) { const c = JSON.parse(cur.v); merged = { ...data, _deleted: c._deleted || [], _deletedNotas: c._deletedNotas || [] }; }
      else merged = merge(JSON.parse(cur.v), data);
      await putKV(env.DB, "data", JSON.stringify(merged), ver + 1);
      return J({ ok: true, version: ver + 1, merged: Number(base) !== ver && !!cur });
    }

    if (url.pathname === "/api/data") {
      const cur = await getKV(env.DB, "data");
      const ver = cur ? cur.ver : 0;
      if (req.method === "GET") {
        return new Response(cur ? cur.v : "{}", { headers: { "content-type": "application/json; charset=utf-8", "cache-control": "no-store", "X-Version": String(ver) } });
      }
      if (req.method === "PUT") { // saves from the page: must be based on the latest version
        if (String(ver) !== (req.headers.get("If-Match") || "")) return J({ error: "conflict", version: ver }, 409, { "X-Version": String(ver) });
        const body = await req.text();
        let j; try { j = JSON.parse(body); } catch (e) { return J({ error: "bad json" }, 400); }
        const prev = cur ? JSON.parse(cur.v) : { items: [] };
        const now = new Set((j.items || []).map(i => i.id));
        const removed = (prev.items || []).map(i => i.id).filter(id => !now.has(id));
        j._deleted = [...new Set([...(prev._deleted || []), ...(j._deleted || []), ...removed])].slice(-1000);
        const nowN = new Set((j.notas || []).map(n => n.id));
        const goneN = (prev.notas || []).map(n => n.id).filter(id => !nowN.has(id));
        j._deletedNotas = [...new Set([...(prev._deletedNotas || []), ...(j._deletedNotas || []), ...goneN])].slice(-1000);
        await putKV(env.DB, "data", JSON.stringify(j), ver + 1);
        return J({ ok: true, version: ver + 1 }, 200, { "X-Version": String(ver + 1) });
      }
      return J({ error: "method" }, 405);
    }

    return asset(env, req, url.pathname);
  }
};
async function asset(env, req, path) {
  const u = new URL(req.url); u.pathname = path;
  const res = await env.ASSETS.fetch(new Request(u, { method: "GET", headers: req.headers }));
  const h = new Headers(res.headers); h.set("cache-control", "no-store"); h.set("X-Frame-Options", "DENY"); h.set("Referrer-Policy", "no-referrer");
  h.set("X-Content-Type-Options", "nosniff");
  return new Response(res.body, { status: res.status, headers: h });
}
