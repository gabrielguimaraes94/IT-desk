// IT Desk — Cloudflare Worker
//   D1 binding: DB
//   secret:     SYNC_KEY (PC sync script)
//   variables:  TEAM_DOMAIN (e.g. gabriel.cloudflareaccess.com), ACCESS_AUD (Access application AUD tag)
//   Login: Cloudflare Access in front of the whole worker (Google account or e-mail code).
//   The PC script passes Access with a service token and writes with X-Sync-Key.
// Protect the whole worker with Cloudflare Access. Requests without an Access token are refused.
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

export default {
  async fetch(req, env) {
    const url = new URL(req.url);
    if (!env.SYNC_KEY || !env.TEAM_DOMAIN || !env.ACCESS_AUD) return new Response("IT Desk setup: add SYNC_KEY (secret), TEAM_DOMAIN and ACCESS_AUD to this worker.", { status: 503 });
    const user = await accessUser(req, env);
    if (!user) return new Response("Sign in through Cloudflare Access.", { status: 401 });
    await init(env.DB);
    const isSync = () => sameText(req.headers.get("X-Sync-Key") || "", env.SYNC_KEY);
    if (url.pathname === "/api/me") return J({ user });

    // PC sync script
    if (url.pathname === "/api/sync" && req.method === "POST") {
      if (!isSync()) return J({ error: "bad sync key" }, 403);
      const { base, data } = await req.json();
      const cur = await getKV(env.DB, "data");
      const ver = cur ? cur.ver : 0;
      let merged;
      if (!cur) merged = data;
      else if (Number(base) === ver) merged = { ...data, _deleted: JSON.parse(cur.v)._deleted || [] };
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
        await putKV(env.DB, "data", JSON.stringify(j), ver + 1);
        return J({ ok: true, version: ver + 1 }, 200, { "X-Version": String(ver + 1) });
      }
      return J({ error: "method" }, 405);
    }

    const res = await env.ASSETS.fetch(req);
    const h = new Headers(res.headers); h.set("cache-control", "no-store"); h.set("X-Frame-Options", "DENY"); h.set("Referrer-Policy", "no-referrer");
    return new Response(res.body, { status: res.status, headers: h });
  }
};
