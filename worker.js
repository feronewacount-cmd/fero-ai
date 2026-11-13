// FERO AI v3 backend (Cloudflare Workers + KV)
// Binding KV: FERO_KV
// Secrets: GEMINI_API_KEY
// Vars: FIREBASE_PROJECT_ID, DEV_EMAIL, (opsional) GEMINI_MODEL, FREE_LIMIT, PRO_LIMIT, ALLOWED_ORIGIN

const JWKS_URL = "https://www.googleapis.com/service_accounts/v1/jwk/securetoken@system.gserviceaccount.com";

export default {
  async fetch(req, env) {
    const cors = {
      "Access-Control-Allow-Origin": env.ALLOWED_ORIGIN || "*",
      "Access-Control-Allow-Headers": "Content-Type, Authorization",
      "Access-Control-Allow-Methods": "GET, POST, OPTIONS",
    };
    if (req.method === "OPTIONS") return new Response(null, { headers: cors });

    const json = (obj, status = 200) =>
      new Response(JSON.stringify(obj), { status, headers: { ...cors, "Content-Type": "application/json" } });

    try {
      const url = new URL(req.url);
      if (url.pathname === "/") return json({ ok: true, name: "FERO AI v3" });

      const user = await verifyUser(req, env);
      if (!user) return json({ error: "Belum login atau sesi habis. Masuk ulang." }, 401);

      const role = await getRole(user.email, env);
      const limit = role === "dev" ? 999999 : role === "pro" ? Number(env.PRO_LIMIT || 100) : Number(env.FREE_LIMIT || 10);

      if (url.pathname === "/me") {
        const used = await getUsed(user.email, env);
        return json({ role, used, limit: role === "dev" ? 0 : limit, email: user.email });
      }

      if (url.pathname === "/chat" && req.method === "POST") {
        const body = await req.json();
        const used = await getUsed(user.email, env);
        if (role !== "dev" && used >= limit) {
          return json({ error: role === "pro" ? "Batas harian Pro habis. Coba lagi besok." : "Batas harian gratis habis. Upgrade ke Pro atau coba besok." }, 429);
        }
        if (body.image && role === "free") return json({ error: "Kirim foto hanya untuk Pro." }, 403);

        const message = String(body.message || "").slice(0, 8000);
        const contents = [];
        for (const h of (body.history || []).slice(-12)) {
          contents.push({ role: h.role === "ai" ? "model" : "user", parts: [{ text: String(h.text || "").slice(0, 4000) }] });
        }
        while (contents.length && contents[0].role !== "user") contents.shift(); // Gemini wajib mulai dari "user"
        const parts = [];
        if (body.image && body.image.data && body.image.data.length < 3_000_000) {
          parts.push({ inline_data: { mime_type: body.image.mime || "image/jpeg", data: body.image.data } });
        }
        parts.push({ text: message || "Jelaskan gambar ini." });
        contents.push({ role: "user", parts });

        const payload = {
          system_instruction: { parts: [{ text: "Kamu FERO AI, asisten ramah. Jawab dalam bahasa pengguna, ringkas dan jelas." }] },
          contents,
        };
        if (role === "dev") payload.tools = [{ google_search: {} }]; // info terkini hanya dev

        const model = env.GEMINI_MODEL || "gemini-2.0-flash";
        const r = await fetch(
          `https://generativelanguage.googleapis.com/v1beta/models/${model}:generateContent?key=${env.GEMINI_API_KEY}`,
          { method: "POST", headers: { "Content-Type": "application/json" }, body: JSON.stringify(payload) }
        );
        const data = await r.json();
        if (!r.ok) return json({ error: "AI error: " + (data.error?.message || r.status) }, 502);
        const reply = (data.candidates?.[0]?.content?.parts || []).map(p => p.text || "").join("").trim()
          || "Maaf, tidak ada jawaban.";

        const newUsed = used + 1;
        await env.FERO_KV.put(usageKey(user.email), String(newUsed), { expirationTtl: 172800 });
        return json({ reply, used: newUsed });
      }

      // ---- admin (hanya developer) ----
      if (url.pathname.startsWith("/admin/")) {
        if (role !== "dev") return json({ error: "Khusus developer." }, 403);

        if (url.pathname === "/admin/list") {
          const l = await env.FERO_KV.list({ prefix: "pro:" });
          return json({ emails: l.keys.map(k => k.name.slice(4)) });
        }
        if (req.method === "POST") {
          const { email } = await req.json();
          const em = String(email || "").trim().toLowerCase();
          if (!/^[^@\s]+@[^@\s]+\.[^@\s]+$/.test(em)) return json({ error: "Email tidak valid." }, 400);
          if (url.pathname === "/admin/grant") { await env.FERO_KV.put("pro:" + em, "1"); return json({ ok: true }); }
          if (url.pathname === "/admin/revoke") { await env.FERO_KV.delete("pro:" + em); return json({ ok: true }); }
        }
      }

      return json({ error: "Tidak ditemukan." }, 404);
    } catch (e) {
      return json({ error: "Server error: " + e.message }, 500);
    }
  },
};

/* ---------- helper ---------- */
function usageKey(email) {
  const day = new Date(Date.now() + 7 * 3600 * 1000).toISOString().slice(0, 10); // hari WIB
  return `use:${day}:${email}`;
}
async function getUsed(email, env) { return Number((await env.FERO_KV.get(usageKey(email))) || 0); }

async function getRole(email, env) {
  if (email === String(env.DEV_EMAIL || "").toLowerCase()) return "dev";
  return (await env.FERO_KV.get("pro:" + email)) ? "pro" : "free";
}

function b64uToBytes(s) {
  s = s.replace(/-/g, "+").replace(/_/g, "/");
  while (s.length % 4) s += "=";
  return Uint8Array.from(atob(s), c => c.charCodeAt(0));
}

// Verifikasi Firebase ID token (RS256) tanpa library
async function verifyUser(req, env) {
  const auth = req.headers.get("Authorization") || "";
  const tok = auth.startsWith("Bearer ") ? auth.slice(7) : "";
  const p = tok.split(".");
  if (p.length !== 3) return null;
  try {
    const header = JSON.parse(new TextDecoder().decode(b64uToBytes(p[0])));
    const claims = JSON.parse(new TextDecoder().decode(b64uToBytes(p[1])));
    if (header.alg !== "RS256") return null;

    const jwks = await (await fetch(JWKS_URL, { cf: { cacheTtl: 3600, cacheEverything: true } })).json();
    const jwk = jwks.keys.find(k => k.kid === header.kid);
    if (!jwk) return null;
    const key = await crypto.subtle.importKey("jwk", jwk, { name: "RSASSA-PKCS1-v1_5", hash: "SHA-256" }, false, ["verify"]);
    const ok = await crypto.subtle.verify("RSASSA-PKCS1-v1_5", key, b64uToBytes(p[2]), new TextEncoder().encode(p[0] + "." + p[1]));
    if (!ok) return null;

    const now = Math.floor(Date.now() / 1000);
    const pid = env.FIREBASE_PROJECT_ID;
    if (claims.aud !== pid || claims.iss !== "https://securetoken.google.com/" + pid) return null;
    if (claims.exp < now || !claims.sub) return null;
    if (!claims.email || claims.email_verified !== true) return null;
    return { uid: claims.sub, email: String(claims.email).toLowerCase() };
  } catch (_) {
    return null;
  }
}
