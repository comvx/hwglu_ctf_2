// Cloudflare Pages Function: POST /api/verify
// Body: { matrikel: string, flag_n: 1..5, flag: string }
// Prüft, ob die eingereichte Flag zur Matrikel des Studenten passt.
// Absprache/Copy zwischen Studenten wird erkannt, weil die Flag
// serverseitig identisch neu berechnet wird.

const FLAG_HEX_LEN = 16;

async function hmacSha256(keyBytes, msgBytes) {
  const key = await crypto.subtle.importKey(
    "raw", keyBytes, { name: "HMAC", hash: "SHA-256" }, false, ["sign"],
  );
  const sig = await crypto.subtle.sign("HMAC", key, msgBytes);
  return new Uint8Array(sig);
}

function toBytes(str) { return new TextEncoder().encode(str); }

function joinWithNul(parts) {
  const encoded = parts.map(p => toBytes(p));
  const total = encoded.reduce((n, a) => n + a.length, 0) + (encoded.length - 1);
  const out = new Uint8Array(total);
  let off = 0;
  encoded.forEach((a, i) => {
    out.set(a, off); off += a.length;
    if (i < encoded.length - 1) { out[off] = 0; off += 1; }
  });
  return out;
}

async function prf(secret, parts, tag) {
  const msg = tag ? joinWithNul([tag, ...parts]) : joinWithNul(parts);
  return hmacSha256(secret, msg);
}

function bytesToHex(b) {
  return [...b].map(v => v.toString(16).padStart(2, "0")).join("");
}

async function computeFlag(secret, matrikel, challenge, flagN) {
  const d = await prf(secret,
    [String(matrikel), `chall${challenge}`, `flag${flagN}`], "flag");
  return "FLAG{" + bytesToHex(d).slice(0, FLAG_HEX_LEN) + "}";
}

function loadSecret(raw) {
  if (!raw) throw new Error("MASTER_SECRET env var not set");
  const hex = raw.trim();
  if (/^[0-9a-fA-F]+$/.test(hex) && hex.length >= 32 && hex.length % 2 === 0) {
    const out = new Uint8Array(hex.length / 2);
    for (let i = 0; i < out.length; i++) out[i] = parseInt(hex.substr(i*2, 2), 16);
    return out;
  }
  const utf8 = toBytes(raw);
  if (utf8.length < 16) throw new Error("MASTER_SECRET too short");
  return utf8;
}

export async function onRequestPost({ request, env }) {
  let body;
  try { body = await request.json(); }
  catch { return json({ error: "invalid JSON" }, 400); }

  const matrikel = String(body.matrikel || "").trim();
  const flagN    = Number(body.flag_n);
  const flag     = String(body.flag || "").trim();

  if (!/^[0-9A-Za-z._-]{3,32}$/.test(matrikel)) {
    return json({ error: "matrikel format invalid" }, 400);
  }
  if (!Number.isInteger(flagN) || flagN < 1 || flagN > 5) {
    return json({ error: "flag_n must be 1..5" }, 400);
  }
  if (!/^FLAG\{[0-9a-f]{16}\}$/.test(flag)) {
    return json({ ok: false, reason: "format" });
  }

  let secret;
  try { secret = loadSecret(env.MASTER_SECRET); }
  catch (e) { return json({ error: e.message }, 500); }

  const expected = await computeFlag(secret, matrikel, 2, flagN);
  const ok = flag === expected;
  return json({ ok, matrikel, flag_n: flagN });
}

export function onRequestOptions() {
  return new Response(null, {
    status: 204,
    headers: {
      "Access-Control-Allow-Origin": "*",
      "Access-Control-Allow-Methods": "POST, OPTIONS",
      "Access-Control-Allow-Headers": "Content-Type",
    },
  });
}

function json(obj, status = 200) {
  return new Response(JSON.stringify(obj), {
    status,
    headers: {
      "Content-Type": "application/json; charset=utf-8",
      "Cache-Control": "no-store",
      "Access-Control-Allow-Origin": "*",
    },
  });
}
