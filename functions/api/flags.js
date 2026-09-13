// Cloudflare Pages Function: POST /api/flags
// Nimmt {matrikel} entgegen, gibt personalisierte Werte für alle 18
// Placeholder aus PLACEHOLDERS.md zurück.
//
// Sicherheits-Modell:
//   * MASTER_SECRET wird als Env-Var (Cloudflare Pages Secret) gesetzt.
//   * Alle Ableitungen sind HMAC-SHA256 basiert und deterministisch —
//     identisch zu framework/flag_lib.py (Port nach JS).
//   * Weder Flag-Klartext (F4) noch das Secret verlässt jemals die Function.

const FLAG_HEX_LEN = 16;

// Wortliste für Coupon-Codes — identisch zu PLACEHOLDERS.md
const F3_WORDS = [
  "shop", "gift", "hero", "holo", "aqua", "neon",
  "spark", "forge", "echo", "void",
];

// Klartext-JS-Body für den obfuskierten F4-Check.
// Wird base64-encodiert an den Client ausgeliefert.
const F4_CHECK_BODY = `
if (!user || user.isAdmin !== true) return null;
const cipher = new Uint8Array(cipher_hex.match(/.{2}/g).map(h => parseInt(h, 16)));
const key = Uint8Array.from(atob(key_b64), c => c.charCodeAt(0));
const out = new Uint8Array(cipher.length);
for (let i = 0; i < cipher.length; i++) out[i] = cipher[i] ^ key[i % key.length];
return new TextDecoder().decode(out);
`;

// -----------------------------------------------------------------------
// Kern-PRF: HMAC-SHA256, deterministisch — Port von flag_lib._prf
// -----------------------------------------------------------------------
async function hmacSha256(keyBytes, msgBytes) {
  const cryptoKey = await crypto.subtle.importKey(
    "raw", keyBytes,
    { name: "HMAC", hash: "SHA-256" },
    false, ["sign"],
  );
  const sig = await crypto.subtle.sign("HMAC", cryptoKey, msgBytes);
  return new Uint8Array(sig);
}

async function sha256Hex(input) {
  const buf = typeof input === "string" ? new TextEncoder().encode(input) : input;
  const h = await crypto.subtle.digest("SHA-256", buf);
  return [...new Uint8Array(h)].map(b => b.toString(16).padStart(2, "0")).join("");
}

function toBytes(str) { return new TextEncoder().encode(str); }

function joinWithNul(parts) {
  // NUL-Byte als Trenner, wie in flag_lib._prf
  const encoded = parts.map(p => toBytes(p));
  const total = encoded.reduce((n, a) => n + a.length, 0) + (encoded.length - 1);
  const out = new Uint8Array(total);
  let offset = 0;
  encoded.forEach((a, i) => {
    out.set(a, offset);
    offset += a.length;
    if (i < encoded.length - 1) { out[offset] = 0x00; offset += 1; }
  });
  return out;
}

async function prf(secretBytes, parts, tag) {
  let msg;
  if (tag) {
    msg = joinWithNul([tag, ...parts]);
  } else {
    msg = joinWithNul(parts);
  }
  return hmacSha256(secretBytes, msg);
}

function canon(matrikel, challenge, flagN) {
  return [String(matrikel), `chall${challenge}`, `flag${flagN}`];
}

function bytesToHex(bytes) {
  return [...bytes].map(b => b.toString(16).padStart(2, "0")).join("");
}

function bytesToB64(bytes) {
  let bin = "";
  for (let i = 0; i < bytes.length; i++) bin += String.fromCharCode(bytes[i]);
  return btoa(bin);
}

// -----------------------------------------------------------------------
// Flag-Berechnung — Port compute_flag
// -----------------------------------------------------------------------
async function computeFlag(secret, matrikel, challenge, flagN) {
  const d = await prf(secret, canon(matrikel, challenge, flagN), "flag");
  return "FLAG{" + bytesToHex(d).slice(0, FLAG_HEX_LEN) + "}";
}

// -----------------------------------------------------------------------
// XOR-Key — Port xor_key
// -----------------------------------------------------------------------
async function xorKey(secret, matrikel, challenge, flagN, length) {
  const parts = [];
  let counter = 0;
  let total = 0;
  while (total < length) {
    const d = await prf(secret, canon(matrikel, challenge, flagN),
                        `xor_key_${counter}`);
    parts.push(d);
    total += d.length;
    counter += 1;
  }
  const out = new Uint8Array(length);
  let off = 0;
  for (const p of parts) {
    const room = length - off;
    if (room <= 0) break;
    out.set(p.slice(0, room), off);
    off += Math.min(room, p.length);
  }
  return out;
}

// -----------------------------------------------------------------------
// Hex-Token — Port hex_token
// -----------------------------------------------------------------------
async function hexToken(secret, matrikel, challenge, flagN, byteLength, tag) {
  const parts = [];
  let counter = 0;
  let total = 0;
  while (total < byteLength) {
    const d = await prf(secret, canon(matrikel, challenge, flagN),
                        `${tag}_${counter}`);
    parts.push(d);
    total += d.length;
    counter += 1;
  }
  const out = new Uint8Array(byteLength);
  let off = 0;
  for (const p of parts) {
    const room = byteLength - off;
    if (room <= 0) break;
    out.set(p.slice(0, room), off);
    off += Math.min(room, p.length);
  }
  return bytesToHex(out);
}

// -----------------------------------------------------------------------
// F3 — Coupon
// -----------------------------------------------------------------------
async function f3Coupon(secret, matrikel) {
  const parts = canon(matrikel, 2, 3);
  const d1 = await prf(secret, parts, "cpn_w1");
  const d2 = await prf(secret, parts, "cpn_w2");
  const d3 = await prf(secret, parts, "cpn_num");
  const idx1 = new DataView(d1.buffer).getUint32(0, false) % F3_WORDS.length;
  const idx2 = new DataView(d2.buffer).getUint32(0, false) % F3_WORDS.length;
  const num  = new DataView(d3.buffer).getUint32(0, false) % 10000;
  const w1 = F3_WORDS[idx1];
  const w2 = F3_WORDS[idx2];
  return `${w1}-${String(num).padStart(4, "0")}-${w2}`;
}

// -----------------------------------------------------------------------
// Secret-Loader (hex-decoded oder utf8-bytes)
// -----------------------------------------------------------------------
function loadSecret(raw) {
  if (!raw) throw new Error("MASTER_SECRET env var not set");
  const hexClean = raw.trim();
  if (/^[0-9a-fA-F]+$/.test(hexClean) && hexClean.length >= 32
      && hexClean.length % 2 === 0) {
    const out = new Uint8Array(hexClean.length / 2);
    for (let i = 0; i < out.length; i++) {
      out[i] = parseInt(hexClean.substr(i * 2, 2), 16);
    }
    return out;
  }
  const utf8 = toBytes(raw);
  if (utf8.length < 16) throw new Error("MASTER_SECRET too short (need >=16 bytes)");
  return utf8;
}

// -----------------------------------------------------------------------
// Handler
// -----------------------------------------------------------------------
export async function onRequestPost({ request, env }) {
  let body;
  try { body = await request.json(); }
  catch { return json({ error: "invalid JSON" }, 400); }

  const matrikelRaw = body && body.matrikel;
  if (typeof matrikelRaw !== "string") {
    return json({ error: "matrikel required (string)" }, 400);
  }
  const matrikel = matrikelRaw.trim();
  if (!/^[0-9A-Za-z._-]{3,32}$/.test(matrikel)) {
    return json({ error: "matrikel format invalid" }, 400);
  }
  const name = (body.name && typeof body.name === "string")
    ? body.name.trim().slice(0, 80)
    : `student-${matrikel}`;

  let secret;
  try { secret = loadSecret(env.MASTER_SECRET); }
  catch (e) { return json({ error: "server misconfigured: " + e.message }, 500); }

  // Flags 1..5
  const f1 = await computeFlag(secret, matrikel, 2, 1);
  const f2 = await computeFlag(secret, matrikel, 2, 2);
  const f3 = await computeFlag(secret, matrikel, 2, 3);
  const f4 = await computeFlag(secret, matrikel, 2, 4);
  const f5 = await computeFlag(secret, matrikel, 2, 5);

  // Flag-Hashes
  const [h1, h2, h3, h4, h5] = await Promise.all([
    sha256Hex(f1), sha256Hex(f2), sha256Hex(f3), sha256Hex(f4), sha256Hex(f5),
  ]);

  // F3 Coupon
  const coupon = await f3Coupon(secret, matrikel);
  const couponHash = await sha256Hex(coupon);

  // F4 XOR
  const flag4Bytes = toBytes(f4);
  const key = await xorKey(secret, matrikel, 2, 4, flag4Bytes.length);
  const cipher = new Uint8Array(flag4Bytes.length);
  for (let i = 0; i < flag4Bytes.length; i++) cipher[i] = flag4Bytes[i] ^ key[i];
  const cipherHex = bytesToHex(cipher);
  const keyB64 = bytesToB64(key);
  const obfuscatedCheck = btoa(F4_CHECK_BODY);

  // F5 Hidden Value (12 hex chars = 6 bytes)
  const hidden = await hexToken(secret, matrikel, 2, 5, 6, "f5_hidden");
  const hiddenHash = await sha256Hex(hidden);

  const placeholders = {
    NAME: name,
    MATRIKEL: matrikel,
    CH2_F1_FLAG: f1,
    CH2_F1_FLAG_HASH: h1,
    CH2_F2_FLAG: f2,
    CH2_F2_FLAG_HASH: h2,
    CH2_F3_FLAG: f3,
    CH2_F3_FLAG_HASH: h3,
    CH2_F3_COUPON: coupon,
    CH2_F3_COUPON_HASH: couponHash,
    // NOTE: CH2_F4_FLAG (Klartext) wird bewusst NICHT ausgeliefert.
    CH2_F4_FLAG_HASH: h4,
    CH2_F4_FLAG_CIPHERTEXT_HEX: cipherHex,
    CH2_F4_XOR_KEY_B64: keyB64,
    CH2_F4_OBFUSCATED_CHECK: obfuscatedCheck,
    CH2_F5_FLAG: f5,
    CH2_F5_FLAG_HASH: h5,
    CH2_F5_HIDDEN_VALUE: hidden,
    CH2_F5_HIDDEN_VALUE_HASH: hiddenHash,
  };

  return json({ ok: true, placeholders });
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
