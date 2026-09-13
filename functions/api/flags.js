// Cloudflare Pages Function: GET/POST /api/flags
//
// Session-Cookie + Per-Second-Timestamp Modell:
//   * Kein Matrikel-Input mehr.
//   * Beim ersten Request: neue session_id (8 hex chars) wird erzeugt und
//     via HttpOnly-Cookie `hwglu_sid` an den Client gesetzt.
//   * Bei folgenden Requests: Cookie wird gelesen; wenn valide wird die
//     bestehende Session weiterverwendet, sonst wird eine neue erzeugt.
//   * Alle Flags eines Response teilen den GLEICHEN unix_ts (Sekunden seit
//     Epoch) — der wird pro Request einmal berechnet und für alle 5 Flags
//     verwendet.
//
// Flag-Format:
//   FLAG{<session_id>-<unix_ts>-<hmac16>}
//     hmac16 = HMAC-SHA256(MASTER_SECRET, "<session_id>|<flag_index>|<unix_ts>").slice(0,16)
//
// Sicherheits-Modell:
//   * MASTER_SECRET als Cloudflare Pages Secret gesetzt, verlässt Function nie.
//   * Cookie ist HttpOnly + Secure + SameSite=Strict → Student-JS kann Session
//     nicht auslesen oder faken.
//   * Der Klartext-Flag für F4 (XOR) wird NICHT ausgeliefert — nur Cipher+Key.

const FLAG_HEX_LEN = 16;

// Wortliste für Coupon-Codes (F3) — identisch zu vorherigem Setup.
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
// Kern-Crypto
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

function bytesToHex(bytes) {
  return [...bytes].map(b => b.toString(16).padStart(2, "0")).join("");
}

function bytesToB64(bytes) {
  let bin = "";
  for (let i = 0; i < bytes.length; i++) bin += String.fromCharCode(bytes[i]);
  return btoa(bin);
}

// -----------------------------------------------------------------------
// Master Derivation Function
//
//   derive(session_id, unix_ts, flag_index, salt_purpose) → hex hmac
//
// Alle personalisierten Werte (Hashes, Wortlisten-Indizes, PINs, Vigenère-
// Keys, XOR-Keys, RSA-Parameter, …) werden aus dieser einzigen Funktion
// abgeleitet. Damit sind zwei Werte NUR DANN gleich, wenn session_id,
// unix_ts, flag_index und salt_purpose alle übereinstimmen.
// -----------------------------------------------------------------------
async function derive(secret, session_id, unix_ts, flag_index, salt_purpose) {
  const material = `${session_id}|${String(unix_ts)}|${String(flag_index)}|${salt_purpose}`;
  const d = await hmacSha256(secret, toBytes(material));
  return bytesToHex(d);
}

// Deterministic bytes für XOR-Key etc.
async function deriveBytes(secret, session_id, unix_ts, flag_index, salt_purpose, length) {
  const parts = [];
  let counter = 0;
  let total = 0;
  while (total < length) {
    const material = `${session_id}|${String(unix_ts)}|${String(flag_index)}|${salt_purpose}|${counter}`;
    const d = await hmacSha256(secret, toBytes(material));
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
// Flag-Berechnung
//   FLAG{<session_id>-<unix_ts>-<hmac16>}
// -----------------------------------------------------------------------
async function computeFlag(secret, session_id, unix_ts, flag_index) {
  const material = `${session_id}|${String(flag_index)}|${String(unix_ts)}`;
  const d = await hmacSha256(secret, toBytes(material));
  const hmac16 = bytesToHex(d).slice(0, FLAG_HEX_LEN);
  return `FLAG{${session_id}-${unix_ts}-${hmac16}}`;
}

// -----------------------------------------------------------------------
// F3 — Coupon:  <word>-<4digits>-<word>
// -----------------------------------------------------------------------
async function f3Coupon(secret, session_id, unix_ts) {
  const w1Hex = await derive(secret, session_id, unix_ts, 3, "cpn_w1");
  const w2Hex = await derive(secret, session_id, unix_ts, 3, "cpn_w2");
  const numHex = await derive(secret, session_id, unix_ts, 3, "cpn_num");
  const idx1 = parseInt(w1Hex.slice(0, 8), 16) % F3_WORDS.length;
  const idx2 = parseInt(w2Hex.slice(0, 8), 16) % F3_WORDS.length;
  const num  = parseInt(numHex.slice(0, 8), 16) % 10000;
  return `${F3_WORDS[idx1]}-${String(num).padStart(4, "0")}-${F3_WORDS[idx2]}`;
}

// -----------------------------------------------------------------------
// Secret-Loader
// -----------------------------------------------------------------------
function loadSecret(raw) {
  if (!raw) throw new Error("MASTER_SECRET env var not set");
  const hex = raw.trim();
  if (/^[0-9a-fA-F]+$/.test(hex) && hex.length >= 32 && hex.length % 2 === 0) {
    const out = new Uint8Array(hex.length / 2);
    for (let i = 0; i < out.length; i++) {
      out[i] = parseInt(hex.substr(i * 2, 2), 16);
    }
    return out;
  }
  const utf8 = toBytes(raw);
  if (utf8.length < 16) throw new Error("MASTER_SECRET too short (need >=16 bytes)");
  return utf8;
}

// -----------------------------------------------------------------------
// Cookie parsing + session-id extraction
// -----------------------------------------------------------------------
function parseCookies(header) {
  const out = {};
  if (!header) return out;
  header.split(/;\s*/).forEach(pair => {
    const eq = pair.indexOf("=");
    if (eq < 0) return;
    out[pair.slice(0, eq)] = pair.slice(eq + 1);
  });
  return out;
}

function newSessionId() {
  // 8 hex chars aus crypto.randomUUID (strip dashes, slice)
  return crypto.randomUUID().replace(/-/g, "").slice(0, 8);
}

function isValidSessionId(s) {
  return typeof s === "string" && /^[0-9a-f]{8}$/.test(s);
}

// -----------------------------------------------------------------------
// Handler — akzeptiert GET und POST (POST für backwards-compat mit alten
// Clients; GET reicht weil kein Body mehr nötig ist).
// -----------------------------------------------------------------------
async function handle(request, env) {
  let secret;
  try { secret = loadSecret(env.MASTER_SECRET); }
  catch (e) { return json({ error: "server misconfigured: " + e.message }, 500); }

  // Session-ID: aus Cookie oder frisch erzeugen
  const cookies = parseCookies(request.headers.get("Cookie") || "");
  let session_id = cookies.hwglu_sid;
  let isNewSession = false;
  if (!isValidSessionId(session_id)) {
    session_id = newSessionId();
    isNewSession = true;
  }

  const unix_ts = Math.floor(Date.now() / 1000);

  // Flags 1..5 — alle mit demselben unix_ts
  const [f1, f2, f3, f4, f5] = await Promise.all([
    computeFlag(secret, session_id, unix_ts, 1),
    computeFlag(secret, session_id, unix_ts, 2),
    computeFlag(secret, session_id, unix_ts, 3),
    computeFlag(secret, session_id, unix_ts, 4),
    computeFlag(secret, session_id, unix_ts, 5),
  ]);

  // Flag-Hashes
  const [h1, h2, h3, h4, h5] = await Promise.all([
    sha256Hex(f1), sha256Hex(f2), sha256Hex(f3), sha256Hex(f4), sha256Hex(f5),
  ]);

  // F3 Coupon (aus session_id + unix_ts abgeleitet)
  const coupon = await f3Coupon(secret, session_id, unix_ts);
  const couponHash = await sha256Hex(coupon);

  // F4 XOR-Cipher aus Klartext-Flag berechnen
  const flag4Bytes = toBytes(f4);
  const key = await deriveBytes(secret, session_id, unix_ts, 4, "xor", flag4Bytes.length);
  const cipher = new Uint8Array(flag4Bytes.length);
  for (let i = 0; i < flag4Bytes.length; i++) cipher[i] = flag4Bytes[i] ^ key[i];
  const cipherHex = bytesToHex(cipher);
  const keyB64 = bytesToB64(key);
  const obfuscatedCheck = btoa(F4_CHECK_BODY);

  // F5 Hidden-Value (12 hex chars = 6 bytes)
  const hiddenBytes = await deriveBytes(secret, session_id, unix_ts, 5, "hidden", 6);
  const hidden = bytesToHex(hiddenBytes);
  const hiddenHash = await sha256Hex(hidden);

  // Human-lesbarer Session-Start-String (UTC)
  const startedIso = new Date(unix_ts * 1000).toISOString()
    .replace("T", " ").slice(0, 19) + " UTC";

  const placeholders = {
    SESSION_ID: session_id,
    SESSION_UNIX_TS: String(unix_ts),
    SESSION_START: startedIso,
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

  const body = JSON.stringify({
    ok: true,
    session_id,
    unix_ts,
    session_start: startedIso,
    placeholders,
  });

  const headers = {
    "Content-Type": "application/json; charset=utf-8",
    "Cache-Control": "no-store",
  };

  // Cookie IMMER setzen (auch bei recycled session) — Refresh der Max-Age.
  // HttpOnly + Secure + SameSite=Strict → Student-JS hat keinen Zugriff.
  const cookieVal = [
    `hwglu_sid=${session_id}`,
    "HttpOnly",
    "Secure",
    "SameSite=Strict",
    "Path=/",
    "Max-Age=2592000", // 30 Tage
  ].join("; ");
  headers["Set-Cookie"] = cookieVal;

  return new Response(body, { status: 200, headers });
}

export const onRequestGet  = ({ request, env }) => handle(request, env);
export const onRequestPost = ({ request, env }) => handle(request, env);

export function onRequestOptions() {
  return new Response(null, {
    status: 204,
    headers: {
      "Access-Control-Allow-Methods": "GET, POST, OPTIONS",
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
    },
  });
}
