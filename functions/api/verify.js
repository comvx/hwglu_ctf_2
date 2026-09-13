// Cloudflare Pages Function: POST /api/verify
//
// Nimmt eine eingereichte Flag entgegen, parst
//   FLAG{<session_id>-<unix_ts>-<hmac16>}
// und prüft für jeden möglichen flag_index (1..5), ob der HMAC stimmt.
//
// Rückgabe:
//   { ok: true,  session_id, unix_ts, flag_index }   // Flag ist echt
//   { ok: false, reason: "..." }                     // Format, HMAC, oder TS-Range falsch
//
// Es wird KEINE Matrikelnummer geprüft — die Zuordnung Session ↔ Student
// passiert erst im Moodle-Formular (Student trägt Matrikel + Session-ID +
// Flags ein; Dozent verifiziert via CSV-Export lokal).

const FLAG_HEX_LEN = 16;

// Timestamp-Plausibilität: Flag darf nicht in der Zukunft und nicht
// älter als 1 Jahr sein. Verhindert absurde Test-Payloads.
const MAX_AGE_SECONDS   = 365 * 24 * 3600;
const CLOCK_SKEW_FUTURE = 300;

async function hmacSha256(keyBytes, msgBytes) {
  const key = await crypto.subtle.importKey(
    "raw", keyBytes, { name: "HMAC", hash: "SHA-256" }, false, ["sign"],
  );
  const sig = await crypto.subtle.sign("HMAC", key, msgBytes);
  return new Uint8Array(sig);
}

function toBytes(str) { return new TextEncoder().encode(str); }

function bytesToHex(b) {
  return [...b].map(v => v.toString(16).padStart(2, "0")).join("");
}

async function computeFlagHmac(secret, session_id, unix_ts, flag_index) {
  const material = `${session_id}|${String(flag_index)}|${String(unix_ts)}`;
  const d = await hmacSha256(secret, toBytes(material));
  return bytesToHex(d).slice(0, FLAG_HEX_LEN);
}

function loadSecret(raw) {
  if (!raw) throw new Error("MASTER_SECRET env var not set");
  const hex = raw.trim();
  if (/^[0-9a-fA-F]+$/.test(hex) && hex.length >= 32 && hex.length % 2 === 0) {
    const out = new Uint8Array(hex.length / 2);
    for (let i = 0; i < out.length; i++) out[i] = parseInt(hex.substr(i * 2, 2), 16);
    return out;
  }
  const utf8 = toBytes(raw);
  if (utf8.length < 16) throw new Error("MASTER_SECRET too short");
  return utf8;
}

function timingSafeEqualStr(a, b) {
  if (a.length !== b.length) return false;
  let diff = 0;
  for (let i = 0; i < a.length; i++) diff |= a.charCodeAt(i) ^ b.charCodeAt(i);
  return diff === 0;
}

export async function onRequestPost({ request, env }) {
  let body;
  try { body = await request.json(); }
  catch { return json({ ok: false, reason: "invalid JSON" }, 400); }

  const flag = String((body && body.flag) || "").trim();

  // Format: FLAG{<8hex>-<digits>-<16hex>}
  const m = flag.match(/^FLAG\{([0-9a-f]{8})-(\d{1,20})-([0-9a-f]{16})\}$/);
  if (!m) {
    return json({ ok: false, reason: "format" });
  }
  const session_id = m[1];
  const unix_ts    = Number(m[2]);
  const claimHmac  = m[3];

  if (!Number.isFinite(unix_ts) || unix_ts <= 0) {
    return json({ ok: false, reason: "bad_timestamp" });
  }

  const now = Math.floor(Date.now() / 1000);
  if (unix_ts > now + CLOCK_SKEW_FUTURE) {
    return json({ ok: false, reason: "timestamp_in_future" });
  }
  if (now - unix_ts > MAX_AGE_SECONDS) {
    return json({ ok: false, reason: "timestamp_too_old" });
  }

  let secret;
  try { secret = loadSecret(env.MASTER_SECRET); }
  catch (e) { return json({ ok: false, reason: "server_misconfigured: " + e.message }, 500); }

  // Iteriere flag_index 1..5 und finde matchendes HMAC.
  for (let i = 1; i <= 5; i++) {
    const expected = await computeFlagHmac(secret, session_id, unix_ts, i);
    if (timingSafeEqualStr(claimHmac, expected)) {
      return json({ ok: true, session_id, unix_ts, flag_index: i });
    }
  }
  return json({ ok: false, reason: "hmac_mismatch" });
}

export function onRequestOptions() {
  return new Response(null, {
    status: 204,
    headers: {
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
    },
  });
}
