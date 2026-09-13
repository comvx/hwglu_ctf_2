# HWG-LU CTF Challenge 2 — Web-Attacks

Cloudflare Pages Site für Challenge 2 (Client-side Web-Attacks) des HWG-LU
IT-Sicherheit-Kurses (WS 2025/26).

**Flow (v3, Session-Cookie-basiert):**
Studierender öffnet URL → Browser wird automatisch von Cloudflare-Function
mit einem HttpOnly-Session-Cookie (`hwglu_sid`) ausgestattet → `/api/flags`
berechnet 18 personalisierte Placeholder-Werte per HMAC-SHA256 aus
`MASTER_SECRET`, `session_id` und aktuellem `unix_ts` (Sekunden) →
Challenge-HTML wird mit diesen Werten gerendert → 5 Flags zu erobern.
Jede Flag trägt Session-ID und Timestamp bereits im Klartext:
`FLAG{<session_id>-<unix_ts>-<hmac16>}`.

## Was hat sich gegenüber v2 geändert?

| v2 (matrikel-basiert)                        | v3 (session-cookie-basiert)              |
|----------------------------------------------|------------------------------------------|
| Student tippt Matrikel-Nr. auf Landing       | Kein Prompt — direkt Boot-Sequence + Challenge |
| Flag-Formel: `hmac(sec, matrikel\|chall\|N)` | `hmac(sec, session_id\|N\|unix_ts)`      |
| Flag-Format: `FLAG{16hex}`                   | `FLAG{<sid>-<unix_ts>-<hmac16>}`         |
| Zuordnung Flag↔Student via Matrikel im Flag  | via Session-ID im Flag; Student pflegt Matrikel im Moodle-Formular |
| Verify verlangt Matrikel + flag_n            | Verify parst Flag selbst, iteriert flag_index 1..5 |

## Struktur

```
├── functions/
│   └── api/
│       ├── flags.js         # GET/POST /api/flags  – Cookie setzen + Placeholders
│       └── verify.js        # POST /api/verify     – Flag-Signatur prüfen
├── public/
│   ├── index.html           # CRT-Terminal Landing (kein UID-Prompt mehr)
│   └── challenge.html       # Challenge-Template + Session-Report + Copy-Button
├── package.json
├── README.md
└── .gitignore
```

## Cloudflare Pages Setup

### 1. Projekt anlegen

Im Cloudflare Dashboard → **Workers & Pages** → **Create** →
**Pages** → **Connect to Git**.

### 2. Build-Konfiguration

| Setting                     | Wert                          |
|-----------------------------|-------------------------------|
| **Framework preset**        | *None*                        |
| **Build command**           | `npm run build` *(no-op ok)*  |
| **Build output directory**  | `public`                      |
| **Root directory**          | `/` (Repo-Root)               |

Die `functions/`-Directory wird automatisch als Pages Functions erkannt —
kein zusätzliches Setup nötig.

### 3. Environment Variables

**Settings → Environment variables → Production**:

| Name            | Wert                                             |
|-----------------|--------------------------------------------------|
| `MASTER_SECRET` | Hex-String, ≥ 32 hex chars (empfohlen 64+)       |

Als **Secret / Encrypted** markieren:

```bash
openssl rand -hex 32
# → 7f4c...        (in dashboard einfügen)
```

**WICHTIG:** Bei Rotation des `MASTER_SECRET` werden ALLE bereits
ausgegebenen Flags ungültig — nur zwischen Semestern rotieren, nicht
während laufender Challenge.

### 4. Deploy

Nach dem ersten Push wird automatisch deployed. Alle weiteren
Commits triggern Rebuilds.

## Lokal entwickeln

```bash
# einmalig
npm install -g wrangler        # oder: npx wrangler ...

# .dev.vars anlegen (nicht committen!)
echo 'MASTER_SECRET=deadbeef...' > .dev.vars

# starten
npm run dev
# → http://localhost:8788
```

Wrangler serviert `public/` statisch und führt Functions unter `/api/*`
aus — identische Semantik zu Production.

## API

### `POST /api/flags` (auch `GET` möglich)

Erzeugt eine neue Session (oder reused existierende, wenn Cookie vorhanden)
und liefert 18 Placeholder + Session-Metadata.

**Request:**
Body ist leer / optional `{}`. Der Client MUSS `credentials: "same-origin"`
setzen, damit das Cookie mitgeschickt wird.

**Response:**
```json
{
  "ok": true,
  "session_id": "a3f9b2c1",
  "unix_ts": 1731679425,
  "session_start": "2024-11-15 14:23:45 UTC",
  "placeholders": {
    "SESSION_ID": "a3f9b2c1",
    "SESSION_UNIX_TS": "1731679425",
    "SESSION_START": "2024-11-15 14:23:45 UTC",
    "CH2_F1_FLAG": "FLAG{a3f9b2c1-1731679425-e8f2d9a4b1c3e7f8}",
    "CH2_F1_FLAG_HASH": "...",
    "...": "..."
  }
}
```

Response setzt `Set-Cookie: hwglu_sid=<sid>; HttpOnly; Secure; SameSite=Strict; Path=/; Max-Age=2592000`.

Alle 18 CH2_-Placeholder aus der ursprünglichen `PLACEHOLDERS.md` sind gesetzt,
mit einer Ausnahme: `CH2_F4_FLAG` (Klartext) wird bewusst NICHT ausgeliefert —
nur `CH2_F4_FLAG_HASH`, `CH2_F4_FLAG_CIPHERTEXT_HEX`, `CH2_F4_XOR_KEY_B64` und
`CH2_F4_OBFUSCATED_CHECK`.

**Wichtig für Konsistenz:** Alle 5 Flags eines Response teilen denselben
`unix_ts`. Ein Reload/zweiter Fetch mit demselben Cookie liefert einen NEUEN
Timestamp und damit NEUE Flags — die Session-ID bleibt aber gleich.
Studierende werden ihre Flags typischerweise aus dem ersten Fetch nutzen
(der beim Öffnen der Seite passiert und im Session-Report gespeichert wird).

### `POST /api/verify`

Prüft, ob eine eingereichte Flag echt ist.

**Request:**
```json
{ "flag": "FLAG{a3f9b2c1-1731679425-e8f2d9a4b1c3e7f8}" }
```

**Response (Success):**
```json
{ "ok": true, "session_id": "a3f9b2c1", "unix_ts": 1731679425, "flag_index": 1 }
```

**Response (Failure):**
```json
{ "ok": false, "reason": "hmac_mismatch" }
```

`reason` kann sein: `format`, `bad_timestamp`, `timestamp_in_future`,
`timestamp_too_old`, `hmac_mismatch`.

## Flag-Personalisierung

Die 18 Placeholder werden per HMAC-SHA256 aus
`(MASTER_SECRET, session_id, unix_ts, flag_index, salt_purpose)` abgeleitet.

Flag-Formel:
```
material   = "<session_id>|<flag_index>|<unix_ts>"
hmac16     = HMAC-SHA256(secret, material).hex[:16]
flag       = "FLAG{" + session_id + "-" + unix_ts + "-" + hmac16 + "}"
```

Alle Ableitungen (Coupon-Wörter, PIN, Vigenère-Key, XOR-Key, F5-Hidden-Value)
laufen über eine einheitliche Derive-Funktion:
```
derive(sid, ts, flag_index, salt_purpose)
  = HMAC-SHA256(secret, "<sid>|<ts>|<flag_index>|<salt_purpose>").hex
```

Das garantiert: dieselbe Session + derselbe Timestamp erzeugt dieselben
Puzzle-Werte, aber jede Session bekommt ihre eigenen — Absprache/Copy
zwischen Studierenden wird sofort sichtbar (fremde Session-ID im Flag).

- **Flag 1:** Steht im HTML-Kommentar + `data-note`-Attribut.
- **Flag 2:** LocalStorage-Login (`role=guest→admin` bypass).
- **Flag 3:** Coupon `word-4digits-word` — passt bewusst nicht auf
  die naive Regex `^[A-Z]{4}-\d{4}$`.
- **Flag 4:** XOR-Ciphertext (hex) + XOR-Key (base64) +
  obfuskierter Check (base64 JS-Body). Klartext-Flag nur nach
  Prototype-Pollution-Exploit berechenbar.
- **Flag 5:** Hidden-Value als HTML-Kommentar; DOM Clobbering
  über `<form id="appConfig"><input name="unlockFlag" value="...">`.

## Sicherheitsmodell

- **`MASTER_SECRET`** verlässt die Cloudflare-Function nie.
- **Cookie `hwglu_sid`** ist `HttpOnly` + `Secure` + `SameSite=Strict` —
  Student-JS hat KEINEN Zugriff auf die Session-ID über `document.cookie`.
  Die einzige Quelle für `session_id` im Frontend ist die JSON-Response,
  die vom Server explizit ausgeliefert wird.
- **`CH2_F4_FLAG`** (Klartext) wird nie ausgeliefert — Student muss
  die XOR-Attack ausführen um an die Flag zu kommen.
- Alle anderen Flags stehen zwar im HTML, sind aber **pro Session unique**.
  Trägt jemand die Flag eines Kommilitonen ein, sieht der Dozent im Moodle-
  Formular auf einen Blick, dass Matrikel und Session-ID nicht zueinander
  passen (fremde Session-ID im Flag) — oder dass zwei Studierende dieselbe
  Session-ID einreichen.
- Verify verlangt HMAC-Match (nicht brute-forcbar über SHA-256 auf 16 hex).
- Timestamp-Range-Check verhindert absurde Testeinsendungen (weit in Zukunft
  oder älter als 1 Jahr werden abgelehnt).

## Grading / Dozenten-Workflow

1. Studierender öffnet die Seite. Session-Cookie wird gesetzt, Session-ID
   und Timestamp erscheinen im Session-Report am Ende der Challenge-Seite.
2. Studierender löst 5 Flags und klickt "COPY REPORT" — bekommt einen
   fertigen Text-Block mit Session-ID + Timestamp + alle 5 Flags.
3. Studierender fügt in Moodle ein: seine Matrikelnummer + den Report-Block.
4. Dozent exportiert CSV aus Moodle.
5. Lokales `verify.py`-Skript (nutzt `MASTER_SECRET`) validiert jede
   eingereichte Flag:
   - Ist die HMAC-Signatur korrekt? (Beweis: Flag stammt aus unserer Instanz)
   - Ist die Session-ID in dieser Zeile eindeutig für eine Matrikelnummer?
     Falls zwei Matrikelnummern dieselbe Session-ID einreichen → Kopie.
   - Liegt der Timestamp im plausiblen Bereich (Semester-Zeitraum)?

## Verwandte Dateien

- `SOLUTION.md`     — Dozenten-Lösung (im Kurs-Repo)
- `verify.py`       — Offline-Validator + CSV-Auswertung (im Kurs-Repo)

## Lizenz

Kurs-internes Material. Keine öffentliche Wiederverwendung ohne
Rücksprache mit dem Dozenten.
