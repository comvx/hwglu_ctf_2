# HWG-LU CTF Challenge 2 — Web-Attacks

Cloudflare Pages Site für Challenge 2 (Client-side Web-Attacks) des HWG-LU
IT-Sicherheit-Kurses (WS 2025/26).

**Flow:** Studierender öffnet URL → gibt Matrikelnummer ein →
Cloudflare-Function `/api/flags` berechnet 18 personalisierte
Placeholder-Werte per HMAC-SHA256 aus `MASTER_SECRET` + Matrikel →
Challenge-HTML wird mit diesen Werten gerendert → 5 Flags zu erobern.

## Struktur

```
├── functions/
│   └── api/
│       ├── flags.js         # POST /api/flags   – Placeholder-Berechnung
│       └── verify.js        # POST /api/verify  – Flag-Einreichungs-Check
├── public/
│   ├── index.html           # CRT-Terminal Landing (SESSION LOGIN)
│   └── challenge.html       # Challenge-Template mit 18 {{PLACEHOLDERS}}
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

Als **Secret / Encrypted** markieren. Beispiel:

```bash
openssl rand -hex 32
# → 7f4c...        (in dashboard einfügen)
```

**WICHTIG:** Derselbe `MASTER_SECRET` muss auch im Framework
(`framework/gen.py` / Verifier) gesetzt sein, damit die serverseitige
Prüfung reproduzierbar bleibt.

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

### `POST /api/flags`

Berechnet 18 Placeholder für eine Matrikelnummer.

**Request:**
```json
{ "matrikel": "12345678", "name": "optional" }
```

**Response:**
```json
{
  "ok": true,
  "placeholders": {
    "NAME": "...",
    "MATRIKEL": "12345678",
    "CH2_F1_FLAG": "FLAG{...}",
    "CH2_F1_FLAG_HASH": "...",
    "...": "..."
  }
}
```

Alle 18 Keys aus `PLACEHOLDERS.md` sind gesetzt — mit einer Ausnahme:
`CH2_F4_FLAG` (Klartext) wird **nicht** ausgeliefert. Nur Hash +
XOR-Ciphertext + Key. Der Klartext-Flag existiert im HTML gar nicht;
er wird erst client-seitig aus dem Prototype-Pollution-Exploit
entschlüsselt.

### `POST /api/verify` (Bonus)

Prüft eine Flag-Einreichung.

**Request:**
```json
{ "matrikel": "12345678", "flag_n": 3, "flag": "FLAG{...}" }
```

**Response:**
```json
{ "ok": true, "matrikel": "12345678", "flag_n": 3 }
```

## Personalisierung

Die 18 Placeholder werden **HMAC-basiert** aus
`(MASTER_SECRET, matrikel, challenge=2, flag_n)` abgeleitet — 1:1 Port
von `framework/flag_lib.py` nach JavaScript (Web Crypto API).

- **Flag 1:** Steht im HTML-Kommentar + `data-note`-Attribut.
- **Flag 2:** LocalStorage-Login (`role=guest→admin` bypass).
- **Flag 3:** Coupon `word-4digits-word` — passt bewusst nicht auf
  die naive Regex `^[A-Z]{4}-\d{4}$`.
- **Flag 4:** XOR-Ciphertext (hex) + XOR-Key (base64) +
  obfuskierter Check (base64 JS-Body). Klartext-Flag nur nach
  Prototype-Pollution-Exploit berechenbar.
- **Flag 5:** Hidden-Value als HTML-Kommentar; DOM Clobbering
  über `<form id="appConfig"><input name="unlockFlag" value="...">`.

Sitzungen persistieren via `sessionStorage` — Reload lädt direkt in
die Challenge zurück ohne UID neu einzugeben (`?logout=1` → reset).

## Sicherheitsmodell

- **`MASTER_SECRET`** verlässt die Cloudflare-Function nie.
- **`CH2_F4_FLAG`** (Klartext) wird nie ausgeliefert — Student muss
  die Attack ausführen um an die Flag zu kommen.
- Alle anderen Flags stehen zwar im HTML, sind aber **pro Matrikel
  unique**. Absprache/Copy fällt beim Verifier auf.
- Für 16-hex-Flags (64 bit) ist Brute-Force auf `sha256`-Hash
  nicht praktikabel.

## Verwandte Dateien

- `PLACEHOLDERS.md` — vollständige Placeholder-Liste (im Kurs-Repo)
- `SOLUTION.md`     — Dozenten-Lösung (im Kurs-Repo)
- `framework/flag_lib.py` — Python-Referenz-Implementierung

## Lizenz

Kurs-internes Material. Keine öffentliche Wiederverwendung ohne
Rücksprache mit dem Dozenten.
