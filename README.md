# secure-file-share

A small Spring Boot service for sharing files securely. You upload a file, the server
**encrypts it with AES-256-GCM**, and hands back a **one-time-ish link** that **expires** by
time and by download count. Optionally protect a file with a **password** - then the file is
wrapped with a key derived from that password via **Argon2id**, so *not even the server* can
read it without the password. Or turn on **end-to-end encryption**: the browser encrypts the
file (and its name) with **WebCrypto** before upload and puts the key in the link's
`#fragment` - which browsers never send to the server - so the server only ever stores an
opaque blob. Expired shares are cleaned up automatically.

Ships with a small **web UI** (EN/PL/DE) on top of a clean REST API: an upload form with a live
progress bar and a **QR code** for the link, and a download page with an **expiry countdown** and
password prompt.

Built to demonstrate practical backend security: authenticated encryption, envelope
encryption, memory-hard password KDF, hashed secret tokens, TTL/quota expiry, constant-time
secret comparison, and no secrets in the codebase.

- **Stack:** Java 21 · Spring Boot 4.1 (Web MVC, Data JPA, Validation) · Maven
- **DB:** H2 (embedded) for dev/test · PostgreSQL for the `prod` profile
- **Crypto:** AES-256-GCM (JDK `javax.crypto`) · Argon2id (Bouncy Castle)

---

## Architecture

Envelope encryption: every file is encrypted with a fresh random **data-encryption key (DEK)**;
the DEK is then *wrapped* (encrypted) with either the server master key or a password-derived key.

```
POST /api/files ──► ApiKeyFilter ──► FileController ──► FileShareService
   (multipart)        (X-Api-Key)                          │
                                                           ├─ EncryptionService  (AES-256-GCM)
                                                           ├─ KeyService         (random DEK · Argon2id from password)
                                                           ├─ FileStorageService (ciphertext ─► disk, UUID name)
                                                           ├─ TokenService       (256-bit token, SHA-256 hash)
                                                           └─ StoredFileRepository (metadata + wrapped DEK ─► DB)
                                                           ▼
                                          { downloadUrl, token, expiresAt, maxDownloads, passwordProtected }

GET /api/files/{token}/meta ─► filename, passwordProtected, expiresAt, downloadsRemaining  (does NOT consume)

GET /api/files/{token} ──► FileController ──► FileShareService
        (X-Download-Password?)                   ├─ hash token ─► look up row (locked)
                                                 ├─ enforce expiry (time) + download limit
                                                 ├─ resolve wrap key (master, or Argon2id(password))
                                                 ├─ unwrap DEK  (wrong password ⇒ GCM tag fails ⇒ 403)
                                                 ├─ decrypt ciphertext with DEK
                                                 └─ increment download count (only on success)
                                                 ▼  streamed file (Content-Disposition: attachment)

@Scheduled CleanupService ──► deletes expired rows + their blobs on disk
```

Package layout (`com.securefileshare`):

| Package     | Responsibility |
|-------------|----------------|
| `config`    | `SecurityProperties`, `ApiKeyFilter` (upload/revoke auth), `SecurityHeadersFilter`, `OpenApiConfig` |
| `web`       | `FileController`, `GlobalExceptionHandler`, `dto/UploadResponse` |
| `service`   | `EncryptionService`, `KeyService`, `TokenService`, `FileStorageService`, `FileShareService`, `CleanupService`, `DownloadAttemptLimiter` |
| `domain`    | `StoredFile` entity + `StoredFileRepository` |
| `exception` | `ShareNotFound` (404), `ShareExpired` (410), `PasswordRequired` (401), `InvalidPassword` (403), `TooManyAttempts` (429) |

Static web UI lives in `src/main/resources/static`: `index.html` (upload) and `download.html`
(prompts for a password when the share is protected). Both are localized EN/PL/DE.

## Security model

- **Encryption at rest (envelope).** Each file is encrypted with a **fresh random per-file DEK**
  using **AES-256-GCM** - an AEAD cipher that provides confidentiality *and* integrity, so a
  tampered ciphertext (or a wrong key) fails to decrypt rather than returning garbage. Each
  encryption uses a fresh random 12-byte IV.
- **Key wrapping.** The DEK is never stored in the clear. It is encrypted with:
  - the **server master key** (`SFS_ENCRYPTION_KEY`, Base64 256-bit, validated to 32 bytes on
    startup, never hard-coded) for anonymous shares; or
  - a key **derived from the user's password via Argon2id** for password-protected shares.
- **Password protection = zero-knowledge.** When a password is set, the DEK is wrapped *only*
  with the Argon2id-derived key. The server keeps no other copy, so **the server cannot decrypt
  the file without the password**. A wrong password makes the DEK unwrap fail (GCM auth) → `403`;
  it does **not** consume a download.
- **End-to-end encryption (browser).** With E2E on, the browser encrypts the file *and its
  filename* with a random AES-256-GCM key via WebCrypto **before** upload, and uploads only the
  opaque `[IV][ciphertext]` blob. The key is placed in the link's URL **`#fragment`**, which
  browsers never transmit - so the server (and its logs, and this codebase) never sees the key,
  the plaintext, or even the real filename. The blob is still wrapped with the master key at rest
  (defence in depth). E2E and the server-side password are mutually exclusive (the fragment key is
  the secret). Requires a secure context (HTTPS or localhost).
- **Argon2id KDF.** Memory-hard (OWASP baseline: 19 MiB, t=2, p=1), which resists GPU/ASIC
  brute-force far better than a plain PBKDF2. The algorithm + parameters are stored per share as
  a self-describing spec (e.g. `argon2id$v=19,m=19456,t=2,p=1`), so parameters can be raised over
  time while old shares stay decryptable (legacy `pbkdf2$…` specs are still understood).
- **Unguessable links, hashed at rest.** Each link carries a **256-bit** `SecureRandom` token
  (URL-safe Base64). Only the token's **SHA-256 hash** is stored, so a database leak exposes no
  working links.
- **Expiry two ways.** A share dies at `expiresAt` (TTL from upload, configurable and capped)
  **or** once `downloadCount` reaches `maxDownloads`. The check + increment run under a row lock,
  atomic across concurrent downloads. A `@Scheduled` job purges expired rows and their blobs.
- **Upload authentication.** Uploads require a valid `X-Api-Key` header, compared in **constant
  time** (`MessageDigest.isEqual`). Downloads are anonymous - the token is the credential; the
  download password (if any) travels in the `X-Download-Password` header, never in the URL.
- **Password attempt throttling.** Wrong-password attempts are counted per link; after
  `sfs.max-password-attempts` the link is locked for `sfs.password-lockout-minutes` and returns
  `429` with a `Retry-After` header. Combined with Argon2id, this makes online guessing impractical.
- **Security headers.** Every response carries `Content-Security-Policy`, `X-Content-Type-Options:
  nosniff`, `X-Frame-Options: SAMEORIGIN`, `Referrer-Policy: no-referrer`, `Permissions-Policy`,
  and `Strict-Transport-Security` over HTTPS (see `SecurityHeadersFilter`).
- **Hardening.** Upload size capped; on-disk filenames are UUIDs under a fixed root (no path
  traversal); client filenames are sanitised; secrets are never logged; `storage/` and `.env`
  are git-ignored.

> **Threat-model notes / not-yet-done:** whole files are buffered in memory (bounded by the
> upload cap, not streamed); the master key is a single static key (no rotation); prod should
> serve over **HTTPS** (also required for browser E2E outside localhost) and use DB migrations
> (e.g. Flyway) instead of `ddl-auto`.

## Running it

Prerequisites: **JDK 21**. Maven is not required — the bundled wrapper (`./mvnw`) fetches it.

### Dev (H2, runs out of the box)

```bash
export SFS_ENCRYPTION_KEY=$(openssl rand -base64 32)   # PowerShell: see below
export SFS_API_KEY=dev-api-key
./mvnw spring-boot:run
```

Open **http://localhost:8080/** for the web UI: drag-and-drop upload, live progress bar, QR code,
language switch (EN/PL/DE) and a light/dark theme toggle. The generated link opens a **download
page** with an expiry countdown that prompts for the password / decrypts E2E as needed. Dev has
insecure fallback secrets baked into `application.yml` so it starts even without the env vars -
**do not rely on those outside dev.** Dev-only helpers: H2 console at `/h2-console`, Swagger UI at
`/swagger-ui.html`, health at `/actuator/health`.

PowerShell equivalent for the key:
```powershell
$bytes = New-Object byte[] 32; [Security.Cryptography.RandomNumberGenerator]::Create().GetBytes($bytes)
$env:SFS_ENCRYPTION_KEY = [Convert]::ToBase64String($bytes)
$env:SFS_API_KEY = "dev-api-key"
./mvnw spring-boot:run
```

### Prod (PostgreSQL)

Set `SPRING_PROFILES_ACTIVE=prod` and provide every secret via the environment
(`SFS_ENCRYPTION_KEY`, `SFS_API_KEY`, `SFS_STORAGE_DIR`, `SFS_DB_URL`, `SFS_DB_USER`,
`SFS_DB_PASSWORD`). See `.env.example`. In prod the schema is created by **Flyway**
(`db/migration/V1__init.sql`) and Hibernate only validates it. Dev/test run on H2 with Hibernate
schema generation, so the migration should be verified against a real PostgreSQL before deploying.

## API

### Upload - `POST /api/files`
Headers: `X-Api-Key: <key>` · Body: `multipart/form-data`

| Field          | Type | Required | Notes |
|----------------|------|----------|-------|
| `file`         | file | yes      | the file to share |
| `ttlHours`     | int  | no       | link lifetime; default 24, capped at `sfs.max-ttl-hours` |
| `maxDownloads` | int  | no       | download limit; default `sfs.default-max-downloads` |
| `password`     | text | no       | if set, enables Argon2id zero-knowledge protection |
| `e2e`          | bool | no       | mark the upload as already client-encrypted (browser E2E); disables server-side password |

```bash
curl -sS -H "X-Api-Key: dev-api-key" \
     -F "file=@secret.pdf" -F "maxDownloads=3" -F "ttlHours=48" -F "password=hunter2" \
     http://localhost:8080/api/files
# → 201 { "downloadUrl": "...", "token": "...", "expiresAt": "...", "maxDownloads": 3, "passwordProtected": true }
```

### Metadata - `GET /api/files/{token}/meta`
Non-consuming; lets a client know whether a password/E2E applies before downloading.
Returns `{ filename, passwordProtected, e2e, expiresAt, downloadsRemaining }`.

### Revoke — `DELETE /api/files/{token}`
Uploader-only (requires `X-Api-Key`). Permanently deletes the blob + metadata → `204`, or `404`
if unknown. **Burn after reading** = upload with `maxDownloads=1`; the share is deleted the instant
its single download completes (not left for the cleanup job).

Interactive API docs: **Swagger UI at `/swagger-ui.html`** (OpenAPI JSON at `/v3/api-docs`).
Health probe: **`/actuator/health`**.

### Download - `GET /api/files/{token}`
No API key; the token is the credential. For protected shares, send the password in the
`X-Download-Password` header.

```bash
curl -OJ -H "X-Download-Password: hunter2" "http://localhost:8080/api/files/<token>"
```

Responses: `200` file stream · `401` password required (or bad API key on upload) ·
`403` wrong password · `404` unknown token · `410` expired (time or limit) · `413` upload too large.

## Configuration (`sfs.*`)

| Key                         | Default     | Meaning |
|-----------------------------|-------------|---------|
| `sfs.encryption-key`        | (dev only)  | Base64 256-bit master key (`SFS_ENCRYPTION_KEY`) |
| `sfs.api-key`               | (dev only)  | upload API key (`SFS_API_KEY`) |
| `sfs.storage-dir`           | `./storage` | encrypted blob directory |
| `sfs.default-ttl-hours`     | `24`        | default link lifetime |
| `sfs.max-ttl-hours`         | `168`       | hard cap on requested lifetime |
| `sfs.default-max-downloads` | `5`         | default download limit |
| `sfs.cleanup-interval-ms`   | `300000`    | cleanup job interval |
| `sfs.public-base-url`       | (empty)     | base URL for links; else derived from the request |
| `sfs.max-password-attempts` | `5`         | wrong-password tries before a link is locked |
| `sfs.password-lockout-minutes` | `15`     | how long a link stays locked after too many tries |

Argon2id parameters live in `KeyService` (OWASP baseline) and are recorded per share.

## Tests

```bash
./mvnw test
```

Covers: AES-GCM round-trip + tamper/wrong-key detection + key-length validation; token
uniqueness/hashing; Argon2id determinism, salt independence, and legacy-PBKDF2 compatibility;
the full upload→download HTTP flow including the password path (401 / 403 / 200); API-key
rejection; unknown/expired tokens; and scheduled cleanup.
