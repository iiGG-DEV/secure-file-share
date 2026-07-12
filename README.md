# secure-file-share

A small Spring Boot service for sharing files securely. You upload a file, the server
**encrypts it with AES-256-GCM**, and hands back a **one-time-ish link** that **expires** by
time and by download count. Optionally protect a file with a **password** - then the file is
wrapped with a key derived from that password via **Argon2id**, so *not even the server* can
read it without the password. Expired shares are cleaned up automatically.

Ships with a small **web UI** (upload form + download page, EN/PL/DE) on top of a clean REST API.

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
| `config`    | `SecurityProperties` (typed `sfs.*` config), `ApiKeyFilter` (upload auth) |
| `web`       | `FileController`, `GlobalExceptionHandler`, `dto/UploadResponse` |
| `service`   | `EncryptionService`, `KeyService`, `TokenService`, `FileStorageService`, `FileShareService`, `CleanupService` |
| `domain`    | `StoredFile` entity + `StoredFileRepository` |
| `exception` | `ShareNotFound` (404), `ShareExpired` (410), `PasswordRequired` (401), `InvalidPassword` (403) |

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
- **Hardening.** Upload size capped; on-disk filenames are UUIDs under a fixed root (no path
  traversal); client filenames are sanitised; secrets are never logged; `storage/` and `.env`
  are git-ignored.

> **Threat-model notes / not-yet-done:** **no rate limiting on password attempts** - a memory-hard
> KDF slows each guess but an online limiter is still the right defence for weak passwords;
> whole files are buffered in memory (bounded by the upload cap, not streamed); the master key is
> a single static key (no rotation); prod should serve over **HTTPS** and use DB migrations
> (e.g. Flyway) instead of `ddl-auto`.

## Running it

Prerequisites: **JDK 21**. Maven is not required — the bundled wrapper (`./mvnw`) fetches it.

### Dev (H2, runs out of the box)

```bash
export SFS_ENCRYPTION_KEY=$(openssl rand -base64 32)   # PowerShell: see below
export SFS_API_KEY=dev-api-key
./mvnw spring-boot:run
```

Open **http://localhost:8080/** for the web UI (upload form; pick a language top-right). The
generated link opens a **download page** that prompts for the password when needed. Dev has
insecure fallback secrets baked into `application.yml` so it starts even without the env vars -
**do not rely on those outside dev.** The H2 console (dev only) is at `/h2-console`.

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
`SFS_DB_PASSWORD`). See `.env.example`.

## API

### Upload - `POST /api/files`
Headers: `X-Api-Key: <key>` · Body: `multipart/form-data`

| Field          | Type | Required | Notes |
|----------------|------|----------|-------|
| `file`         | file | yes      | the file to share |
| `ttlHours`     | int  | no       | link lifetime; default 24, capped at `sfs.max-ttl-hours` |
| `maxDownloads` | int  | no       | download limit; default `sfs.default-max-downloads` |
| `password`     | text | no       | if set, enables Argon2id zero-knowledge protection |

```bash
curl -sS -H "X-Api-Key: dev-api-key" \
     -F "file=@secret.pdf" -F "maxDownloads=3" -F "ttlHours=48" -F "password=hunter2" \
     http://localhost:8080/api/files
# → 201 { "downloadUrl": "...", "token": "...", "expiresAt": "...", "maxDownloads": 3, "passwordProtected": true }
```

### Metadata - `GET /api/files/{token}/meta`
Non-consuming; lets a client know whether a password is required before downloading.
Returns `{ filename, passwordProtected, expiresAt, downloadsRemaining }`.

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

Argon2id parameters live in `KeyService` (OWASP baseline) and are recorded per share.

## Tests

```bash
./mvnw test
```

Covers: AES-GCM round-trip + tamper/wrong-key detection + key-length validation; token
uniqueness/hashing; Argon2id determinism, salt independence, and legacy-PBKDF2 compatibility;
the full upload→download HTTP flow including the password path (401 / 403 / 200); API-key
rejection; unknown/expired tokens; and scheduled cleanup.
