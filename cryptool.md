# CRYPTOOL v3 — Feature Reference

An advanced desktop cryptography suite with a modern dark React-inspired GUI. Five dedicated tabs covering encryption, hashing, key management, password tools, and data analysis — all in a single Python file.

---

## Getting Started

```bash
pip install cryptography   # auto-installs on first run if missing
python3 cryptool.py
```

`tkinter` is bundled with Python's standard library. The only external dependency is `cryptography`.

On Windows the script auto-relaunches under `pythonw.exe` to hide the console window.

---

## Tabs

### 🔒 Cipher — Encrypt & Decrypt

The main tab. A fixed-width scrollable sidebar on the left holds all configuration; the right panel holds the input/output areas.

**Algorithm selector** groups ciphers by category with clickable cards that wrap onto new rows based on available space. The key/config area below swaps dynamically depending on which algorithm is selected.

**Algorithms:**

| Category | Algorithm | Notes |
|----------|-----------|-------|
| Authenticated | AES-256-GCM | Recommended. Auth tag detects tampering. |
| Authenticated | ChaCha20-Poly1305 | Fast stream cipher. Authenticated. |
| Authenticated | Fernet | Safe high-level AES-128-CBC + HMAC wrapper. |
| Symmetric | AES-256-CBC | Classic block cipher, PKCS7 padded. |
| Symmetric | AES-256-CTR | Stream mode, no padding required. |
| Legacy | Blowfish-CBC | 128-bit legacy block cipher. |
| Legacy | 3DES-CBC | 192-bit Triple DES legacy mode. |
| Asymmetric | RSA-OAEP | Encrypt with public key, decrypt with private key. |
| Classical | XOR | SHA-256 key-stretched XOR. Obfuscation only. |
| Classical | Caesar | Alphabetic shift cipher (1–25). |
| Classical | Vigenère | Polyalphabetic keyword cipher. |

All symmetric algorithms derive keys via **PBKDF2-HMAC-SHA256** (260,000 iterations, random 16-byte salt per operation).

**Output formats:** Base64, Hex, or Raw. Falls back to Base64 automatically if output is non-UTF-8.

**Actions:** Encrypt, Decrypt, Load File, Save Output, Swap input/output, Copy output.

---

### # Hash — Hashing & HMAC

**Text hashing** across 9 algorithms with character count and algorithm label in the result.

| Algorithm | Output Size |
|-----------|-------------|
| MD5 | 128-bit (32 hex chars) |
| SHA-1 | 160-bit (40 hex chars) |
| SHA-256 | 256-bit (64 hex chars) |
| SHA-384 | 384-bit (96 hex chars) |
| SHA-512 | 512-bit (128 hex chars) |
| SHA3-256 | 256-bit |
| SHA3-512 | 512-bit |
| BLAKE2b | 512-bit |
| BLAKE2s | 256-bit |

**File hashing** — select any file and hash its raw bytes. Result shows filename, file size, algorithm, and hex digest.

**HMAC signing** — sign a message with a secret key using HMAC-SHA256, HMAC-SHA512, HMAC-SHA1, or HMAC-MD5. Result shows algorithm, key length, message length, and hex digest.

---

### 🔑 Keys — Key Generation & Signing

**RSA key generation** — generates PKCS#8 PEM keypairs at 1024, 2048, or 4096-bit. Keys display in separate colour-coded text boxes (cyan for public, purple for private). Save both to a folder in one click.

**EC key generation** — elliptic curve keypairs for P-256, P-384, or P-521 curves.

**Ed25519 key generation** — modern Edwards-curve keypair for high-performance signing.

**RSA Sign & Verify panel** — three-column layout with message, key, and signature fields. Sign a message with a private key (PSS/SHA-256), then verify the Base64 signature against a public key with a live tick Valid / cross Invalid result label.

---

### ★ Password — Generator, Strength & KDF

Scrollable tab so all three sections are always accessible regardless of window height.

**Password Generator** — cryptographically secure random passwords using `secrets.choice`. Configurable length (8–128 via slider) and character sets: uppercase, lowercase, digits, symbols. Result displayed in a read-only monospace box with a Copy button.

**Password Strength Checker** — real-time analysis on every keystroke. Scores 0–7 across: minimum length, extended length, uppercase, lowercase, digits, special characters, and character variety. Displays a colour-coded strength label (Very Weak to Excellent), an animated fill bar, and a list of improvement tips.

**Key Derivation (KDF)** — derives a cryptographic key from a password with a randomly generated salt. Choose between PBKDF2-SHA256 or Scrypt, and key lengths of 16, 32, or 64 bytes. Output shows the algorithm, key length, salt (hex), and derived key (hex).

---

### ⚡ Analyzer — Text & Data Inspection

Paste any text, hash, ciphertext, or encoded string and get instant analysis.

**Statistics panel** — five stat cards showing character count, byte count, Shannon entropy, unique byte count, and printable character count.

**Format detection** — automatically identifies: valid Base64, valid hex, MD5/SHA-1/SHA-256/SHA-512 by length matching, PEM key or certificate headers, and Fernet token prefixes.

**Base64 decode preview** — if input is valid Base64, the decoded content is shown below (as UTF-8 text or hex if binary).

---

## GUI Design

- Zinc-950/900/800 dark colour palette (shadcn/ui-inspired)
- Indigo-500 accent for primary actions and selection states
- Fixed 300px sidebar in the Cipher tab — never resizable, cards always visible
- Algorithm cards wrap onto new rows on narrow sidebars (flex-wrap equivalent)
- Toast notifications slide in at the bottom — colour-coded, auto-dismiss after 6 seconds with a manual close button
- Tab bar with indigo underline indicator for the active tab
- All text areas have a focus-ring highlight on the active input
- Password fields have a toggle eye button for show/hide

---

## Key Derivation Details

```
Symmetric key  = PBKDF2-HMAC-SHA256(password, random_salt_16B, iterations=260_000)
Scrypt key     = Scrypt(password, random_salt_16B, N=2^15, r=8, p=1)
```

Salt is prepended to ciphertext and read back automatically on decrypt — you only need the password.

---

## Algorithm Selection Guide

```
Strong authenticated encryption?     → AES-256-GCM
Fast authenticated stream?           → ChaCha20-Poly1305
Safe, hard-to-misuse symmetric?      → Fernet
Encrypt for someone else?            → RSA-OAEP (give them your public key)
Sign a message?                      → Keys tab → RSA Sign
Legacy system compatibility?         → AES-256-CBC, Blowfish-CBC, 3DES-CBC
Quick obfuscation (not secure)?      → XOR, Caesar, Vigenère
Hash a file for integrity check?     → Hash tab → Hash File → SHA-256
Verify a password is strong enough?  → Password tab → Strength Checker
Derive a key from a passphrase?      → Password tab → KDF → PBKDF2 or Scrypt
```

---

## Dependencies

| Package | Purpose | Required |
|---------|---------|---------|
| `cryptography` | AES, RSA, ChaCha20, Fernet, Blowfish, 3DES, EC, Ed25519, PBKDF2, Scrypt, HMAC | Yes — auto-installed |
| `tkinter` | GUI framework | Built into Python stdlib |
| `hashlib`, `secrets`, `base64`, `hmac` | Hashing, random bytes, encoding, HMAC | Built into Python stdlib |

---

## Security Notes

- Caesar, Vigenère, and XOR are **not cryptographically secure** — for learning and obfuscation only
- Blowfish and 3DES are **legacy algorithms** — prefer AES-256-GCM for new work
- All symmetric algorithms generate a fresh random salt and IV per operation — identical passwords never produce identical ciphertext
- RSA and EC key material is held in memory only — never written to disk unless you explicitly save via the Keys tab
- PBKDF2 uses 260,000 iterations (above the 2023 OWASP minimum of 210,000 for SHA-256)

---

## Module Structure

```
CRYPTOOL v3
├── Cipher
│   ├── Authenticated:  AES-256-GCM · ChaCha20-Poly1305 · Fernet
│   ├── Symmetric:      AES-256-CBC · AES-256-CTR
│   ├── Legacy:         Blowfish-CBC · 3DES-CBC
│   ├── Asymmetric:     RSA-OAEP (1024 / 2048 / 4096-bit)
│   └── Classical:      XOR · Caesar · Vigenère
├── Hash
│   ├── Text hash:      MD5 · SHA-1 · SHA-256/384/512 · SHA3-256/512 · BLAKE2b · BLAKE2s
│   ├── File hash:      any file, any of the above algorithms
│   └── HMAC:           SHA-256 · SHA-512 · SHA-1 · MD5
├── Keys
│   ├── RSA keygen:     1024 / 2048 / 4096-bit, PKCS#8 PEM
│   ├── EC keygen:      P-256 · P-384 · P-521
│   ├── Ed25519 keygen
│   └── RSA Sign/Verify: PSS/SHA-256
├── Password
│   ├── Generator:      length 8–128, configurable charset
│   ├── Strength:       real-time score + improvement tips
│   └── KDF:            PBKDF2-SHA256 · Scrypt, 16/32/64-byte output
└── Analyzer
    ├── Statistics:     length · bytes · entropy · unique bytes · printable
    ├── Format detect:  Base64 · Hex · MD5/SHA hashes · PEM · Fernet
    └── B64 preview:    decode and display Base64 content inline
```
