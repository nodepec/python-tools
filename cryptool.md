# CRYPTOOL — Feature Reference

An advanced desktop encryption and decryption suite with a dark amber-on-black terminal GUI. Supports 10 cipher algorithms across symmetric, asymmetric, and classical categories — all in a single Python file.

---

## Getting Started

```bash
pip install cryptography   # auto-installs on first run if missing
python3 cryptool.py
```

`tkinter` is bundled with Python's standard library. The only external dependency is `cryptography`.

---

## Algorithms

### Symmetric Encryption

All symmetric algorithms derive their key from a password using **PBKDF2-HMAC-SHA256** with 260,000 iterations and a random 16-byte salt per operation. This means the same password produces a different ciphertext every time.

| Algorithm | Mode | Key Size | Notes |
|-----------|------|----------|-------|
| AES-256-GCM | Authenticated | 256-bit | Recommended. Detects tampering via GCM auth tag. |
| AES-256-CBC | Block | 256-bit | Classic mode, PKCS7 padded. No authentication. |
| ChaCha20-Poly1305 | Authenticated stream | 256-bit | Fast on devices without AES hardware acceleration. |
| Fernet | Block + HMAC | 128-bit AES + HMAC-SHA256 | High-level safe wrapper, timestamp-signed tokens. |
| Blowfish-CBC | Block | 128-bit | Legacy cipher, 8-byte block size, PKCS7 padded. |
| 3DES-CBC | Block | 192-bit | Triple DES legacy mode, 8-byte block, PKCS7 padded. |
| XOR | Stream | SHA-256 stretched | Key is SHA-256 of password, XOR'd cyclically. Simple but fast. |

---

### Asymmetric Encryption

| Algorithm | Padding | Hash | Notes |
|-----------|---------|------|-------|
| RSA-OAEP | OAEP + MGF1 | SHA-256 | Encrypt with public key, decrypt with private key. |

**Key sizes available:** 1024-bit, 2048-bit, 4096-bit

RSA keys can be:
- Generated in-app and used immediately
- Loaded from existing `.pem` files
- The public and private key fields are separate — paste each independently

> RSA-OAEP has a plaintext size limit based on key size. For large data, use a symmetric algorithm instead.

---

### Classical Ciphers

Classical ciphers operate on text directly and do not use the output format selector (Base64/Hex/Raw).

| Algorithm | Type | Key Input |
|-----------|------|-----------|
| Caesar | Monoalphabetic shift | Shift value 1–25 via spinner |
| Vigenère | Polyalphabetic keyword | Keyword entered in the password field |

Both support encrypt and decrypt — Caesar reverses the shift, Vigenère reverses the key application. Non-alphabetic characters (spaces, punctuation, numbers) are passed through unchanged.

---

## Key Derivation

For all symmetric algorithms, the password is never used directly as the key. Instead:

```
Key = PBKDF2-HMAC-SHA256(password, random_salt, iterations=260_000, length=<algo_bits>)
```

A fresh random salt is generated for every encryption operation, so identical passwords never produce identical ciphertext. The salt is prepended to the ciphertext and read back automatically during decryption.

---

## Output Formats

The output format selector controls how binary ciphertext is encoded for display and storage.

| Format | Description | Best For |
|--------|-------------|----------|
| Base64 | URL-safe base64 encoding | Pasting into text fields, emails, JSON |
| Hex | Lowercase hex string | Debugging, log files |
| Raw | UTF-8 decoded text | When ciphertext is printable (rare) |

> If the output cannot be decoded as UTF-8 in Raw mode, it falls back to Base64 automatically.

---

## GUI Layout

### Left Panel — Controls

- **Algorithm selector** — radio buttons for all 10 algorithms; the key/config area updates dynamically based on the selection
- **Password field** — shown for all symmetric and classical keyword ciphers; toggle visibility with the checkbox
- **Caesar shift spinner** — appears only when Caesar is selected; range 1–25
- **RSA key area** — appears only when RSA-OAEP is selected; includes generate, load, and separate public/private key text boxes
- **Output format** — Base64, Hex, or Raw
- **Action buttons** — Encrypt, Decrypt, Load File, Save Output, Swap, Clear All

### Right Panel — Input / Output

- **Input box** (amber tint) — paste text, load from file, or type directly
- **Output box** (cyan tint) — displays the result of encrypt/decrypt operations
- Both panels have a **Copy** button in their header
- The output badge shows the currently active algorithm name

### Status Bar

Displayed at the bottom of the window — colour-coded green for success, red for errors. Auto-clears after 6–8 seconds.

---

## Actions

| Button | Function |
|--------|----------|
| ENCRYPT | Encrypts the input using the selected algorithm and key |
| DECRYPT | Decrypts the input using the selected algorithm and key |
| Load File | Opens a file dialog; binary files are auto-loaded as Base64 |
| Save Output | Saves the output box content to a `.txt` file |
| Swap ↕ | Swaps the input and output boxes (useful for chaining operations) |
| Clear All | Clears input, output, and password fields |

---

## Algorithm Selection Guide

```
Need strong encryption for sensitive data?
  → AES-256-GCM  (authenticated, tamper-proof)

Encrypting large files or streaming data?
  → ChaCha20-Poly1305  (fast, authenticated)

Need a safe, simple symmetric option?
  → Fernet  (hard to misuse)

Encrypting for someone else (asymmetric)?
  → RSA-OAEP  (give them your public key)

Working with legacy systems?
  → AES-256-CBC, Blowfish-CBC, or 3DES-CBC

Just need quick obfuscation (not secure)?
  → XOR, Caesar, or Vigenère
```

---

## Dependencies

| Package | Purpose | Required |
|---------|---------|---------|
| `cryptography` | All crypto primitives (AES, RSA, ChaCha20, Fernet, Blowfish, 3DES, PBKDF2) | Yes — auto-installed on first run |
| `tkinter` | GUI framework | Built into Python stdlib |
| `hashlib`, `secrets`, `base64` | Hashing, random bytes, encoding | Built into Python stdlib |

---

## Security Notes

- Classical ciphers (Caesar, Vigenère, XOR) are **not cryptographically secure** — use them for learning or obfuscation only
- 3DES and Blowfish are **legacy algorithms** — prefer AES-256-GCM for new applications
- All modern symmetric algorithms use **random salts and IVs** per operation — the same password never produces the same ciphertext twice
- RSA key material is held in memory for the session only — it is never written to disk unless you explicitly save it

---

## Module Quick Reference

```
CRYPTOOL
├── Symmetric (password + PBKDF2)
│   ├── AES-256-GCM          ← recommended
│   ├── AES-256-CBC
│   ├── ChaCha20-Poly1305
│   ├── Fernet
│   ├── Blowfish-CBC
│   ├── 3DES-CBC
│   └── XOR
├── Asymmetric (keypair)
│   └── RSA-OAEP (1024 / 2048 / 4096-bit)
└── Classical (text only)
    ├── Caesar (shift 1–25)
    └── Vigenère (keyword)
```
