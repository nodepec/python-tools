# RSA Tool — Feature Reference

A desktop GUI application for RSA cryptography operations. Built with Python, `tkinter`, and the `cryptography` library. Features a dark terminal-style interface with five dedicated tabs.

---

## Getting Started

```bash
pip install cryptography   # auto-installs on first run if missing
python3 rsa_tool.py
```

`tkinter` is included with Python's standard library — no extra install needed for the GUI.

---

## Tabs

### 1. Keygen — Key Pair Generation

Generate RSA public/private key pairs locally.

| Feature | Detail |
|---------|--------|
| Key sizes | 1024-bit, 2048-bit, 4096-bit |
| Format | PEM (PKCS#1 private key, SubjectPublicKeyInfo public key) |
| Copy Private Key | Copies the private key PEM to clipboard |
| Copy Public Key | Copies the public key PEM to clipboard |
| Save Private Key | Saves to a `.pem` file via file dialog |
| Save Public Key | Saves to a `.pem` file via file dialog |

> Keys are generated entirely locally and never transmitted anywhere.

Generated keys are stored in memory for the session and can be pulled into other tabs using the **"Use Generated Key"** button — no copy/paste required.

---

### 2. Encrypt

Encrypt plaintext using an RSA public key.

| Feature | Detail |
|---------|--------|
| Input | Paste plaintext into the message field |
| Key input | Paste PEM directly, load from file, or use the session-generated key |
| Algorithm | OAEP padding with SHA-256 |
| Output | Base64-encoded ciphertext |
| Copy button | Copies ciphertext to clipboard |

---

### 3. Decrypt

Decrypt RSA ciphertext back to plaintext using a private key.

| Feature | Detail |
|---------|--------|
| Input | Paste Base64 ciphertext |
| Key input | Paste PEM directly, load from file, or use the session-generated key |
| Algorithm | OAEP padding with SHA-256 (must match encryption) |
| Output | Decoded plaintext |
| Copy button | Copies plaintext to clipboard |

---

### 4. Sign

Produce a cryptographic signature over a message using a private key.

| Feature | Detail |
|---------|--------|
| Input | Paste the message to sign |
| Key input | Paste PEM directly, load from file, or use the session-generated key |
| Algorithm | PSS padding with SHA-256, maximum salt length |
| Output | Base64-encoded signature |
| Copy button | Copies signature to clipboard |

---

### 5. Verify

Verify a signature against a message and public key.

| Feature | Detail |
|---------|--------|
| Inputs | Public key PEM + original message + Base64 signature |
| Key input | Paste PEM directly, load from file, or use the session-generated key |
| Algorithm | PSS/SHA-256 (must match signing parameters) |
| Result display | Large ✓ SIGNATURE VALID (green) or ✗ SIGNATURE INVALID (red) |

---

## Cryptographic Details

| Operation | Padding | Hash |
|-----------|---------|------|
| Encrypt / Decrypt | OAEP + MGF1 | SHA-256 |
| Sign / Verify | PSS + MGF1 | SHA-256, max salt length |

All operations use the `cryptography` library (`cryptography.hazmat.primitives`), which wraps OpenSSL.

---

## Interface Features

- Dark terminal aesthetic — `#0d1117` background, monospace output fields
- Status bar at the bottom — shows success (green) or error (red) messages, auto-clears after 6 seconds
- Hover effects on all buttons
- All output fields are read-only to prevent accidental edits
- File dialogs for loading `.pem` key files and saving generated keys
- Session key sharing — generate once in Keygen, reuse across all tabs without re-pasting

---

## Dependencies

| Package | Purpose | Required |
|---------|---------|---------|
| `cryptography` | RSA key generation, encrypt/decrypt, sign/verify | Yes — auto-installed |
| `tkinter` | GUI framework | Built into Python stdlib |

---

## Quick Workflow Examples

**Generate a keypair and encrypt a message:**
1. Keygen tab → select key size → click **Generate Keypair**
2. Encrypt tab → click **Use Generated Key** → type message → click **Encrypt**
3. Copy ciphertext

**Decrypt with a saved private key:**
1. Decrypt tab → click **Load Private Key** → select `.pem` file
2. Paste ciphertext → click **Decrypt**

**Sign and verify a message:**
1. Sign tab → paste or load private key → type message → click **Sign** → copy signature
2. Verify tab → paste or load public key → paste message + signature → click **Verify**
