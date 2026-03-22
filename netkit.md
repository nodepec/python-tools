# NETKIT — Feature Reference

A terminal-based Python toolkit for encoding, decoding, network diagnostics, and data conversions. Runs on Windows, macOS, and Linux with an optional `rich` TUI for a polished terminal experience.

---

## Getting Started

```bash
pip install rich        # optional but recommended
python3 toolkit.py
```

On first run, NETKIT will attempt to auto-install `rich` if it's missing. It falls back gracefully to plain-text output if unavailable.

---

## Modules

### 1. Encoding

Transform plaintext or binary data into encoded representations.

| Option | Description |
|--------|-------------|
| Base64 Encode | Encodes text to Base64 using standard alphabet |
| URL Encode | Percent-encodes text for safe use in URLs |
| Hex Encode | Converts text to its hexadecimal byte representation |
| Binary Encode | Outputs 8-bit binary for each character, space-separated |
| HTML Entity Encode | Escapes `<`, `>`, `&`, `"` and other reserved HTML characters |
| MD5 Hash | Produces a 128-bit MD5 digest (hex) |
| SHA-1 Hash | Produces a 160-bit SHA-1 digest (hex) |
| SHA-256 Hash | Produces a 256-bit SHA-256 digest (hex) |
| SHA-512 Hash | Produces a 512-bit SHA-512 digest (hex) |

---

### 2. Decoding

Reverse-engineer encoded data back to its original form.

| Option | Description |
|--------|-------------|
| Base64 Decode | Decodes a Base64 string back to plaintext |
| URL Decode | Converts percent-encoded strings back to readable text |
| Hex Decode | Converts a hex string back to ASCII/UTF-8 text |
| Binary Decode | Converts space-separated 8-bit binary strings back to characters |
| HTML Entity Decode | Unescapes HTML entities back to their original characters |

> Note: Hash functions (MD5, SHA, etc.) are one-way and cannot be decoded.

---

### 3. Network Tools

Live network diagnostics using your system's native utilities and Python sockets.

| Option | Description |
|--------|-------------|
| Ping a Host | Sends ICMP packets to a host using the system `ping` command. Configurable packet count. |
| Port Scanner | Scans a range or comma-separated list of TCP ports on a target (e.g. `1-1024` or `80,443,8080`). Displays open ports with common service name guesses. |
| DNS Lookup | Resolves a hostname to its IP addresses, plus a reverse lookup on the first result |
| Reverse DNS Lookup | Looks up the hostname for a given IP address |
| Get Local IP | Detects your machine's local network IP address |
| Get Public IP | Retrieves your external/public IP via `api.ipify.org` |
| Host Info | Returns the IP address and FQDN (fully qualified domain name) for a host |
| TCP Port Check | Tests whether a single TCP port is open or closed/filtered on a given host |

**Port scanner service guessing covers:** FTP, SSH, Telnet, SMTP, DNS, HTTP, HTTPS, POP3, IMAP, MySQL, PostgreSQL, Redis, MongoDB, and more.

---

### 4. Conversions

Utility conversions for numbers, IPs, sizes, and timestamps.

| Option | Description |
|--------|-------------|
| Number Base Converter | Converts between decimal, hexadecimal, octal, and binary. Accepts `0x`, `0b`, `0o` prefixes for non-decimal input. |
| IP ↔ Integer | Converts an IPv4 address to its 32-bit integer representation, or vice versa |
| CIDR to IP Range | Expands a CIDR block (e.g. `192.168.1.0/24`) into network address, broadcast, first/last usable host, usable host count, and subnet mask |
| Bytes → Human Readable | Converts a raw byte count into KB, MB, GB, TB, or PB automatically |
| Unix Timestamp ↔ Date | Converts between Unix epoch timestamps and human-readable `YYYY-MM-DD HH:MM:SS` format |

---

### 5. System Info

Displays a quick snapshot of the local environment:

- Hostname
- Operating system and kernel version
- CPU architecture
- Python version
- Local IP address
- Current date and time

---

## Interface

- **Rich TUI mode** (when `rich` is installed): coloured output, formatted tables, progress spinners, syntax-highlighted blocks, and bordered result panels
- **Plain text fallback**: works in any terminal without dependencies — markup is automatically stripped
- **Cross-platform**: tested on Windows (cmd/PowerShell), macOS Terminal, and Linux bash
- **No external network dependencies** for most features — only Public IP lookup and ping use outbound connections

---

## Dependencies

| Package | Purpose | Required |
|---------|---------|---------|
| `rich` | TUI formatting, tables, progress bars | Optional |
| Standard library (`socket`, `hashlib`, `base64`, `struct`, `subprocess`, `urllib`) | All core functionality | Built-in |

---

## Module Quick Reference

```
NETKIT
├── Encoding
│   ├── Base64 / URL / Hex / Binary / HTML
│   └── MD5 / SHA-1 / SHA-256 / SHA-512
├── Decoding
│   └── Base64 / URL / Hex / Binary / HTML
├── Network Tools
│   ├── Ping, Port Scanner, TCP Check
│   ├── DNS Lookup, Reverse DNS
│   └── Local IP, Public IP, Host Info
├── Conversions
│   ├── Number Bases (Dec/Hex/Oct/Bin)
│   ├── IP ↔ Integer
│   ├── CIDR Range Expander
│   ├── Bytes → Human Size
│   └── Unix Timestamp ↔ Date
└── System Info
```
