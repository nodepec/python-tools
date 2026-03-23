"""
CRYPTOOL — Advanced Encryption & Decryption Suite
Supports: AES, RSA, ChaCha20, Fernet, Blowfish, XOR, Caesar, Vigenère, Base64
GUI: tkinter (stdlib) · Crypto: cryptography library
"""

import sys, os, subprocess, importlib, base64, hashlib, struct, secrets, string

def ensure(pkg, import_as=None):
    try: importlib.import_module(import_as or pkg.replace("-","_"))
    except ImportError:
        subprocess.check_call([sys.executable,"-m","pip","install",pkg,"-q"])

ensure("cryptography")

import tkinter as tk
from tkinter import ttk, filedialog, messagebox

from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
try:
    from cryptography.hazmat.decrepit.ciphers.algorithms import TripleDES as _3DES
except ImportError:
    _3DES = algorithms.TripleDES
from cryptography.hazmat.primitives.ciphers.aead import ChaCha20Poly1305
from cryptography.hazmat.primitives.asymmetric import rsa, padding as apad
from cryptography.hazmat.primitives import hashes, serialization, padding as sym_padding, hmac
from cryptography.hazmat.backends import default_backend
from cryptography.fernet import Fernet
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC

BG      = "#0b0c0e"
BG2     = "#111318"
BG3     = "#1a1d24"
BG4     = "#22252f"
BORDER  = "#2e3240"
FG      = "#e8dcc8"
FG_DIM  = "#6b7080"
FG_MED  = "#9aa0b0"
AMBER   = "#f0a020"
AMBER2  = "#c87800"
CYAN    = "#38c8c8"
GREEN   = "#40c870"
RED     = "#e04848"
PURPLE  = "#9870e8"

MONO    = ("Courier New", 10)
MONO_SM = ("Courier New", 9)
MONO_LG = ("Courier New", 13, "bold")
UI      = ("Segoe UI", 10) if sys.platform=="win32" else ("Helvetica Neue", 10)
UI_SM   = ("Segoe UI", 9)  if sys.platform=="win32" else ("Helvetica Neue", 9)

PAD = dict(padx=16, pady=6)


def derive_key(password: str, salt: bytes, length: int) -> bytes:
    kdf = PBKDF2HMAC(algorithm=hashes.SHA256(), length=length,
                     salt=salt, iterations=260_000, backend=default_backend())
    return kdf.derive(password.encode())

def aes_encrypt(plaintext: bytes, password: str) -> bytes:
    salt = secrets.token_bytes(16)
    key  = derive_key(password, salt, 32)
    iv   = secrets.token_bytes(12)
    enc  = Cipher(algorithms.AES(key), modes.GCM(iv), backend=default_backend()).encryptor()
    ct   = enc.update(plaintext) + enc.finalize()
    return salt + iv + enc.tag + ct

def aes_decrypt(data: bytes, password: str) -> bytes:
    salt, iv, tag, ct = data[:16], data[16:28], data[28:44], data[44:]
    key = derive_key(password, salt, 32)
    dec = Cipher(algorithms.AES(key), modes.GCM(iv, tag), backend=default_backend()).decryptor()
    return dec.update(ct) + dec.finalize()

def aes_cbc_encrypt(plaintext: bytes, password: str) -> bytes:
    salt = secrets.token_bytes(16)
    key  = derive_key(password, salt, 32)
    iv   = secrets.token_bytes(16)
    pad  = sym_padding.PKCS7(128).padder()
    padded = pad.update(plaintext) + pad.finalize()
    enc  = Cipher(algorithms.AES(key), modes.CBC(iv), backend=default_backend()).encryptor()
    ct   = enc.update(padded) + enc.finalize()
    return salt + iv + ct

def aes_cbc_decrypt(data: bytes, password: str) -> bytes:
    salt, iv, ct = data[:16], data[16:32], data[32:]
    key  = derive_key(password, salt, 32)
    dec  = Cipher(algorithms.AES(key), modes.CBC(iv), backend=default_backend()).decryptor()
    padded = dec.update(ct) + dec.finalize()
    unpad = sym_padding.PKCS7(128).unpadder()
    return unpad.update(padded) + unpad.finalize()

def chacha_encrypt(plaintext: bytes, password: str) -> bytes:
    salt = secrets.token_bytes(16)
    key  = derive_key(password, salt, 32)
    nonce = secrets.token_bytes(12)
    ct   = ChaCha20Poly1305(key).encrypt(nonce, plaintext, None)
    return salt + nonce + ct

def chacha_decrypt(data: bytes, password: str) -> bytes:
    salt, nonce, ct = data[:16], data[16:28], data[28:]
    key = derive_key(password, salt, 32)
    return ChaCha20Poly1305(key).decrypt(nonce, ct, None)

def fernet_encrypt(plaintext: bytes, password: str) -> bytes:
    salt = secrets.token_bytes(16)
    key  = derive_key(password, salt, 32)
    fkey = base64.urlsafe_b64encode(key)
    ct   = Fernet(fkey).encrypt(plaintext)
    return salt + ct

def fernet_decrypt(data: bytes, password: str) -> bytes:
    salt, ct = data[:16], data[16:]
    key  = derive_key(password, salt, 32)
    fkey = base64.urlsafe_b64encode(key)
    return Fernet(fkey).decrypt(ct)

def rsa_gen(bits=2048):
    priv = rsa.generate_private_key(65537, bits, default_backend())
    pub  = priv.public_key()
    priv_pem = priv.private_bytes(serialization.Encoding.PEM,
               serialization.PrivateFormat.TraditionalOpenSSL,
               serialization.NoEncryption()).decode()
    pub_pem  = pub.public_bytes(serialization.Encoding.PEM,
               serialization.PublicFormat.SubjectPublicKeyInfo).decode()
    return priv_pem, pub_pem

def rsa_encrypt(plaintext: bytes, pub_pem: str) -> bytes:
    pub = serialization.load_pem_public_key(pub_pem.encode(), default_backend())
    return pub.encrypt(plaintext, apad.OAEP(
        mgf=apad.MGF1(hashes.SHA256()), algorithm=hashes.SHA256(), label=None))

def rsa_decrypt(data: bytes, priv_pem: str) -> bytes:
    priv = serialization.load_pem_private_key(priv_pem.encode(), None, default_backend())
    return priv.decrypt(data, apad.OAEP(
        mgf=apad.MGF1(hashes.SHA256()), algorithm=hashes.SHA256(), label=None))

def xor_crypt(data: bytes, password: str) -> bytes:
    key = hashlib.sha256(password.encode()).digest()
    return bytes(b ^ key[i % 32] for i, b in enumerate(data))

def caesar_crypt(text: str, shift: int) -> str:
    out = []
    for c in text:
        if c.isupper(): out.append(chr((ord(c)-65+shift)%26+65))
        elif c.islower(): out.append(chr((ord(c)-97+shift)%26+97))
        else: out.append(c)
    return "".join(out)

def vigenere_crypt(text: str, key: str, encrypt: bool) -> str:
    key = key.upper()
    if not key: raise ValueError("Key cannot be empty")
    out, ki = [], 0
    for c in text:
        if c.isalpha():
            shift = ord(key[ki % len(key)]) - 65
            if not encrypt: shift = -shift
            base = 65 if c.isupper() else 97
            out.append(chr((ord(c)-base+shift) % 26 + base))
            ki += 1
        else:
            out.append(c)
    return "".join(out)

def blowfish_encrypt(plaintext: bytes, password: str) -> bytes:
    salt = secrets.token_bytes(16)
    key  = derive_key(password, salt, 32)[:16]
    iv   = secrets.token_bytes(8)
    pad_len = 8 - (len(plaintext) % 8)
    padded  = plaintext + bytes([pad_len]*pad_len)
    enc = Cipher(algorithms.Blowfish(key), modes.CBC(iv), backend=default_backend()).encryptor()
    ct  = enc.update(padded) + enc.finalize()
    return salt + iv + ct

def blowfish_decrypt(data: bytes, password: str) -> bytes:
    salt, iv, ct = data[:16], data[16:24], data[24:]
    key  = derive_key(password, salt, 32)[:16]
    dec  = Cipher(algorithms.Blowfish(key), modes.CBC(iv), backend=default_backend()).decryptor()
    padded = dec.update(ct) + dec.finalize()
    pad_len = padded[-1]
    return padded[:-pad_len]

def tdes_encrypt(plaintext: bytes, password: str) -> bytes:
    salt = secrets.token_bytes(16)
    key  = derive_key(password, salt, 24)
    iv   = secrets.token_bytes(8)
    pad_len = 8 - (len(plaintext) % 8)
    padded  = plaintext + bytes([pad_len]*pad_len)
    enc = Cipher(_3DES(key), modes.CBC(iv), backend=default_backend()).encryptor()
    ct  = enc.update(padded) + enc.finalize()
    return salt + iv + ct

def tdes_decrypt(data: bytes, password: str) -> bytes:
    salt, iv, ct = data[:16], data[16:24], data[24:]
    key  = derive_key(password, salt, 24)
    dec  = Cipher(_3DES(key), modes.CBC(iv), backend=default_backend()).decryptor()
    padded = dec.update(ct) + dec.finalize()
    return padded[:-padded[-1]]


class CrypTool(tk.Tk):
    def __init__(self):
        super().__init__()
        self.title("CRYPTOOL")
        self.configure(bg=BG)
        self.minsize(980, 720)
        self._rsa_priv = ""
        self._rsa_pub  = ""
        self._build()
        self.update_idletasks()
        w,h = 1080,760
        self.geometry(f"{w}x{h}+{(self.winfo_screenwidth()-w)//2}+{(self.winfo_screenheight()-h)//2}")

    def _build(self):
        self._build_header()
        self._build_body()
        self._build_footer()
        self._algo_badge.config(text=f"[ {self._algo.get()} ]")

    def _build_header(self):
        h = tk.Frame(self, bg=BG2, height=56)
        h.pack(fill="x")
        h.pack_propagate(False)
        tk.Frame(h, bg=AMBER, width=4).pack(side="left", fill="y")
        inner = tk.Frame(h, bg=BG2)
        inner.pack(side="left", fill="both", expand=True, padx=18)
        tk.Label(inner, text="CRYPTOOL", bg=BG2, fg=AMBER,
                 font=("Courier New",18,"bold")).pack(side="left", pady=10)
        tk.Label(inner, text="  Advanced Encryption & Decryption Suite",
                 bg=BG2, fg=FG_DIM, font=MONO_SM).pack(side="left", pady=14)

        tk.Label(inner, text="AES · RSA · ChaCha20 · Fernet · Blowfish · 3DES · XOR · Caesar · Vigenère",
                 bg=BG2, fg=FG_DIM, font=("Courier New",8)).pack(side="right", pady=18)
        tk.Frame(self, bg=BORDER, height=1).pack(fill="x")

    def _build_body(self):
        body = tk.Frame(self, bg=BG)
        body.pack(fill="both", expand=True)

        left = tk.Frame(body, bg=BG2, width=300)
        left.pack(side="left", fill="y")
        left.pack_propagate(False)
        tk.Frame(body, bg=BORDER, width=1).pack(side="left", fill="y")

        right = tk.Frame(body, bg=BG)
        right.pack(side="left", fill="both", expand=True)

        self._build_controls(left)
        self._build_io(right)

    def _build_footer(self):
        tk.Frame(self, bg=BORDER, height=1).pack(fill="x")
        f = tk.Frame(self, bg=BG2, height=30)
        f.pack(fill="x")
        f.pack_propagate(False)
        self._status_var = tk.StringVar(value="Ready.")
        self._status_lbl = tk.Label(f, textvariable=self._status_var,
                                    bg=BG2, fg=FG_DIM, font=MONO_SM, anchor="w", padx=14)
        self._status_lbl.pack(fill="both", expand=True)

    def _build_controls(self, parent):
        def section(title):
            f = tk.Frame(parent, bg=BG2)
            f.pack(fill="x", padx=14, pady=(14,2))
            tk.Label(f, text=title, bg=BG2, fg=AMBER, font=("Courier New",8,"bold")).pack(side="left")
            tk.Frame(f, bg=BORDER, height=1).pack(side="left", fill="x", expand=True, padx=(6,0), pady=5)

        def lbl(p, t, color=FG_MED):
            tk.Label(p, text=t, bg=BG2, fg=color, font=UI_SM, anchor="w").pack(fill="x", padx=14, pady=(4,0))

        section("ALGORITHM")
        self._algo = tk.StringVar(value="AES-256-GCM")
        algos = [
            ("AES-256-GCM",       "Authenticated (recommended)"),
            ("AES-256-CBC",       "Classic block cipher"),
            ("ChaCha20-Poly1305", "Stream cipher, fast"),
            ("Fernet",            "Safe symmetric wrapper"),
            ("Blowfish-CBC",      "Legacy symmetric"),
            ("3DES-CBC",          "Triple DES legacy"),
            ("RSA-OAEP",          "Asymmetric / keypair"),
            ("XOR",               "Simple key-stretch XOR"),
            ("Caesar",            "Classic shift cipher"),
            ("Vigenère",          "Polyalphabetic cipher"),
        ]
        algo_frame = tk.Frame(parent, bg=BG2)
        algo_frame.pack(fill="x", padx=10)
        for val, desc in algos:
            row = tk.Frame(algo_frame, bg=BG2)
            row.pack(fill="x")
            rb = tk.Radiobutton(row, text=val, variable=self._algo, value=val,
                                bg=BG2, fg=FG, selectcolor=BG3,
                                activebackground=BG2, activeforeground=AMBER,
                                font=("Courier New",9), cursor="hand2",
                                command=self._on_algo_change)
            rb.pack(side="left", padx=(8,4))
            tk.Label(row, text=desc, bg=BG2, fg=FG_DIM, font=("Courier New",8)).pack(side="left")

        section("KEY / PASSWORD")
        self._pw_frame = tk.Frame(parent, bg=BG2)
        self._pw_frame.pack(fill="x")
        lbl(self._pw_frame, "Password (symmetric algorithms):")
        self._pw = tk.Entry(self._pw_frame, bg=BG3, fg=FG, insertbackground=AMBER,
                            font=MONO, show="•", relief="flat",
                            highlightthickness=1, highlightbackground=BORDER,
                            highlightcolor=AMBER)
        self._pw.pack(fill="x", padx=14, pady=4)

        self._show_pw = tk.BooleanVar()
        tk.Checkbutton(self._pw_frame, text="Show password", variable=self._show_pw,
                       bg=BG2, fg=FG_DIM, activebackground=BG2, selectcolor=BG3,
                       font=UI_SM, cursor="hand2",
                       command=lambda: self._pw.config(show="" if self._show_pw.get() else "•")
                       ).pack(padx=14, anchor="w")

        self._shift_frame = tk.Frame(parent, bg=BG2)
        lbl(self._shift_frame, "Caesar shift (1–25):")
        self._shift = tk.Spinbox(self._shift_frame, from_=1, to=25, width=6,
                                  bg=BG3, fg=AMBER, font=MONO, relief="flat",
                                  buttonbackground=BG4, insertbackground=AMBER)
        self._shift.pack(padx=14, anchor="w", pady=4)

        self._rsa_frame = tk.Frame(parent, bg=BG2)
        lbl(self._rsa_frame, "RSA Key Size:")
        self._rsa_bits = tk.IntVar(value=2048)
        brow = tk.Frame(self._rsa_frame, bg=BG2)
        brow.pack(fill="x", padx=14)
        for b in (1024,2048,4096):
            tk.Radiobutton(brow, text=f"{b}", variable=self._rsa_bits, value=b,
                           bg=BG2, fg=FG, selectcolor=BG3, activebackground=BG2,
                           activeforeground=AMBER, font=MONO_SM, cursor="hand2"
                           ).pack(side="left", padx=(0,10))

        def _btn(p,t,cmd,color=AMBER,w=None):
            b = tk.Button(p,text=t,command=cmd,bg=BG3,fg=color,
                          activebackground=BG4,activeforeground=color,
                          font=UI_SM,relief="flat",cursor="hand2",
                          bd=0,highlightthickness=1,highlightbackground=BORDER,
                          pady=5,padx=10)
            if w: b.config(width=w)
            b.bind("<Enter>", lambda e: b.config(bg=BG4,highlightbackground=color))
            b.bind("<Leave>", lambda e: b.config(bg=BG3,highlightbackground=BORDER))
            return b

        rsa_btn_row = tk.Frame(self._rsa_frame, bg=BG2)
        rsa_btn_row.pack(fill="x", padx=14, pady=6)
        _btn(rsa_btn_row,"Generate Keypair",self._rsa_gen,AMBER).pack(side="left",padx=(0,6))
        _btn(rsa_btn_row,"Load Keys",self._rsa_load,FG_DIM).pack(side="left")

        lbl(self._rsa_frame,"Public Key (encrypt):")
        self._rsa_pub_box = tk.Text(self._rsa_frame, height=3, bg=BG3, fg=CYAN,
                                     font=("Courier New",7), relief="flat",
                                     highlightthickness=1,highlightbackground=BORDER)
        self._rsa_pub_box.pack(fill="x",padx=14,pady=(0,4))
        lbl(self._rsa_frame,"Private Key (decrypt):")
        self._rsa_priv_box = tk.Text(self._rsa_frame, height=3, bg=BG3, fg=PURPLE,
                                      font=("Courier New",7), relief="flat",
                                      highlightthickness=1,highlightbackground=BORDER)
        self._rsa_priv_box.pack(fill="x",padx=14,pady=(0,4))

        section("OUTPUT FORMAT")
        self._fmt = tk.StringVar(value="base64")
        fmt_row = tk.Frame(parent, bg=BG2)
        fmt_row.pack(fill="x", padx=14, pady=4)
        for val,label_txt in (("base64","Base64"),("hex","Hex"),("raw","Raw bytes")):
            tk.Radiobutton(fmt_row, text=label_txt, variable=self._fmt, value=val,
                           bg=BG2, fg=FG, selectcolor=BG3, activebackground=BG2,
                           activeforeground=AMBER, font=UI_SM, cursor="hand2"
                           ).pack(side="left", padx=(0,12))

        section("ACTIONS")
        abrow = tk.Frame(parent, bg=BG2)
        abrow.pack(fill="x", padx=14, pady=4)
        _btn(abrow,"⬛  ENCRYPT",self._do_encrypt,GREEN,14).pack(side="left",padx=(0,6))
        _btn(abrow,"⬜  DECRYPT",self._do_decrypt,CYAN,14).pack(side="left")

        ab2 = tk.Frame(parent, bg=BG2)
        ab2.pack(fill="x", padx=14, pady=(0,6))
        _btn(ab2,"Load File",self._load_file,FG_DIM).pack(side="left",padx=(0,6))
        _btn(ab2,"Save Output",self._save_output,FG_DIM).pack(side="left",padx=(0,6))
        _btn(ab2,"Swap ↕",self._swap,FG_DIM).pack(side="left",padx=(0,6))
        _btn(ab2,"Clear All",self._clear,RED).pack(side="left")

        self._on_algo_change()

    def _build_io(self, parent):
        def half(title, color):
            frame = tk.Frame(parent, bg=BG)
            frame.pack(fill="both", expand=True, padx=0)
            hdr = tk.Frame(frame, bg=BG3)
            hdr.pack(fill="x")
            tk.Label(hdr, text=title, bg=BG3, fg=color, font=("Courier New",9,"bold"),
                     padx=14, pady=6).pack(side="left")
            box = tk.Text(frame, bg=BG, fg=FG, insertbackground=AMBER,
                          font=MONO, relief="flat", borderwidth=0,
                          highlightthickness=0, selectbackground=AMBER2,
                          selectforeground=BG, wrap="word", padx=10, pady=8)
            box.pack(fill="both", expand=True)
            def _copy(b=box, c=color):
                self.clipboard_clear()
                self.clipboard_append(b.get("1.0","end").strip())
                self._ok("Copied to clipboard.")
            tk.Button(hdr, text="copy", command=_copy,
                      bg=BG3, fg=FG_DIM, activebackground=BG4, activeforeground=color,
                      font=("Courier New",8), relief="flat", cursor="hand2",
                      bd=0, padx=8).pack(side="right", padx=6)
            return frame, box

        tk.Frame(parent, bg=BORDER, height=1).pack(fill="x")
        top_lbl = tk.Frame(parent, bg=BG3)
        top_lbl.pack(fill="x")
        tk.Label(top_lbl, text=" INPUT", bg=BG3, fg=AMBER,
                 font=("Courier New",9,"bold"), padx=14, pady=6).pack(side="left")
        def _copy_in():
            self.clipboard_clear()
            self.clipboard_append(self._input_box.get("1.0","end").strip())
            self._ok("Copied input to clipboard.")
        tk.Button(top_lbl, text="copy", command=_copy_in,
                  bg=BG3, fg=FG_DIM, activebackground=BG4, activeforeground=AMBER,
                  font=("Courier New",8), relief="flat", cursor="hand2", bd=0, padx=8
                  ).pack(side="right", padx=6)

        self._input_box = tk.Text(parent, bg=BG2, fg=FG, insertbackground=AMBER,
                                   font=MONO, relief="flat", borderwidth=0,
                                   highlightthickness=0, selectbackground=AMBER2,
                                   selectforeground=BG, wrap="word", padx=10, pady=8)
        self._input_box.pack(fill="both", expand=True)

        tk.Frame(parent, bg=BORDER, height=1).pack(fill="x")
        bot_lbl = tk.Frame(parent, bg=BG3)
        bot_lbl.pack(fill="x")
        tk.Label(bot_lbl, text=" OUTPUT", bg=BG3, fg=CYAN,
                 font=("Courier New",9,"bold"), padx=14, pady=6).pack(side="left")
        def _copy_out():
            self.clipboard_clear()
            self.clipboard_append(self._output_box.get("1.0","end").strip())
            self._ok("Copied output to clipboard.")
        tk.Button(bot_lbl, text="copy", command=_copy_out,
                  bg=BG3, fg=FG_DIM, activebackground=BG4, activeforeground=CYAN,
                  font=("Courier New",8), relief="flat", cursor="hand2", bd=0, padx=8
                  ).pack(side="right", padx=6)
        self._algo_badge = tk.Label(bot_lbl, text="", bg=BG3, fg=FG_DIM,
                                     font=("Courier New",8), padx=10)
        self._algo_badge.pack(side="right")

        self._output_box = tk.Text(parent, bg=BG, fg=CYAN, insertbackground=CYAN,
                                    font=MONO, relief="flat", borderwidth=0,
                                    highlightthickness=0, selectbackground=AMBER2,
                                    selectforeground=BG, wrap="word", padx=10, pady=8)
        self._output_box.pack(fill="both", expand=True)

    def _on_algo_change(self):
        algo = self._algo.get()
        self._pw_frame.pack_forget()
        self._shift_frame.pack_forget()
        self._rsa_frame.pack_forget()

        if algo == "Caesar":
            self._shift_frame.pack(fill="x")
        elif algo == "RSA-OAEP":
            self._rsa_frame.pack(fill="x")
        elif algo not in ("XOR",):
            self._pw_frame.pack(fill="x")
        else:
            self._pw_frame.pack(fill="x")

        if hasattr(self, "_algo_badge"):
            self._algo_badge.config(text=f"[ {algo} ]")

    def _ok(self, msg):
        self._status_var.set(f"✓  {msg}")
        self._status_lbl.config(fg=GREEN)
        self.after(6000, lambda: (self._status_var.set("Ready."), self._status_lbl.config(fg=FG_DIM)))

    def _err(self, msg):
        self._status_var.set(f"✗  {msg}")
        self._status_lbl.config(fg=RED)
        self.after(8000, lambda: (self._status_var.set("Ready."), self._status_lbl.config(fg=FG_DIM)))

    def _encode_out(self, data: bytes) -> str:
        fmt = self._fmt.get()
        if fmt == "base64": return base64.b64encode(data).decode()
        if fmt == "hex":    return data.hex()
        try: return data.decode()
        except: return base64.b64encode(data).decode() + "  [non-UTF8, fell back to base64]"

    def _decode_in(self, text: str) -> bytes:
        fmt = self._fmt.get()
        t = text.strip()
        if fmt == "base64":
            return base64.b64decode(t)
        if fmt == "hex":
            return bytes.fromhex(t.replace(" ",""))
        return t.encode()

    def _get_input(self) -> str:
        return self._input_box.get("1.0","end").strip()

    def _set_output(self, text: str):
        self._output_box.config(state="normal")
        self._output_box.delete("1.0","end")
        self._output_box.insert("1.0", text)

    def _do_encrypt(self):
        inp   = self._get_input()
        algo  = self._algo.get()
        pw    = self._pw.get()

        if not inp:
            self._err("No input text."); return

        if algo == "Caesar":
            try:
                shift = int(self._shift.get())
                result = caesar_crypt(inp, shift)
                self._set_output(result)
                self._ok(f"Caesar encrypted (shift {shift}).")
            except Exception as e:
                self._err(str(e))
            return

        if algo == "Vigenère":
            if not pw: self._err("Enter a keyword as the password."); return
            try:
                result = vigenere_crypt(inp, pw, encrypt=True)
                self._set_output(result)
                self._ok("Vigenère encrypted.")
            except Exception as e:
                self._err(str(e))
            return

        if algo == "RSA-OAEP":
            pub = self._rsa_pub_box.get("1.0","end").strip()
            if not pub: self._err("Paste or generate a public key."); return
            try:
                ct = rsa_encrypt(inp.encode(), pub)
                self._set_output(self._encode_out(ct))
                self._ok("RSA-OAEP encrypted.")
            except Exception as e:
                self._err(str(e))
            return

        if not pw:
            self._err("Enter a password/key."); return

        try:
            pt = inp.encode()
            dispatch = {
                "AES-256-GCM":       aes_encrypt,
                "AES-256-CBC":       aes_cbc_encrypt,
                "ChaCha20-Poly1305": chacha_encrypt,
                "Fernet":            fernet_encrypt,
                "Blowfish-CBC":      blowfish_encrypt,
                "3DES-CBC":          tdes_encrypt,
                "XOR":               xor_crypt,
            }
            ct = dispatch[algo](pt, pw)
            self._set_output(self._encode_out(ct))
            self._ok(f"{algo} encrypted.")
        except Exception as e:
            self._err(str(e))

    def _do_decrypt(self):
        inp  = self._get_input()
        algo = self._algo.get()
        pw   = self._pw.get()

        if not inp:
            self._err("No input text."); return

        if algo == "Caesar":
            try:
                shift = int(self._shift.get())
                result = caesar_crypt(inp, -shift)
                self._set_output(result)
                self._ok(f"Caesar decrypted (shift -{shift}).")
            except Exception as e:
                self._err(str(e))
            return

        if algo == "Vigenère":
            if not pw: self._err("Enter the keyword."); return
            try:
                result = vigenere_crypt(inp, pw, encrypt=False)
                self._set_output(result)
                self._ok("Vigenère decrypted.")
            except Exception as e:
                self._err(str(e))
            return

        if algo == "RSA-OAEP":
            priv = self._rsa_priv_box.get("1.0","end").strip()
            if not priv: self._err("Paste or generate a private key."); return
            try:
                ct = self._decode_in(inp)
                pt = rsa_decrypt(ct, priv)
                self._set_output(pt.decode(errors="replace"))
                self._ok("RSA-OAEP decrypted.")
            except Exception as e:
                self._err(str(e))
            return

        if not pw:
            self._err("Enter the password/key."); return

        try:
            ct = self._decode_in(inp)
            dispatch = {
                "AES-256-GCM":       aes_decrypt,
                "AES-256-CBC":       aes_cbc_decrypt,
                "ChaCha20-Poly1305": chacha_decrypt,
                "Fernet":            fernet_decrypt,
                "Blowfish-CBC":      blowfish_decrypt,
                "3DES-CBC":          tdes_decrypt,
                "XOR":               xor_crypt,
            }
            pt = dispatch[algo](ct, pw)
            self._set_output(pt.decode(errors="replace"))
            self._ok(f"{algo} decrypted.")
        except Exception as e:
            self._err(f"Decryption failed: {e}")

    def _rsa_gen(self):
        try:
            priv, pub = rsa_gen(self._rsa_bits.get())
            self._rsa_priv = priv
            self._rsa_pub  = pub
            self._rsa_pub_box.delete("1.0","end")
            self._rsa_pub_box.insert("1.0", pub)
            self._rsa_priv_box.delete("1.0","end")
            self._rsa_priv_box.insert("1.0", priv)
            self._ok(f"{self._rsa_bits.get()}-bit RSA keypair generated.")
        except Exception as e:
            self._err(str(e))

    def _rsa_load(self):
        path = filedialog.askopenfilename(filetypes=[("PEM","*.pem"),("All","*.*")])
        if not path: return
        with open(path) as f: data = f.read()
        if "PRIVATE" in data:
            self._rsa_priv_box.delete("1.0","end")
            self._rsa_priv_box.insert("1.0", data)
            self._ok("Private key loaded.")
        else:
            self._rsa_pub_box.delete("1.0","end")
            self._rsa_pub_box.insert("1.0", data)
            self._ok("Public key loaded.")

    def _load_file(self):
        path = filedialog.askopenfilename()
        if not path: return
        try:
            with open(path,"rb") as f:
                raw = f.read()
            try:
                self._input_box.delete("1.0","end")
                self._input_box.insert("1.0", raw.decode())
            except UnicodeDecodeError:
                self._input_box.delete("1.0","end")
                self._input_box.insert("1.0", base64.b64encode(raw).decode())
                self._ok("Binary file loaded as Base64.")
                return
            self._ok(f"Loaded: {os.path.basename(path)}")
        except Exception as e:
            self._err(str(e))

    def _save_output(self):
        out = self._output_box.get("1.0","end").strip()
        if not out: self._err("Nothing in output."); return
        path = filedialog.asksaveasfilename(defaultextension=".txt",
               filetypes=[("Text","*.txt"),("All","*.*")])
        if path:
            with open(path,"w") as f: f.write(out)
            self._ok(f"Saved → {os.path.basename(path)}")

    def _swap(self):
        inp = self._input_box.get("1.0","end").strip()
        out = self._output_box.get("1.0","end").strip()
        self._input_box.delete("1.0","end")
        self._input_box.insert("1.0", out)
        self._output_box.config(state="normal")
        self._output_box.delete("1.0","end")
        self._output_box.insert("1.0", inp)
        self._ok("Input and output swapped.")

    def _clear(self):
        self._input_box.delete("1.0","end")
        self._output_box.delete("1.0","end")
        self._pw.delete(0,"end")
        self._ok("Cleared.")


if __name__ == "__main__":
    app = CrypTool()
    app.mainloop()
