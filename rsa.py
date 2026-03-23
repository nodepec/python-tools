import sys
import subprocess
import importlib

def ensure(pkg, import_as=None):
    name = import_as or pkg
    try:
        importlib.import_module(name)
    except ImportError:
        print(f"Installing {pkg}…")
        subprocess.check_call([sys.executable, "-m", "pip", "install", pkg, "-q"])

ensure("cryptography")

import base64
import textwrap
import tkinter as tk
from tkinter import ttk, filedialog, messagebox

from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.backends import default_backend
from cryptography.exceptions import InvalidSignature

BG       = "#0d1117"
BG2      = "#161b22"
BG3      = "#21262d"
BORDER   = "#30363d"
FG       = "#e6edf3"
FG_DIM   = "#8b949e"
ACCENT   = "#58a6ff"
GREEN    = "#3fb950"
RED      = "#f85149"
YELLOW   = "#d29922"
FONT_MONO = ("Courier New", 10)
FONT_UI   = ("Segoe UI", 10) if sys.platform == "win32" else ("SF Pro Text", 10) if sys.platform == "darwin" else ("Ubuntu", 10)
FONT_TITLE= ("Courier New", 16, "bold")

def styled_frame(parent, **kw):
    return tk.Frame(parent, bg=kw.pop("bg", BG2), relief="flat", **kw)

def label(parent, text, color=FG, font=None, **kw):
    return tk.Label(parent, text=text, bg=kw.pop("bg", parent["bg"]),
                    fg=color, font=font or FONT_UI, **kw)

def text_box(parent, height=6, **kw):
    t = tk.Text(parent, height=height,
                bg=BG3, fg=FG, insertbackground=ACCENT,
                font=FONT_MONO, relief="flat",
                borderwidth=0, highlightthickness=1,
                highlightbackground=BORDER, highlightcolor=ACCENT,
                selectbackground=ACCENT, selectforeground=BG,
                wrap="word", **kw)
    return t

def btn(parent, text, cmd, color=ACCENT, width=18):
    b = tk.Button(parent, text=text, command=cmd,
                  bg=BG3, fg=color, activebackground=BG,
                  activeforeground=color, font=FONT_UI,
                  relief="flat", cursor="hand2",
                  bd=0, highlightthickness=1,
                  highlightbackground=BORDER, highlightcolor=color,
                  padx=12, pady=6, width=width)
    def on_enter(e): b.config(bg=BG, highlightbackground=color)
    def on_leave(e): b.config(bg=BG3, highlightbackground=BORDER)
    b.bind("<Enter>", on_enter)
    b.bind("<Leave>", on_leave)
    return b

def status_bar(parent):
    f = tk.Frame(parent, bg=BG2, height=28)
    var = tk.StringVar(value="Ready.")
    lbl = tk.Label(f, textvariable=var, bg=BG2, fg=FG_DIM,
                   font=("Courier New", 9), anchor="w", padx=10)
    lbl.pack(fill="x", expand=True)
    return f, var

def separator(parent):
    tk.Frame(parent, bg=BORDER, height=1).pack(fill="x", pady=4)

def generate_keypair(key_size: int):
    private_key = rsa.generate_private_key(
        public_exponent=65537,
        key_size=key_size,
        backend=default_backend()
    )
    public_key = private_key.public_key()
    priv_pem = private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.TraditionalOpenSSL,
        encryption_algorithm=serialization.NoEncryption()
    ).decode()
    pub_pem = public_key.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo
    ).decode()
    return priv_pem, pub_pem

def load_private_key(pem: str):
    return serialization.load_pem_private_key(
        pem.encode(), password=None, backend=default_backend()
    )

def load_public_key(pem: str):
    return serialization.load_pem_public_key(
        pem.encode(), backend=default_backend()
    )

def rsa_encrypt(public_key_pem: str, plaintext: str) -> str:
    key = load_public_key(public_key_pem)
    ct = key.encrypt(
        plaintext.encode(),
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None
        )
    )
    return base64.b64encode(ct).decode()

def rsa_decrypt(private_key_pem: str, ciphertext_b64: str) -> str:
    key = load_private_key(private_key_pem)
    ct = base64.b64decode(ciphertext_b64.strip())
    pt = key.decrypt(
        ct,
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None
        )
    )
    return pt.decode()

def rsa_sign(private_key_pem: str, message: str) -> str:
    key = load_private_key(private_key_pem)
    sig = key.sign(
        message.encode(),
        padding.PSS(
            mgf=padding.MGF1(hashes.SHA256()),
            salt_length=padding.PSS.MAX_LENGTH
        ),
        hashes.SHA256()
    )
    return base64.b64encode(sig).decode()

def rsa_verify(public_key_pem: str, message: str, signature_b64: str) -> bool:
    key = load_public_key(public_key_pem)
    sig = base64.b64decode(signature_b64.strip())
    try:
        key.verify(
            sig,
            message.encode(),
            padding.PSS(
                mgf=padding.MGF1(hashes.SHA256()),
                salt_length=padding.PSS.MAX_LENGTH
            ),
            hashes.SHA256()
        )
        return True
    except InvalidSignature:
        return False

class RSAApp(tk.Tk):
    def __init__(self):
        super().__init__()
        self.title("RSA Tool")
        self.configure(bg=BG)
        self.resizable(True, True)
        self.minsize(820, 640)

        self._priv_pem = tk.StringVar()
        self._pub_pem  = tk.StringVar()

        self._build_titlebar()
        self._build_notebook()
        self._build_statusbar()

        self.update_idletasks()
        w, h = 940, 720
        x = (self.winfo_screenwidth()  - w) // 2
        y = (self.winfo_screenheight() - h) // 2
        self.geometry(f"{w}x{h}+{x}+{y}")

    def _build_titlebar(self):
        bar = styled_frame(self, bg=BG2)
        bar.pack(fill="x")
        tk.Frame(bar, bg=BORDER, height=1).pack(fill="x", side="bottom")

        inner = tk.Frame(bar, bg=BG2)
        inner.pack(fill="x", padx=20, pady=10)

        label(inner, "⬡ RSA TOOL", color=ACCENT, font=FONT_TITLE, bg=BG2).pack(side="left")
        label(inner, "  encrypt · decrypt · sign · verify · keygen",
              color=FG_DIM, font=("Courier New", 9), bg=BG2).pack(side="left", pady=2)

    def _build_statusbar(self):
        tk.Frame(self, bg=BORDER, height=1).pack(fill="x", side="bottom")
        self._status_frame, self._status = status_bar(self)
        self._status_frame.pack(fill="x", side="bottom")

    def _build_notebook(self):
        style = ttk.Style(self)
        style.theme_use("default")
        style.configure("TNotebook",
                        background=BG, borderwidth=0, tabmargins=[0, 0, 0, 0])
        style.configure("TNotebook.Tab",
                        background=BG2, foreground=FG_DIM,
                        font=FONT_UI, padding=[18, 8],
                        borderwidth=0)
        style.map("TNotebook.Tab",
                  background=[("selected", BG3), ("active", BG)],
                  foreground=[("selected", ACCENT), ("active", FG)])

        nb = ttk.Notebook(self)
        nb.pack(fill="both", expand=True, padx=0, pady=0)

        tabs = [
            ("  Keygen  ",   self._tab_keygen),
            ("  Encrypt  ",  self._tab_encrypt),
            ("  Decrypt  ",  self._tab_decrypt),
            ("  Sign  ",     self._tab_sign),
            ("  Verify  ",   self._tab_verify),
        ]
        for title, builder in tabs:
            frame = tk.Frame(nb, bg=BG)
            nb.add(frame, text=title)
            builder(frame)

    def _ok(self, msg):
        self._status.set(f"✓  {msg}")
        self._status_frame.config(bg=BG2)
        self.after(6000, lambda: self._status.set("Ready."))

    def _err(self, msg):
        self._status.set(f"✗  {msg}")
        self.after(6000, lambda: self._status.set("Ready."))

    def _copy(self, text):
        self.clipboard_clear()
        self.clipboard_append(text)
        self._ok("Copied to clipboard.")

    def _section(self, parent, title):
        f = tk.Frame(parent, bg=BG)
        f.pack(fill="x", padx=20, pady=(14, 4))
        label(f, title, color=FG_DIM, font=("Courier New", 9), bg=BG).pack(side="left")
        tk.Frame(f, bg=BORDER, height=1).pack(side="left", fill="x", expand=True, padx=(8,0), pady=6)
        return f

    def _field(self, parent, title, height=5, read_only=False):
        self._section(parent, title)
        box = text_box(parent, height=height)
        box.pack(fill="x", padx=20, pady=(0, 2))
        if read_only:
            box.config(state="disabled", fg=FG_DIM)
        return box

    def _btn_row(self, parent, buttons):
        row = tk.Frame(parent, bg=BG)
        row.pack(fill="x", padx=20, pady=6)
        for text, cmd, color, width in buttons:
            btn(row, text, cmd, color=color, width=width).pack(side="left", padx=(0, 8))
        return row

    def _tab_keygen(self, parent):
        self._section(parent, "KEY SIZE")
        size_row = tk.Frame(parent, bg=BG)
        size_row.pack(fill="x", padx=20, pady=(0, 8))

        self._key_size = tk.IntVar(value=2048)
        for sz in (1024, 2048, 4096):
            rb = tk.Radiobutton(size_row, text=f"{sz}-bit",
                                variable=self._key_size, value=sz,
                                bg=BG, fg=FG, selectcolor=BG3,
                                activebackground=BG, activeforeground=ACCENT,
                                font=FONT_UI, cursor="hand2")
            rb.pack(side="left", padx=(0, 16))

        self._priv_out = self._field(parent, "PRIVATE KEY  (keep secret)", height=7, read_only=True)
        self._pub_out  = self._field(parent, "PUBLIC KEY", height=5, read_only=True)

        self._btn_row(parent, [
            ("Generate Keypair",  self._do_keygen,         ACCENT,  18),
            ("Copy Private Key",  self._copy_priv,         FG_DIM,  16),
            ("Copy Public Key",   self._copy_pub,          FG_DIM,  16),
            ("Save Private Key",  self._save_priv,         YELLOW,  16),
            ("Save Public Key",   self._save_pub,          YELLOW,  16),
        ])

        note = "Keys are generated locally and never leave your machine."
        label(parent, note, color=FG_DIM, font=("Courier New", 8), bg=BG).pack(padx=20, anchor="w")

    def _set_rw(self, box, text):
        box.config(state="normal")
        box.delete("1.0", "end")
        box.insert("1.0", text)
        box.config(state="disabled")

    def _do_keygen(self):
        try:
            priv, pub = generate_keypair(self._key_size.get())
            self._priv_pem.set(priv)
            self._pub_pem.set(pub)
            self._set_rw(self._priv_out, priv)
            self._set_rw(self._pub_out, pub)
            self._ok(f"{self._key_size.get()}-bit keypair generated.")
        except Exception as e:
            self._err(str(e))

    def _copy_priv(self):
        v = self._priv_pem.get()
        if v: self._copy(v)
        else: self._err("Generate a keypair first.")

    def _copy_pub(self):
        v = self._pub_pem.get()
        if v: self._copy(v)
        else: self._err("Generate a keypair first.")

    def _save_priv(self):
        v = self._priv_pem.get()
        if not v: self._err("Generate a keypair first."); return
        path = filedialog.asksaveasfilename(defaultextension=".pem",
               filetypes=[("PEM files","*.pem"),("All","*.*")],
               initialfile="private_key.pem")
        if path:
            with open(path, "w") as f: f.write(v)
            self._ok(f"Private key saved → {path}")

    def _save_pub(self):
        v = self._pub_pem.get()
        if not v: self._err("Generate a keypair first."); return
        path = filedialog.asksaveasfilename(defaultextension=".pem",
               filetypes=[("PEM files","*.pem"),("All","*.*")],
               initialfile="public_key.pem")
        if path:
            with open(path, "w") as f: f.write(v)
            self._ok(f"Public key saved → {path}")

    def _tab_encrypt(self, parent):
        self._enc_pubkey  = self._field(parent, "PUBLIC KEY  (paste or load)", height=6)
        self._enc_plain   = self._field(parent, "PLAINTEXT", height=4)
        self._enc_out     = self._field(parent, "CIPHERTEXT  (Base64)", height=5, read_only=True)

        self._btn_row(parent, [
            ("Load Public Key",   self._load_pubkey_enc,   FG_DIM,  16),
            ("Use Generated Key", self._use_gen_pub,       FG_DIM,  18),
            ("Encrypt",          self._do_encrypt,         GREEN,   12),
            ("Copy Ciphertext",  lambda: self._copy(self._enc_out.get("1.0","end").strip()), FG_DIM, 16),
        ])

    def _load_pubkey_enc(self):
        path = filedialog.askopenfilename(filetypes=[("PEM","*.pem"),("All","*.*")])
        if path:
            with open(path) as f: data = f.read()
            self._enc_pubkey.delete("1.0","end")
            self._enc_pubkey.insert("1.0", data)

    def _use_gen_pub(self):
        v = self._pub_pem.get()
        if v:
            self._enc_pubkey.delete("1.0","end")
            self._enc_pubkey.insert("1.0", v)
        else:
            self._err("No generated key found — go to Keygen tab first.")

    def _do_encrypt(self):
        pub  = self._enc_pubkey.get("1.0","end").strip()
        text = self._enc_plain.get("1.0","end").strip()
        if not pub:  self._err("Paste a public key."); return
        if not text: self._err("Enter plaintext to encrypt."); return
        try:
            ct = rsa_encrypt(pub, text)
            self._set_rw(self._enc_out, ct)
            self._ok("Encrypted successfully (OAEP/SHA-256).")
        except Exception as e:
            self._err(str(e))

    def _tab_decrypt(self, parent):
        self._dec_privkey = self._field(parent, "PRIVATE KEY  (paste or load)", height=7)
        self._dec_cipher  = self._field(parent, "CIPHERTEXT  (Base64)", height=4)
        self._dec_out     = self._field(parent, "DECRYPTED PLAINTEXT", height=4, read_only=True)

        self._btn_row(parent, [
            ("Load Private Key",  self._load_privkey_dec,  FG_DIM,  16),
            ("Use Generated Key", self._use_gen_priv_dec,  FG_DIM,  18),
            ("Decrypt",          self._do_decrypt,         ACCENT,  12),
            ("Copy Plaintext",   lambda: self._copy(self._dec_out.get("1.0","end").strip()), FG_DIM, 14),
        ])

    def _load_privkey_dec(self):
        path = filedialog.askopenfilename(filetypes=[("PEM","*.pem"),("All","*.*")])
        if path:
            with open(path) as f: data = f.read()
            self._dec_privkey.delete("1.0","end")
            self._dec_privkey.insert("1.0", data)

    def _use_gen_priv_dec(self):
        v = self._priv_pem.get()
        if v:
            self._dec_privkey.delete("1.0","end")
            self._dec_privkey.insert("1.0", v)
        else:
            self._err("No generated key found — go to Keygen tab first.")

    def _do_decrypt(self):
        priv = self._dec_privkey.get("1.0","end").strip()
        ct   = self._dec_cipher.get("1.0","end").strip()
        if not priv: self._err("Paste a private key."); return
        if not ct:   self._err("Paste ciphertext to decrypt."); return
        try:
            pt = rsa_decrypt(priv, ct)
            self._set_rw(self._dec_out, pt)
            self._ok("Decrypted successfully.")
        except Exception as e:
            self._err(f"Decryption failed — {e}")

    def _tab_sign(self, parent):
        self._sign_privkey = self._field(parent, "PRIVATE KEY  (paste or load)", height=7)
        self._sign_msg     = self._field(parent, "MESSAGE", height=4)
        self._sign_out     = self._field(parent, "SIGNATURE  (Base64)", height=4, read_only=True)

        self._btn_row(parent, [
            ("Load Private Key",  self._load_privkey_sign, FG_DIM,  16),
            ("Use Generated Key", self._use_gen_priv_sign, FG_DIM,  18),
            ("Sign",             self._do_sign,            GREEN,   10),
            ("Copy Signature",   lambda: self._copy(self._sign_out.get("1.0","end").strip()), FG_DIM, 14),
        ])

    def _load_privkey_sign(self):
        path = filedialog.askopenfilename(filetypes=[("PEM","*.pem"),("All","*.*")])
        if path:
            with open(path) as f: data = f.read()
            self._sign_privkey.delete("1.0","end")
            self._sign_privkey.insert("1.0", data)

    def _use_gen_priv_sign(self):
        v = self._priv_pem.get()
        if v:
            self._sign_privkey.delete("1.0","end")
            self._sign_privkey.insert("1.0", v)
        else:
            self._err("No generated key found — go to Keygen tab first.")

    def _do_sign(self):
        priv = self._sign_privkey.get("1.0","end").strip()
        msg  = self._sign_msg.get("1.0","end").strip()
        if not priv: self._err("Paste a private key."); return
        if not msg:  self._err("Enter a message to sign."); return
        try:
            sig = rsa_sign(priv, msg)
            self._set_rw(self._sign_out, sig)
            self._ok("Message signed (PSS/SHA-256).")
        except Exception as e:
            self._err(str(e))

    def _tab_verify(self, parent):
        self._ver_pubkey = self._field(parent, "PUBLIC KEY  (paste or load)", height=6)
        self._ver_msg    = self._field(parent, "ORIGINAL MESSAGE", height=3)
        self._ver_sig    = self._field(parent, "SIGNATURE  (Base64)", height=3)

        self._btn_row(parent, [
            ("Load Public Key",   self._load_pubkey_ver,   FG_DIM,  16),
            ("Use Generated Key", self._use_gen_pub_ver,   FG_DIM,  18),
            ("Verify",           self._do_verify,          ACCENT,  10),
        ])

        self._section(parent, "RESULT")
        self._ver_result = tk.Label(parent, text="—", bg=BG, fg=FG_DIM,
                                    font=("Courier New", 14, "bold"), anchor="w")
        self._ver_result.pack(fill="x", padx=24, pady=4)

    def _load_pubkey_ver(self):
        path = filedialog.askopenfilename(filetypes=[("PEM","*.pem"),("All","*.*")])
        if path:
            with open(path) as f: data = f.read()
            self._ver_pubkey.delete("1.0","end")
            self._ver_pubkey.insert("1.0", data)

    def _use_gen_pub_ver(self):
        v = self._pub_pem.get()
        if v:
            self._ver_pubkey.delete("1.0","end")
            self._ver_pubkey.insert("1.0", v)
        else:
            self._err("No generated key found — go to Keygen tab first.")

    def _do_verify(self):
        pub = self._ver_pubkey.get("1.0","end").strip()
        msg = self._ver_msg.get("1.0","end").strip()
        sig = self._ver_sig.get("1.0","end").strip()
        if not pub: self._err("Paste a public key."); return
        if not msg: self._err("Enter the original message."); return
        if not sig: self._err("Paste the signature."); return
        try:
            valid = rsa_verify(pub, msg, sig)
            if valid:
                self._ver_result.config(text="✓  SIGNATURE VALID", fg=GREEN)
                self._ok("Signature verified successfully.")
            else:
                self._ver_result.config(text="✗  SIGNATURE INVALID", fg=RED)
                self._err("Signature does not match.")
        except Exception as e:
            self._ver_result.config(text="✗  ERROR", fg=RED)
            self._err(str(e))

if __name__ == "__main__":
    app = RSAApp()
    app.mainloop()
