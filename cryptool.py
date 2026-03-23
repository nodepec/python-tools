"""
CRYPTOOL — Advanced Encryption & Decryption Suite
  ·  tkinter + cryptography
"""

import sys, os, subprocess, importlib, base64, hashlib, secrets, time

if sys.platform == "win32" and "pythonw" not in sys.executable.lower():
    pythonw = sys.executable.replace("python.exe", "pythonw.exe")
    if os.path.exists(pythonw):
        subprocess.Popen([pythonw] + sys.argv)
        sys.exit()

def ensure(pkg, import_as=None):
    try: importlib.import_module(import_as or pkg.replace("-", "_"))
    except ImportError: subprocess.check_call([sys.executable, "-m", "pip", "install", pkg, "-q"])

ensure("cryptography")

import tkinter as tk
from tkinter import filedialog

from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
try:
    from cryptography.hazmat.decrepit.ciphers.algorithms import TripleDES as _3DES
except ImportError:
    _3DES = algorithms.TripleDES
from cryptography.hazmat.primitives.ciphers.aead import ChaCha20Poly1305
from cryptography.hazmat.primitives.asymmetric import rsa, padding as apad
from cryptography.hazmat.primitives import hashes, serialization, padding as sym_padding
from cryptography.hazmat.backends import default_backend
from cryptography.fernet import Fernet
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC

BG          = "#09090b"
SURFACE     = "#18181b"
SURFACE2    = "#27272a"
SURFACE3    = "#3f3f46"
BORDER      = "#27272a"
BORDER2     = "#3f3f46"
FG          = "#fafafa"
FG2         = "#a1a1aa"
FG3         = "#71717a"
ACCENT      = "#6366f1"
ACCENT_H    = "#4f46e5"
ACCENT_FG   = "#ffffff"
SUCCESS     = "#22c55e"
SUCCESS_BG  = "#14532d"
DANGER      = "#ef4444"
DANGER_BG   = "#7f1d1d"
WARNING     = "#f59e0b"
BLUE        = "#3b82f6"
PURPLE      = "#a855f7"

if sys.platform == "win32":
    FONT_UI   = "Segoe UI"
    FONT_MONO = "Cascadia Code"
elif sys.platform == "darwin":
    FONT_UI   = "SF Pro Text"
    FONT_MONO = "SF Mono"
else:
    FONT_UI   = "Ubuntu"
    FONT_MONO = "Ubuntu Mono"

def ff(size=10, weight="normal", mono=False):
    family = FONT_MONO if mono else FONT_UI
    return (family, size, weight)

def derive_key(password, salt, length):
    kdf = PBKDF2HMAC(algorithm=hashes.SHA256(), length=length,
                     salt=salt, iterations=260_000, backend=default_backend())
    return kdf.derive(password.encode())

def aes_encrypt(pt, pw):
    salt=secrets.token_bytes(16); key=derive_key(pw,salt,32); iv=secrets.token_bytes(12)
    enc=Cipher(algorithms.AES(key),modes.GCM(iv),backend=default_backend()).encryptor()
    ct=enc.update(pt)+enc.finalize(); return salt+iv+enc.tag+ct

def aes_decrypt(data, pw):
    s,iv,tag,ct=data[:16],data[16:28],data[28:44],data[44:]
    dec=Cipher(algorithms.AES(derive_key(pw,s,32)),modes.GCM(iv,tag),backend=default_backend()).decryptor()
    return dec.update(ct)+dec.finalize()

def aes_cbc_encrypt(pt, pw):
    salt=secrets.token_bytes(16); key=derive_key(pw,salt,32); iv=secrets.token_bytes(16)
    p=sym_padding.PKCS7(128).padder(); padded=p.update(pt)+p.finalize()
    enc=Cipher(algorithms.AES(key),modes.CBC(iv),backend=default_backend()).encryptor()
    return salt+iv+enc.update(padded)+enc.finalize()

def aes_cbc_decrypt(data, pw):
    s,iv,ct=data[:16],data[16:32],data[32:]
    dec=Cipher(algorithms.AES(derive_key(pw,s,32)),modes.CBC(iv),backend=default_backend()).decryptor()
    pad=dec.update(ct)+dec.finalize()
    u=sym_padding.PKCS7(128).unpadder(); return u.update(pad)+u.finalize()

def chacha_encrypt(pt, pw):
    salt=secrets.token_bytes(16); key=derive_key(pw,salt,32); n=secrets.token_bytes(12)
    return salt+n+ChaCha20Poly1305(key).encrypt(n,pt,None)

def chacha_decrypt(data, pw):
    s,n,ct=data[:16],data[16:28],data[28:]
    return ChaCha20Poly1305(derive_key(pw,s,32)).decrypt(n,ct,None)

def fernet_encrypt(pt, pw):
    salt=secrets.token_bytes(16); key=derive_key(pw,salt,32)
    return salt+Fernet(base64.urlsafe_b64encode(key)).encrypt(pt)

def fernet_decrypt(data, pw):
    s,ct=data[:16],data[16:]; key=derive_key(pw,s,32)
    return Fernet(base64.urlsafe_b64encode(key)).decrypt(ct)

def rsa_gen(bits=2048):
    priv=rsa.generate_private_key(65537,bits,default_backend()); pub=priv.public_key()
    return (priv.private_bytes(serialization.Encoding.PEM,serialization.PrivateFormat.TraditionalOpenSSL,serialization.NoEncryption()).decode(),
            pub.public_bytes(serialization.Encoding.PEM,serialization.PublicFormat.SubjectPublicKeyInfo).decode())

def rsa_encrypt(pt, pub_pem):
    return serialization.load_pem_public_key(pub_pem.encode(),default_backend()).encrypt(
        pt,apad.OAEP(mgf=apad.MGF1(hashes.SHA256()),algorithm=hashes.SHA256(),label=None))

def rsa_decrypt(data, priv_pem):
    return serialization.load_pem_private_key(priv_pem.encode(),None,default_backend()).decrypt(
        data,apad.OAEP(mgf=apad.MGF1(hashes.SHA256()),algorithm=hashes.SHA256(),label=None))

def xor_crypt(data, pw):
    key=hashlib.sha256(pw.encode()).digest()
    return bytes(b^key[i%32] for i,b in enumerate(data))

def caesar_crypt(text, shift):
    out=[]
    for c in text:
        if c.isupper(): out.append(chr((ord(c)-65+shift)%26+65))
        elif c.islower(): out.append(chr((ord(c)-97+shift)%26+97))
        else: out.append(c)
    return "".join(out)

def vigenere_crypt(text, key, encrypt):
    key=key.upper()
    if not key: raise ValueError("Key cannot be empty")
    out,ki=[],0
    for c in text:
        if c.isalpha():
            shift=ord(key[ki%len(key)])-65
            if not encrypt: shift=-shift
            base=65 if c.isupper() else 97
            out.append(chr((ord(c)-base+shift)%26+base)); ki+=1
        else: out.append(c)
    return "".join(out)

def blowfish_encrypt(pt, pw):
    salt=secrets.token_bytes(16); key=derive_key(pw,salt,32)[:16]; iv=secrets.token_bytes(8)
    pl=8-(len(pt)%8); padded=pt+bytes([pl]*pl)
    enc=Cipher(algorithms.Blowfish(key),modes.CBC(iv),backend=default_backend()).encryptor()
    return salt+iv+enc.update(padded)+enc.finalize()

def blowfish_decrypt(data, pw):
    s,iv,ct=data[:16],data[16:24],data[24:]
    dec=Cipher(algorithms.Blowfish(derive_key(pw,s,32)[:16]),modes.CBC(iv),backend=default_backend()).decryptor()
    pad=dec.update(ct)+dec.finalize(); return pad[:-pad[-1]]

def tdes_encrypt(pt, pw):
    salt=secrets.token_bytes(16); key=derive_key(pw,salt,24); iv=secrets.token_bytes(8)
    pl=8-(len(pt)%8); padded=pt+bytes([pl]*pl)
    enc=Cipher(_3DES(key),modes.CBC(iv),backend=default_backend()).encryptor()
    return salt+iv+enc.update(padded)+enc.finalize()

def tdes_decrypt(data, pw):
    s,iv,ct=data[:16],data[16:24],data[24:]
    dec=Cipher(_3DES(derive_key(pw,s,24)),modes.CBC(iv),backend=default_backend()).decryptor()
    pad=dec.update(ct)+dec.finalize(); return pad[:-pad[-1]]

def frame(parent, bg=None, **kw):
    return tk.Frame(parent, bg=bg or parent["bg"], **kw)

def label(parent, text, size=10, weight="normal", color=None, mono=False, **kw):
    return tk.Label(parent, text=text, font=ff(size,weight,mono),
                    fg=color or FG, bg=kw.pop("bg", parent["bg"]), **kw)

def scrolled_text(parent, height=8, mono=True, fg=FG, readonly=False, **kw):
    f = frame(parent, bg=SURFACE2)
    f.pack_propagate(False)
    sb = tk.Scrollbar(f, bg=SURFACE2, troughcolor=SURFACE2,
                      activebackground=SURFACE3, highlightthickness=0, bd=0, width=10)
    t = tk.Text(f, font=ff(10, mono=mono), fg=fg, bg=SURFACE2,
                insertbackground=ACCENT, relief="flat", bd=0,
                highlightthickness=0, selectbackground=ACCENT,
                selectforeground=FG, wrap="word", yscrollcommand=sb.set,
                padx=12, pady=10, **kw)
    sb.config(command=t.yview)
    t.pack(side="left", fill="both", expand=True)
    sb.pack(side="right", fill="y")
    if readonly:
        t.bind("<Key>", lambda e: "break")
    return f, t

class ModernBtn(tk.Frame):
    """A pill-shaped button with hover + active states."""
    def __init__(self, parent, text, command, variant="default", size="md", icon="", **kw):
        variants = {
            "default":   (SURFACE2, SURFACE3, FG),
            "primary":   (ACCENT, ACCENT_H, ACCENT_FG),
            "success":   ("#16a34a", "#15803d", "#fff"),
            "danger":    ("#dc2626", "#b91c1c", "#fff"),
            "ghost":     (SURFACE, SURFACE2, FG2),
            "outline":   (SURFACE, SURFACE2, FG),
        }
        sizes = {"sm": (8,4,9), "md": (14,7,10), "lg": (20,9,11)}
        bg, bg_h, fg = variants.get(variant, variants["default"])
        px, py, fs = sizes.get(size, sizes["md"])
        super().__init__(parent, bg=bg, cursor="hand2", **kw)
        self._bg, self._bg_h = bg, bg_h
        disp = f"{icon}  {text}" if icon else text
        self._lbl = tk.Label(self, text=disp, bg=bg, fg=fg,
                             font=ff(fs, "bold"), padx=px, pady=py)
        self._lbl.pack()
        for w in (self, self._lbl):
            w.bind("<Enter>",    lambda e: self._hover(True))
            w.bind("<Leave>",    lambda e: self._hover(False))
            w.bind("<Button-1>", lambda e: command())
        self.config(highlightthickness=1,
                    highlightbackground=BORDER2 if variant in ("default","ghost","outline") else bg_h,
                    highlightcolor=ACCENT)

    def _hover(self, on):
        c = self._bg_h if on else self._bg
        self.config(bg=c)
        self._lbl.config(bg=c)

class AlgoCard(tk.Frame):
    """Clickable algorithm selection card."""
    def __init__(self, parent, name, desc, tag, color, variable, on_select, **kw):
        super().__init__(parent, bg=SURFACE, cursor="hand2",
                         highlightthickness=1, highlightbackground=BORDER, **kw)
        self._name = name
        self._var  = variable
        self._color= color
        self._on_select = on_select

        top = frame(self, bg=SURFACE)
        top.pack(fill="x", padx=12, pady=(10,4))

        self._name_lbl = tk.Label(top, text=name, bg=SURFACE, fg=FG,
                                   font=ff(9,"bold"), anchor="w")
        self._name_lbl.pack(side="left")

        tk.Label(top, text=tag, bg=color, fg="#fff",
                 font=ff(7,"bold"), padx=5, pady=1).pack(side="right")

        tk.Label(self, text=desc, bg=SURFACE, fg=FG3,
                 font=ff(8), anchor="w", wraplength=160, justify="left",
                 padx=12).pack(fill="x", pady=(0,10))

        for w in self.winfo_children() + [self]:
            w.bind("<Button-1>", self._click)
            try:
                for ww in w.winfo_children():
                    ww.bind("<Button-1>", self._click)
            except: pass

        variable.trace_add("write", lambda *_: self._update())
        self._update()

    def _click(self, e=None):
        self._var.set(self._name)
        self._on_select()

    def _update(self):
        selected = self._var.get() == self._name
        if selected:
            self.config(highlightbackground=self._color, highlightthickness=2, bg=SURFACE2)
            self._name_lbl.config(fg=self._color, bg=SURFACE2)
            for c in self.winfo_children():
                if isinstance(c, tk.Label): c.config(bg=SURFACE2)
        else:
            self.config(highlightbackground=BORDER, highlightthickness=1, bg=SURFACE)
            self._name_lbl.config(fg=FG, bg=SURFACE)
            for c in self.winfo_children():
                if isinstance(c, tk.Label): c.config(bg=SURFACE)

class Toast:
    """Transient notification bar."""
    def __init__(self, parent):
        self._parent = parent
        self._frame = frame(parent, bg=SURFACE2,
                            highlightthickness=1, highlightbackground=BORDER2)
        self._lbl = tk.Label(self._frame, text="", fg=FG2, bg=SURFACE2,
                             font=ff(9), anchor="w", padx=14, pady=6)
        self._lbl.pack(fill="x")
        self._after_id = None

    def show(self, msg, kind="ok"):
        colors = {"ok": (SUCCESS, SUCCESS_BG), "err": (DANGER, DANGER_BG), "info": (BLUE, SURFACE2)}
        fg, bg = colors.get(kind, colors["ok"])
        self._frame.config(bg=bg, highlightbackground=fg)
        self._lbl.config(text=msg, fg=fg, bg=bg)
        self._frame.pack(fill="x", side="bottom")
        if self._after_id: self._parent.after_cancel(self._after_id)
        self._after_id = self._parent.after(5000, self._hide)

    def _hide(self):
        self._frame.pack_forget()

ALGOS = [
    ("AES-256-GCM",       "Authenticated encryption, tamper-proof",      "AEAD",   ACCENT),
    ("AES-256-CBC",       "Classic block cipher with PKCS7 padding",     "SYM",    BLUE),
    ("ChaCha20-Poly1305", "Fast authenticated stream cipher",            "AEAD",   "#06b6d4"),
    ("Fernet",            "Safe symmetric wrapper, HMAC signed",         "SYM",    PURPLE),
    ("Blowfish-CBC",      "Legacy 128-bit block cipher",                 "LEGACY", WARNING),
    ("3DES-CBC",          "Triple DES, 192-bit legacy mode",             "LEGACY", WARNING),
    ("RSA-OAEP",          "Asymmetric keypair encryption",               "ASYM",   "#ec4899"),
    ("XOR",               "SHA-256 key-stretched XOR stream",            "BASIC",  FG3),
    ("Caesar",            "Classic alphabetic shift cipher",             "CLASS",  FG3),
    ("Vigenère",          "Polyalphabetic keyword cipher",               "CLASS",  FG3),
]

DISPATCH_ENC = {
    "AES-256-GCM": aes_encrypt, "AES-256-CBC": aes_cbc_encrypt,
    "ChaCha20-Poly1305": chacha_encrypt, "Fernet": fernet_encrypt,
    "Blowfish-CBC": blowfish_encrypt, "3DES-CBC": tdes_encrypt, "XOR": xor_crypt,
}
DISPATCH_DEC = {
    "AES-256-GCM": aes_decrypt, "AES-256-CBC": aes_cbc_decrypt,
    "ChaCha20-Poly1305": chacha_decrypt, "Fernet": fernet_decrypt,
    "Blowfish-CBC": blowfish_decrypt, "3DES-CBC": tdes_decrypt, "XOR": xor_crypt,
}

class CrypTool(tk.Tk):
    def __init__(self):
        super().__init__()
        self.title("Cryptool")
        self.configure(bg=BG)
        self.minsize(1100, 700)
        self._algo   = tk.StringVar(value="AES-256-GCM")
        self._fmt    = tk.StringVar(value="base64")
        self._rsa_bits = tk.IntVar(value=2048)
        self._build()
        w, h = 1200, 800
        self.geometry(f"{w}x{h}+{(self.winfo_screenwidth()-w)//2}+{(self.winfo_screenheight()-h)//2}")

    def _build(self):
        self._build_titlebar()
        content = frame(self, bg=BG)
        content.pack(fill="both", expand=True)
        self._build_sidebar(content)
        tk.Frame(content, bg=BORDER, width=1).pack(side="left", fill="y")
        self._build_main(content)
        self._toast = Toast(self)

    def _build_titlebar(self):
        bar = frame(self, bg=SURFACE)
        bar.pack(fill="x")
        tk.Frame(bar, bg=BORDER, height=1).pack(fill="x", side="bottom")

        inner = frame(bar, bg=SURFACE)
        inner.pack(fill="x", padx=20, pady=0)

        left = frame(inner, bg=SURFACE)
        left.pack(side="left", pady=12)

        dot = frame(left, bg=ACCENT, width=8, height=8)
        dot.pack(side="left", padx=(0,10))
        dot.pack_propagate(False)

        tk.Label(left, text="Cryptool", bg=SURFACE, fg=FG,
                 font=ff(14,"bold")).pack(side="left")
        tk.Label(left, text="  Encryption & Decryption Suite", bg=SURFACE, fg=FG3,
                 font=ff(10)).pack(side="left", pady=2)

        right = frame(inner, bg=SURFACE)
        right.pack(side="right", pady=12)
        for algo_name in ["AES", "RSA", "ChaCha20", "Fernet"]:
            tk.Label(right, text=algo_name, bg=SURFACE2, fg=FG2,
                     font=ff(8), padx=8, pady=3).pack(side="left", padx=2)

    def _build_sidebar(self, parent):
        sidebar = frame(parent, bg=SURFACE, width=280)
        sidebar.pack(side="left", fill="y")
        sidebar.pack_propagate(False)

        canvas = tk.Canvas(sidebar, bg=SURFACE, highlightthickness=0, bd=0)
        vsb = tk.Scrollbar(sidebar, orient="vertical", command=canvas.yview,
                           bg=SURFACE, troughcolor=SURFACE, width=6,
                           activebackground=SURFACE3, highlightthickness=0, bd=0)
        canvas.configure(yscrollcommand=vsb.set)
        vsb.pack(side="right", fill="y")
        canvas.pack(side="left", fill="both", expand=True)

        inner = frame(canvas, bg=SURFACE)
        inner_id = canvas.create_window((0,0), window=inner, anchor="nw")

        def _resize(e):
            canvas.itemconfig(inner_id, width=e.width)
        canvas.bind("<Configure>", _resize)
        inner.bind("<Configure>", lambda e: canvas.configure(scrollregion=canvas.bbox("all")))

        def _scroll(e):
            canvas.yview_scroll(int(-1*(e.delta/120)), "units")
        canvas.bind_all("<MouseWheel>", _scroll)

        section_lbl = tk.Label(inner, text="ALGORITHM", bg=SURFACE, fg=FG3,
                               font=ff(8,"bold"), anchor="w", padx=16)
        section_lbl.pack(fill="x", pady=(16,4))

        self._algo_cards = {}
        cards_frame = frame(inner, bg=SURFACE)
        cards_frame.pack(fill="x", padx=10, pady=4)

        for name, desc, tag, color in ALGOS:
            card = AlgoCard(cards_frame, name, desc, tag, color,
                            self._algo, self._on_algo_change)
            card.pack(fill="x", pady=3)
            self._algo_cards[name] = card

        tk.Frame(inner, bg=BORDER, height=1).pack(fill="x", padx=16, pady=12)

        self._key_section = frame(inner, bg=SURFACE)
        self._key_section.pack(fill="x")
        self._build_key_section(self._key_section)

        tk.Frame(inner, bg=BORDER, height=1).pack(fill="x", padx=16, pady=12)

        tk.Label(inner, text="OUTPUT FORMAT", bg=SURFACE, fg=FG3,
                 font=ff(8,"bold"), anchor="w", padx=16).pack(fill="x")
        fmt_row = frame(inner, bg=SURFACE)
        fmt_row.pack(fill="x", padx=16, pady=8)

        self._fmt_btns = {}
        for val, lbl_txt in (("base64","Base64"),("hex","Hex"),("raw","Raw")):
            b = tk.Label(fmt_row, text=lbl_txt, bg=SURFACE2, fg=FG2,
                         font=ff(9), padx=10, pady=5, cursor="hand2",
                         highlightthickness=1, highlightbackground=BORDER2)
            b.pack(side="left", padx=(0,4))
            b.bind("<Button-1>", lambda e, v=val: self._set_fmt(v))
            self._fmt_btns[val] = b
        self._set_fmt("base64")

    def _set_fmt(self, val):
        self._fmt.set(val)
        for k, b in self._fmt_btns.items():
            if k == val:
                b.config(bg=ACCENT, fg=ACCENT_FG, highlightbackground=ACCENT)
            else:
                b.config(bg=SURFACE2, fg=FG2, highlightbackground=BORDER2)

    def _build_key_section(self, parent):
        tk.Label(parent, text="KEY / PASSWORD", bg=SURFACE, fg=FG3,
                 font=ff(8,"bold"), anchor="w", padx=16).pack(fill="x")

        self._pw_frame = frame(parent, bg=SURFACE)
        pw_inner = frame(self._pw_frame, bg=SURFACE)
        pw_inner.pack(fill="x", padx=16, pady=6)
        tk.Label(pw_inner, text="Password", bg=SURFACE, fg=FG2,
                 font=ff(9), anchor="w").pack(fill="x", pady=(0,4))

        pw_box = frame(pw_inner, bg=SURFACE2, highlightthickness=1,
                       highlightbackground=BORDER2)
        pw_box.pack(fill="x")
        self._pw = tk.Entry(pw_box, bg=SURFACE2, fg=FG, insertbackground=ACCENT,
                            font=ff(10, mono=True), show="•", relief="flat", bd=0,
                            highlightthickness=0)
        self._pw.pack(fill="x", padx=10, pady=8)
        pw_box.bind("<FocusIn>", lambda e: pw_box.config(highlightbackground=ACCENT))
        self._pw.bind("<FocusIn>",  lambda e: pw_box.config(highlightbackground=ACCENT))
        self._pw.bind("<FocusOut>", lambda e: pw_box.config(highlightbackground=BORDER2))

        self._show_pw = tk.BooleanVar()
        tk.Checkbutton(pw_inner, text="Show password", variable=self._show_pw,
                       bg=SURFACE, fg=FG3, activebackground=SURFACE,
                       selectcolor=SURFACE2, font=ff(8), cursor="hand2",
                       command=lambda: self._pw.config(show="" if self._show_pw.get() else "•")
                       ).pack(anchor="w", pady=(4,0))

        self._shift_frame = frame(parent, bg=SURFACE)
        sf = frame(self._shift_frame, bg=SURFACE)
        sf.pack(fill="x", padx=16, pady=6)
        tk.Label(sf, text="Caesar Shift", bg=SURFACE, fg=FG2,
                 font=ff(9), anchor="w").pack(fill="x", pady=(0,4))
        spin_box = frame(sf, bg=SURFACE2, highlightthickness=1, highlightbackground=BORDER2)
        spin_box.pack(anchor="w")
        self._shift = tk.Spinbox(spin_box, from_=1, to=25, width=5,
                                  bg=SURFACE2, fg=FG, font=ff(10, mono=True),
                                  relief="flat", bd=0, buttonbackground=SURFACE3,
                                  insertbackground=ACCENT, highlightthickness=0)
        self._shift.pack(padx=10, pady=6)

        self._rsa_frame = frame(parent, bg=SURFACE)
        rf = frame(self._rsa_frame, bg=SURFACE)
        rf.pack(fill="x", padx=16, pady=6)

        tk.Label(rf, text="Key Size", bg=SURFACE, fg=FG2,
                 font=ff(9), anchor="w").pack(fill="x", pady=(0,6))
        bits_row = frame(rf, bg=SURFACE)
        bits_row.pack(anchor="w", pady=(0,8))
        for b in (1024, 2048, 4096):
            rb = tk.Radiobutton(bits_row, text=f"{b}-bit", variable=self._rsa_bits,
                                value=b, bg=SURFACE, fg=FG2, activebackground=SURFACE,
                                activeforeground=FG, selectcolor=SURFACE2,
                                font=ff(9), cursor="hand2")
            rb.pack(side="left", padx=(0,10))

        ModernBtn(rf, "Generate Keypair", self._rsa_gen, variant="primary", size="sm"
                  ).pack(anchor="w", pady=(0,6))
        ModernBtn(rf, "Load from .pem", self._rsa_load, variant="ghost", size="sm"
                  ).pack(anchor="w", pady=(0,8))

        tk.Label(rf, text="Public Key", bg=SURFACE, fg=FG2,
                 font=ff(8), anchor="w").pack(fill="x", pady=(0,2))
        pub_wrap, self._rsa_pub_box = scrolled_text(rf, height=60, fg=FG2)
        pub_wrap.pack(fill="x", pady=(0,6))
        pub_wrap.config(height=60)

        tk.Label(rf, text="Private Key", bg=SURFACE, fg=FG2,
                 font=ff(8), anchor="w").pack(fill="x", pady=(0,2))
        priv_wrap, self._rsa_priv_box = scrolled_text(rf, height=60, fg=FG2)
        priv_wrap.pack(fill="x")
        priv_wrap.config(height=60)

        self._on_algo_change()

    def _on_algo_change(self):
        algo = self._algo.get()
        self._pw_frame.pack_forget()
        self._shift_frame.pack_forget()
        self._rsa_frame.pack_forget()

        if algo == "Caesar":
            self._shift_frame.pack(fill="x")
        elif algo == "RSA-OAEP":
            self._rsa_frame.pack(fill="x")
        else:
            self._pw_frame.pack(fill="x")

        if hasattr(self, "_algo_badge_lbl"):
            for name, desc, tag, color in ALGOS:
                if name == algo:
                    self._algo_badge_lbl.config(text=f"  {name}  ", bg=color)
                    break

    def _build_main(self, parent):
        main = frame(parent, bg=BG)
        main.pack(side="left", fill="both", expand=True)

        io_area = frame(main, bg=BG)
        io_area.pack(fill="both", expand=True)

        input_col = frame(io_area, bg=BG)
        input_col.pack(side="left", fill="both", expand=True)
        tk.Frame(io_area, bg=BORDER, width=1).pack(side="left", fill="y")
        output_col = frame(io_area, bg=BG)
        output_col.pack(side="left", fill="both", expand=True)

        self._build_io_panel(input_col, "INPUT", is_input=True)
        self._build_io_panel(output_col, "OUTPUT", is_input=False)

        tk.Frame(main, bg=BORDER, height=1).pack(fill="x")
        self._build_action_bar(main)

    def _build_io_panel(self, parent, title, is_input):
        hdr = frame(parent, bg=SURFACE)
        hdr.pack(fill="x")
        tk.Frame(hdr, bg=BORDER, height=1).pack(fill="x", side="bottom")

        inner_hdr = frame(hdr, bg=SURFACE)
        inner_hdr.pack(fill="x", padx=16, pady=10)

        tk.Label(inner_hdr, text=title, bg=SURFACE, fg=FG,
                 font=ff(9,"bold")).pack(side="left")

        if not is_input:
            self._algo_badge_lbl = tk.Label(inner_hdr, text="  AES-256-GCM  ",
                                             bg=ACCENT, fg="#fff", font=ff(8,"bold"),
                                             padx=2, pady=2)
            self._algo_badge_lbl.pack(side="left", padx=8)

        copy_btn = tk.Label(inner_hdr, text="Copy", bg=SURFACE, fg=FG3,
                            font=ff(9), cursor="hand2",
                            highlightthickness=1, highlightbackground=BORDER2,
                            padx=10, pady=3)
        copy_btn.pack(side="right")

        if is_input:
            clear_btn = tk.Label(inner_hdr, text="Clear", bg=SURFACE, fg=FG3,
                                 font=ff(9), cursor="hand2",
                                 highlightthickness=1, highlightbackground=BORDER2,
                                 padx=10, pady=3)
            clear_btn.pack(side="right", padx=(0,6))

        text_wrap, text_box = scrolled_text(parent, readonly=not is_input)
        text_wrap.pack(fill="both", expand=True)

        def _copy():
            self.clipboard_clear()
            self.clipboard_append(text_box.get("1.0","end").strip())
            self._toast.show("Copied to clipboard.", "info")

        copy_btn.bind("<Button-1>", lambda e: _copy())
        copy_btn.bind("<Enter>", lambda e: copy_btn.config(fg=FG, highlightbackground=ACCENT))
        copy_btn.bind("<Leave>", lambda e: copy_btn.config(fg=FG3, highlightbackground=BORDER2))

        if is_input:
            self._input_box = text_box
            clear_btn.bind("<Button-1>", lambda e: (text_box.delete("1.0","end")))
            clear_btn.bind("<Enter>", lambda e: clear_btn.config(fg=FG, highlightbackground=DANGER))
            clear_btn.bind("<Leave>", lambda e: clear_btn.config(fg=FG3, highlightbackground=BORDER2))
        else:
            self._output_box = text_box
            text_box.config(fg=FG2)

    def _build_action_bar(self, parent):
        bar = frame(parent, bg=SURFACE)
        bar.pack(fill="x")

        inner = frame(bar, bg=SURFACE)
        inner.pack(fill="x", padx=16, pady=10)

        ModernBtn(inner, "Encrypt", self._do_encrypt, variant="primary", icon="🔒"
                  ).pack(side="left", padx=(0,8))
        ModernBtn(inner, "Decrypt", self._do_decrypt, variant="success", icon="🔓"
                  ).pack(side="left", padx=(0,16))

        tk.Frame(inner, bg=BORDER2, width=1, height=24).pack(side="left", padx=8, fill="y")

        ModernBtn(inner, "Load File", self._load_file, variant="ghost", size="sm"
                  ).pack(side="left", padx=(0,6))
        ModernBtn(inner, "Save Output", self._save_output, variant="ghost", size="sm"
                  ).pack(side="left", padx=(0,6))
        ModernBtn(inner, "Swap ⇅", self._swap, variant="ghost", size="sm"
                  ).pack(side="left", padx=(0,6))
        ModernBtn(inner, "Clear All", self._clear, variant="danger", size="sm"
                  ).pack(side="left")

    def _ok(self, msg):  self._toast.show(f"✓  {msg}", "ok")
    def _err(self, msg): self._toast.show(f"✗  {msg}", "err")

    def _encode_out(self, data):
        fmt = self._fmt.get()
        if fmt == "base64": return base64.b64encode(data).decode()
        if fmt == "hex":    return data.hex()
        try: return data.decode()
        except: return base64.b64encode(data).decode() + "  [non-UTF8, fell back to base64]"

    def _decode_in(self, text):
        t = text.strip()
        fmt = self._fmt.get()
        if fmt == "base64": return base64.b64decode(t)
        if fmt == "hex":    return bytes.fromhex(t.replace(" ",""))
        return t.encode()

    def _get_input(self): return self._input_box.get("1.0","end").strip()

    def _set_output(self, text):
        self._output_box.config(state="normal")
        self._output_box.delete("1.0","end")
        self._output_box.insert("1.0", text)
        self._output_box.config(state="disabled")

    def _do_encrypt(self):
        inp  = self._get_input()
        algo = self._algo.get()
        pw   = self._pw.get()
        if not inp: self._err("No input text."); return

        if algo == "Caesar":
            try:
                shift = int(self._shift.get())
                self._set_output(caesar_crypt(inp, shift))
                self._ok(f"Caesar encrypted (shift {shift}).")
            except Exception as e: self._err(str(e))
            return

        if algo == "Vigenère":
            if not pw: self._err("Enter a keyword."); return
            try:
                self._set_output(vigenere_crypt(inp, pw, True))
                self._ok("Vigenère encrypted.")
            except Exception as e: self._err(str(e))
            return

        if algo == "RSA-OAEP":
            pub = self._rsa_pub_box.get("1.0","end").strip()
            if not pub: self._err("Paste or generate a public key."); return
            try:
                self._set_output(self._encode_out(rsa_encrypt(inp.encode(), pub)))
                self._ok("RSA-OAEP encrypted.")
            except Exception as e: self._err(str(e))
            return

        if not pw: self._err("Enter a password."); return
        try:
            ct = DISPATCH_ENC[algo](inp.encode(), pw)
            self._set_output(self._encode_out(ct))
            self._ok(f"{algo} encrypted.")
        except Exception as e: self._err(str(e))

    def _do_decrypt(self):
        inp  = self._get_input()
        algo = self._algo.get()
        pw   = self._pw.get()
        if not inp: self._err("No input text."); return

        if algo == "Caesar":
            try:
                shift = int(self._shift.get())
                self._set_output(caesar_crypt(inp, -shift))
                self._ok(f"Caesar decrypted (shift -{shift}).")
            except Exception as e: self._err(str(e))
            return

        if algo == "Vigenère":
            if not pw: self._err("Enter the keyword."); return
            try:
                self._set_output(vigenere_crypt(inp, pw, False))
                self._ok("Vigenère decrypted.")
            except Exception as e: self._err(str(e))
            return

        if algo == "RSA-OAEP":
            priv = self._rsa_priv_box.get("1.0","end").strip()
            if not priv: self._err("Paste or generate a private key."); return
            try:
                ct = self._decode_in(inp)
                self._set_output(rsa_decrypt(ct, priv).decode(errors="replace"))
                self._ok("RSA-OAEP decrypted.")
            except Exception as e: self._err(str(e))
            return

        if not pw: self._err("Enter a password."); return
        try:
            ct = self._decode_in(inp)
            pt = DISPATCH_DEC[algo](ct, pw)
            self._set_output(pt.decode(errors="replace"))
            self._ok(f"{algo} decrypted.")
        except Exception as e: self._err(f"Decryption failed: {e}")

    def _rsa_gen(self):
        try:
            priv, pub = rsa_gen(self._rsa_bits.get())
            self._rsa_pub_box.delete("1.0","end"); self._rsa_pub_box.insert("1.0", pub)
            self._rsa_priv_box.delete("1.0","end"); self._rsa_priv_box.insert("1.0", priv)
            self._ok(f"{self._rsa_bits.get()}-bit RSA keypair generated.")
        except Exception as e: self._err(str(e))

    def _rsa_load(self):
        path = filedialog.askopenfilename(filetypes=[("PEM","*.pem"),("All","*.*")])
        if not path: return
        with open(path) as f: data = f.read()
        if "PRIVATE" in data:
            self._rsa_priv_box.delete("1.0","end"); self._rsa_priv_box.insert("1.0", data)
            self._ok("Private key loaded.")
        else:
            self._rsa_pub_box.delete("1.0","end"); self._rsa_pub_box.insert("1.0", data)
            self._ok("Public key loaded.")

    def _load_file(self):
        path = filedialog.askopenfilename()
        if not path: return
        try:
            raw = open(path,"rb").read()
            try: text = raw.decode(); self._input_box.delete("1.0","end"); self._input_box.insert("1.0", text)
            except UnicodeDecodeError:
                text = base64.b64encode(raw).decode()
                self._input_box.delete("1.0","end"); self._input_box.insert("1.0", text)
                self._ok("Binary file loaded as Base64."); return
            self._ok(f"Loaded: {os.path.basename(path)}")
        except Exception as e: self._err(str(e))

    def _save_output(self):
        out = self._output_box.get("1.0","end").strip()
        if not out: self._err("Nothing in output."); return
        path = filedialog.asksaveasfilename(defaultextension=".txt",
               filetypes=[("Text","*.txt"),("All","*.*")])
        if path:
            open(path,"w").write(out)
            self._ok(f"Saved → {os.path.basename(path)}")

    def _swap(self):
        inp = self._input_box.get("1.0","end").strip()
        out = self._output_box.get("1.0","end").strip()
        self._input_box.delete("1.0","end"); self._input_box.insert("1.0", out)
        self._output_box.config(state="normal")
        self._output_box.delete("1.0","end"); self._output_box.insert("1.0", inp)
        self._output_box.config(state="disabled")
        self._ok("Swapped.")

    def _clear(self):
        self._input_box.delete("1.0","end")
        self._output_box.config(state="normal"); self._output_box.delete("1.0","end")
        self._output_box.config(state="disabled")
        self._pw.delete(0,"end")
        self._ok("Cleared.")


if __name__ == "__main__":
    app = CrypTool()
    app.mainloop()
