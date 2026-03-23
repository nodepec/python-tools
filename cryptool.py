"""
CRYPTOOL v3 — Advanced Cryptography Suite
Tabbed UI: Cipher · Hash · RSA Keys · Password · Analyzer
"""

import sys, os, subprocess, importlib, base64, hashlib, secrets, hmac as _hmac, time, re, struct

if sys.platform == "win32" and "pythonw" not in sys.executable.lower():
    pythonw = sys.executable.replace("python.exe", "pythonw.exe")
    if os.path.exists(pythonw):
        subprocess.Popen([pythonw] + sys.argv); sys.exit()

def ensure(pkg, imp=None):
    try: importlib.import_module(imp or pkg.replace("-","_"))
    except ImportError: subprocess.check_call([sys.executable,"-m","pip","install",pkg,"-q"])

ensure("cryptography")

import tkinter as tk
from tkinter import filedialog, ttk

from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives.ciphers.aead import ChaCha20Poly1305, AESGCM
from cryptography.hazmat.primitives.asymmetric import rsa, padding as apad, ec
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives import hashes, serialization, padding as bpad, hmac
from cryptography.hazmat.backends import default_backend
from cryptography.fernet import Fernet
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives.kdf.scrypt import Scrypt
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives.asymmetric import padding as rsapad
from cryptography.exceptions import InvalidSignature

try:
    from cryptography.hazmat.decrepit.ciphers.algorithms import TripleDES as _3DES
except ImportError:
    _3DES = algorithms.TripleDES

BG       = "#09090b"
SURF     = "#18181b"
SURF2    = "#27272a"
SURF3    = "#3f3f46"
BORD     = "#3f3f46"
BORD2    = "#52525b"
FG       = "#fafafa"
FG2      = "#a1a1aa"
FG3      = "#71717a"
IND      = "#6366f1"
IND_H    = "#4f46e5"
IND_L    = "#818cf8"
GRN      = "#22c55e"
GRN_BG   = "#052e16"
RED      = "#ef4444"
RED_BG   = "#450a0a"
AMB      = "#f59e0b"
AMB_BG   = "#451a03"
BLU      = "#3b82f6"
BLU_BG   = "#172554"
PUR      = "#a855f7"
CYN      = "#06b6d4"

if sys.platform == "win32":
    FUI, FMONO = "Segoe UI", "Consolas"
elif sys.platform == "darwin":
    FUI, FMONO = "SF Pro Text", "SF Mono"
else:
    FUI, FMONO = "Ubuntu", "Ubuntu Mono"

def F(s=10, w="normal", m=False): return (FMONO if m else FUI, s, w)


def pbkdf2(pw, salt, n): 
    return PBKDF2HMAC(hashes.SHA256(), n, salt, 260_000, default_backend()).derive(pw.encode())

def scrypt_kdf(pw, salt, n):
    return Scrypt(salt, n, 2**15, 8, 1, default_backend()).derive(pw.encode())

def aes_gcm_enc(pt, pw):
    s=secrets.token_bytes(16); k=pbkdf2(pw,s,32); iv=secrets.token_bytes(12)
    e=Cipher(algorithms.AES(k),modes.GCM(iv),backend=default_backend()).encryptor()
    ct=e.update(pt)+e.finalize(); return s+iv+e.tag+ct

def aes_gcm_dec(d, pw):
    s,iv,tag,ct=d[:16],d[16:28],d[28:44],d[44:]
    e=Cipher(algorithms.AES(pbkdf2(pw,s,32)),modes.GCM(iv,tag),backend=default_backend()).decryptor()
    return e.update(ct)+e.finalize()

def aes_cbc_enc(pt, pw):
    s=secrets.token_bytes(16); k=pbkdf2(pw,s,32); iv=secrets.token_bytes(16)
    p=bpad.PKCS7(128).padder(); pd=p.update(pt)+p.finalize()
    e=Cipher(algorithms.AES(k),modes.CBC(iv),backend=default_backend()).encryptor()
    return s+iv+e.update(pd)+e.finalize()

def aes_cbc_dec(d, pw):
    s,iv,ct=d[:16],d[16:32],d[32:]
    e=Cipher(algorithms.AES(pbkdf2(pw,s,32)),modes.CBC(iv),backend=default_backend()).decryptor()
    pd=e.update(ct)+e.finalize(); u=bpad.PKCS7(128).unpadder(); return u.update(pd)+u.finalize()

def aes_ctr_enc(pt, pw):
    s=secrets.token_bytes(16); k=pbkdf2(pw,s,32); nonce=secrets.token_bytes(16)
    e=Cipher(algorithms.AES(k),modes.CTR(nonce),backend=default_backend()).encryptor()
    return s+nonce+e.update(pt)+e.finalize()

def aes_ctr_dec(d, pw):
    s,nonce,ct=d[:16],d[16:32],d[32:]
    e=Cipher(algorithms.AES(pbkdf2(pw,s,32)),modes.CTR(nonce),backend=default_backend()).decryptor()
    return e.update(ct)+e.finalize()

def chacha_enc(pt, pw):
    s=secrets.token_bytes(16); k=pbkdf2(pw,s,32); n=secrets.token_bytes(12)
    return s+n+ChaCha20Poly1305(k).encrypt(n,pt,None)

def chacha_dec(d, pw):
    s,n,ct=d[:16],d[16:28],d[28:]
    return ChaCha20Poly1305(pbkdf2(pw,s,32)).decrypt(n,ct,None)

def fernet_enc(pt, pw):
    s=secrets.token_bytes(16); k=pbkdf2(pw,s,32)
    return s+Fernet(base64.urlsafe_b64encode(k)).encrypt(pt)

def fernet_dec(d, pw):
    s,ct=d[:16],d[16:]; k=pbkdf2(pw,s,32)
    return Fernet(base64.urlsafe_b64encode(k)).decrypt(ct)

def blowfish_enc(pt, pw):
    s=secrets.token_bytes(16); k=pbkdf2(pw,s,32)[:16]; iv=secrets.token_bytes(8)
    pl=8-(len(pt)%8); pd=pt+bytes([pl]*pl)
    e=Cipher(algorithms.Blowfish(k),modes.CBC(iv),backend=default_backend()).encryptor()
    return s+iv+e.update(pd)+e.finalize()

def blowfish_dec(d, pw):
    s,iv,ct=d[:16],d[16:24],d[24:]
    e=Cipher(algorithms.Blowfish(pbkdf2(pw,s,32)[:16]),modes.CBC(iv),backend=default_backend()).decryptor()
    pd=e.update(ct)+e.finalize(); return pd[:-pd[-1]]

def tdes_enc(pt, pw):
    s=secrets.token_bytes(16); k=pbkdf2(pw,s,24); iv=secrets.token_bytes(8)
    pl=8-(len(pt)%8); pd=pt+bytes([pl]*pl)
    e=Cipher(_3DES(k),modes.CBC(iv),backend=default_backend()).encryptor()
    return s+iv+e.update(pd)+e.finalize()

def tdes_dec(d, pw):
    s,iv,ct=d[:16],d[16:24],d[24:]
    e=Cipher(_3DES(pbkdf2(pw,s,24)),modes.CBC(iv),backend=default_backend()).decryptor()
    pd=e.update(ct)+e.finalize(); return pd[:-pd[-1]]

def xor_enc(d, pw):
    k=hashlib.sha256(pw.encode()).digest(); return bytes(b^k[i%32] for i,b in enumerate(d))

def caesar_enc(t, s): return "".join(chr((ord(c)-65+s)%26+65) if c.isupper() else chr((ord(c)-97+s)%26+97) if c.islower() else c for c in t)

def vigenere(t, key, enc):
    key=key.upper()
    if not key: raise ValueError("Key empty")
    out,ki=[],0
    for c in t:
        if c.isalpha():
            s=ord(key[ki%len(key)])-65; s=s if enc else -s
            b=65 if c.isupper() else 97; out.append(chr((ord(c)-b+s)%26+b)); ki+=1
        else: out.append(c)
    return "".join(out)

def rsa_keygen(bits):
    pk=rsa.generate_private_key(65537,bits,default_backend())
    return (pk.private_bytes(serialization.Encoding.PEM,serialization.PrivateFormat.PKCS8,serialization.NoEncryption()).decode(),
            pk.public_key().public_bytes(serialization.Encoding.PEM,serialization.PublicFormat.SubjectPublicKeyInfo).decode())

def rsa_enc(pt, pub):
    return serialization.load_pem_public_key(pub.encode(),default_backend()).encrypt(
        pt,apad.OAEP(apad.MGF1(hashes.SHA256()),hashes.SHA256(),None))

def rsa_dec(ct, priv):
    return serialization.load_pem_private_key(priv.encode(),None,default_backend()).decrypt(
        ct,apad.OAEP(apad.MGF1(hashes.SHA256()),hashes.SHA256(),None))

def rsa_sign(msg, priv):
    k=serialization.load_pem_private_key(priv.encode(),None,default_backend())
    return k.sign(msg,rsapad.PSS(rsapad.MGF1(hashes.SHA256()),rsapad.PSS.MAX_LENGTH),hashes.SHA256())

def rsa_verify(msg, sig, pub):
    k=serialization.load_pem_public_key(pub.encode(),default_backend())
    try: k.verify(sig,msg,rsapad.PSS(rsapad.MGF1(hashes.SHA256()),rsapad.PSS.MAX_LENGTH),hashes.SHA256()); return True
    except InvalidSignature: return False

def ec_keygen(curve="P-256"):
    curves={"P-256":ec.SECP256R1(),"P-384":ec.SECP384R1(),"P-521":ec.SECP521R1()}
    pk=ec.generate_private_key(curves[curve],default_backend())
    return (pk.private_bytes(serialization.Encoding.PEM,serialization.PrivateFormat.PKCS8,serialization.NoEncryption()).decode(),
            pk.public_key().public_bytes(serialization.Encoding.PEM,serialization.PublicFormat.SubjectPublicKeyInfo).decode())

def ed25519_keygen():
    pk=Ed25519PrivateKey.generate()
    return (pk.private_bytes(serialization.Encoding.PEM,serialization.PrivateFormat.PKCS8,serialization.NoEncryption()).decode(),
            pk.public_key().public_bytes(serialization.Encoding.PEM,serialization.PublicFormat.SubjectPublicKeyInfo).decode())

def hash_text(text, algo):
    algos={"MD5":hashlib.md5,"SHA-1":hashlib.sha1,"SHA-256":hashlib.sha256,
           "SHA-384":hashlib.sha384,"SHA-512":hashlib.sha512,"SHA3-256":hashlib.sha3_256,
           "SHA3-512":hashlib.sha3_512,"BLAKE2b":lambda d:hashlib.blake2b(d,digest_size=64),
           "BLAKE2s":lambda d:hashlib.blake2s(d,digest_size=32)}
    return algos[algo](text.encode()).hexdigest()

def hmac_sign(text, key, algo):
    algos={"SHA-256":hashlib.sha256,"SHA-512":hashlib.sha512,"SHA-1":hashlib.sha1,"MD5":hashlib.md5}
    return _hmac.new(key.encode(),text.encode(),algos[algo]).hexdigest()

def pw_strength(pw):
    score=0; tips=[]
    if len(pw)>=8: score+=1
    else: tips.append("Use at least 8 characters")
    if len(pw)>=16: score+=1
    if any(c.isupper() for c in pw): score+=1
    else: tips.append("Add uppercase letters")
    if any(c.islower() for c in pw): score+=1
    else: tips.append("Add lowercase letters")
    if any(c.isdigit() for c in pw): score+=1
    else: tips.append("Add numbers")
    if any(c in "!@#$%^&*()_+-=[]{}|;':\",./<>?" for c in pw): score+=1
    else: tips.append("Add special characters")
    if len(set(pw))/max(len(pw),1)>0.6: score+=1
    labels=["Very Weak","Weak","Fair","Good","Strong","Very Strong","Excellent"]
    colors=[RED,RED,AMB,AMB,GRN,GRN,GRN]
    idx=min(score,6)
    return labels[idx], colors[idx], score, tips

def gen_password(length, upper, lower, digits, symbols):
    pool=""
    if upper: pool+=string.ascii_uppercase
    if lower: pool+=string.ascii_lowercase
    if digits: pool+=string.digits
    if symbols: pool+="!@#$%^&*()_+-=[]{}|;:,.<>?"
    if not pool: pool=string.ascii_letters+string.digits
    return "".join(secrets.choice(pool) for _ in range(length))

def analyze_text(text):
    b=text.encode()
    freq={}
    for c in b: freq[c]=freq.get(c,0)+1
    entropy=0
    for v in freq.values():
        p=v/len(b); entropy-=p*__import__('math').log2(p)
    return {"length":len(text),"bytes":len(b),"entropy":round(entropy,3),"unique_bytes":len(freq),
            "printable":sum(1 for c in text if c.isprintable()),"b64_valid":_is_b64(text),"hex_valid":_is_hex(text)}

def _is_b64(t):
    try: base64.b64decode(t.strip()); return len(t.strip())%4==0
    except: return False

def _is_hex(t):
    try: bytes.fromhex(t.strip().replace(" ","")); return True
    except: return False

import string

CIPHER_MAP = {
    "AES-256-GCM":       (aes_gcm_enc, aes_gcm_dec,  "sym", "Recommended · authenticated"),
    "AES-256-CBC":       (aes_cbc_enc, aes_cbc_dec,  "sym", "Classic block cipher"),
    "AES-256-CTR":       (aes_ctr_enc, aes_ctr_dec,  "sym", "Stream mode, no padding"),
    "ChaCha20-Poly1305": (chacha_enc,  chacha_dec,   "sym", "Fast stream · authenticated"),
    "Fernet":            (fernet_enc,  fernet_dec,   "sym", "Safe high-level wrapper"),
    "Blowfish-CBC":      (blowfish_enc,blowfish_dec, "sym", "Legacy · 128-bit"),
    "3DES-CBC":          (tdes_enc,    tdes_dec,     "sym", "Legacy · Triple DES"),
    "RSA-OAEP":          (None,        None,         "asym","Asymmetric · keypair"),
    "XOR":               (xor_enc,     xor_enc,      "sym", "Obfuscation · not secure"),
    "Caesar":            (None,        None,         "classic","Shift cipher"),
    "Vigenère":          (None,        None,         "classic","Keyword cipher"),
}


def FR(parent, bg=None, **kw):
    return tk.Frame(parent, bg=bg or parent["bg"], **kw)

def LB(parent, text, s=10, w="normal", m=False, fg=FG, bg=None, **kw):
    return tk.Label(parent, text=text, font=F(s,w,m), fg=fg, bg=bg or parent["bg"], **kw)

def sep(parent, horizontal=True):
    if horizontal: return tk.Frame(parent, bg=BORD, height=1)
    return tk.Frame(parent, bg=BORD, width=1)

def txt_box(parent, h=6, mono=True, fg=FG, ro=False, placeholder=""):
    wrap = FR(parent, bg=SURF2, highlightthickness=1, highlightbackground=BORD)
    sb   = tk.Scrollbar(wrap, bg=SURF2, troughcolor=SURF2, activebackground=SURF3,
                        highlightthickness=0, bd=0, width=8)
    t    = tk.Text(wrap, font=F(10,m=mono), fg=fg, bg=SURF2, insertbackground=IND,
                   relief="flat", bd=0, highlightthickness=0, selectbackground=IND,
                   selectforeground=FG, wrap="word", yscrollcommand=sb.set, padx=12, pady=10)
    sb.config(command=t.yview)
    t.pack(side="left", fill="both", expand=True)
    sb.pack(side="right", fill="y")
    if ro: t.bind("<Key>", lambda e: "break")
    if placeholder:
        t.insert("1.0", placeholder); t.config(fg=FG3)
        def _focus_in(e):
            if t.get("1.0","end").strip()==placeholder: t.delete("1.0","end"); t.config(fg=FG)
        def _focus_out(e):
            if not t.get("1.0","end").strip(): t.insert("1.0",placeholder); t.config(fg=FG3)
        t.bind("<FocusIn>",  _focus_in)
        t.bind("<FocusOut>", _focus_out)
    def _on_focus(e): wrap.config(highlightbackground=IND)
    def _off_focus(e): wrap.config(highlightbackground=BORD)
    t.bind("<FocusIn>", _on_focus, add="+")
    t.bind("<FocusOut>",_off_focus, add="+")
    return wrap, t

def entry(parent, pw=False, placeholder="", width=None):
    wrap = FR(parent, bg=SURF2, highlightthickness=1, highlightbackground=BORD)
    kw = dict(font=F(10), fg=FG, bg=SURF2, insertbackground=IND,
              relief="flat", bd=0, highlightthickness=0,
              selectbackground=IND, selectforeground=FG)
    if width: kw["width"]=width
    if pw: kw["show"]="•"
    e = tk.Entry(wrap, **kw)
    e.pack(fill="x", padx=10, pady=8)
    if placeholder:
        e.insert(0,placeholder); e.config(fg=FG3)
        def _fi(ev):
            if e.get()==placeholder: e.delete(0,"end"); e.config(fg=FG, show="•" if pw else "")
        def _fo(ev):
            if not e.get(): e.insert(0,placeholder); e.config(fg=FG3, show="" if pw else "")
        e.bind("<FocusIn>",_fi); e.bind("<FocusOut>",_fo)
    e.bind("<FocusIn>",  lambda ev: wrap.config(highlightbackground=IND), add="+")
    e.bind("<FocusOut>", lambda ev: wrap.config(highlightbackground=BORD), add="+")
    return wrap, e

class Btn(tk.Frame):
    VARIANTS = {
        "primary": (IND, IND_H, "#fff"),
        "success": ("#16a34a","#15803d","#fff"),
        "danger":  ("#dc2626","#b91c1c","#fff"),
        "ghost":   (SURF2, SURF3, FG2),
        "outline": (SURF, SURF2, FG),
    }
    def __init__(self, parent, text, cmd, v="ghost", s="md", full=False, **kw):
        bg,bgh,fg = self.VARIANTS.get(v, self.VARIANTS["ghost"])
        px,py,fs  = {"sm":(10,4,9),"md":(14,7,10),"lg":(18,9,11)}.get(s,(14,7,10))
        super().__init__(parent, bg=bg, cursor="hand2",
                         highlightthickness=1, highlightbackground=bg, **kw)
        self._b, self._bh = bg, bgh
        self._l = tk.Label(self, text=text, bg=bg, fg=fg, font=F(fs,"bold"), padx=px, pady=py)
        self._l.pack(fill="x" if full else "none", expand=full)
        for w in (self, self._l):
            w.bind("<Enter>",    lambda e: self._h(True))
            w.bind("<Leave>",    lambda e: self._h(False))
            w.bind("<Button-1>", lambda e: cmd())
    def _h(self, on):
        c = self._bh if on else self._b
        self.config(bg=c, highlightbackground=c if on else BORD)
        self._l.config(bg=c)
    def set_text(self, t): self._l.config(text=t)

class RadioGroup(tk.Frame):
    def __init__(self, parent, options, var, cmd=None, **kw):
        super().__init__(parent, bg=kw.pop("bg", parent["bg"]))
        self._btns={}
        for val, lbl in options:
            b=tk.Label(self, text=lbl, font=F(9), cursor="hand2",
                       bg=SURF2, fg=FG2, padx=12, pady=5,
                       highlightthickness=1, highlightbackground=BORD)
            b.pack(side="left", padx=(0,4))
            b.bind("<Button-1>", lambda e,v=val: (var.set(v), cmd() if cmd else None, self._update(var)))
            self._btns[val]=b
        var.trace_add("write", lambda *_: self._update(var))
        self._update(var)
    def _update(self, var):
        for val,b in self._btns.items():
            if var.get()==val: b.config(bg=IND,fg="#fff",highlightbackground=IND)
            else:              b.config(bg=SURF2,fg=FG2,highlightbackground=BORD)

class Toast:
    def __init__(self, root):
        self._root=root; self._id=None
        self._f=FR(root, bg=SURF2, highlightthickness=1, highlightbackground=BORD)
        self._icon=LB(self._f,"",s=10,fg=GRN,bg=SURF2,padx=8)
        self._icon.pack(side="left")
        self._l=LB(self._f,"",s=9,fg=FG2,bg=SURF2,anchor="w",pady=8,padx=4)
        self._l.pack(side="left",fill="x",expand=True)
        self._cls=tk.Label(self._f,text="✕",font=F(9),fg=FG3,bg=SURF2,cursor="hand2",padx=10,pady=8)
        self._cls.pack(side="right")
        self._cls.bind("<Button-1>",lambda e:self._hide())
    def show(self, msg, kind="ok"):
        cfg={"ok":(GRN,GRN_BG,"✓"),"err":(RED,RED_BG,"✗"),"warn":(AMB,AMB_BG,"!"),"info":(BLU,BLU_BG,"i")}
        fg,bg,icon=cfg.get(kind,cfg["ok"])
        self._f.config(bg=bg,highlightbackground=fg)
        self._icon.config(text=icon,fg=fg,bg=bg)
        self._l.config(text=msg,fg=fg,bg=bg)
        self._cls.config(bg=bg,fg=fg)
        self._f.pack(fill="x",side="bottom")
        if self._id: self._root.after_cancel(self._id)
        self._id=self._root.after(6000,self._hide)
    def _hide(self): self._f.pack_forget()

class TabBar(tk.Frame):
    def __init__(self, parent, tabs, cmd, **kw):
        super().__init__(parent, bg=kw.pop("bg", SURF))
        self._btns={}; self._cmd=cmd; self._var=tk.StringVar(value=tabs[0][0])
        for key,lbl,icon in tabs:
            f=FR(self,bg=SURF)
            f.pack(side="left")
            b=tk.Label(f,text=f"{icon}  {lbl}",font=F(10),fg=FG3,bg=SURF,
                       cursor="hand2",padx=18,pady=12)
            b.pack()
            ind=FR(f,bg=SURF,height=2)
            ind.pack(fill="x")
            self._btns[key]=(b,ind,f)
            for w in (b,f): w.bind("<Button-1>",lambda e,k=key:self._select(k))
        self._select(tabs[0][0])
    def _select(self, key):
        self._var.set(key)
        for k,(b,ind,f) in self._btns.items():
            if k==key:
                b.config(fg=IND_L); ind.config(bg=IND)
                f.config(highlightthickness=0)
            else:
                b.config(fg=FG3); ind.config(bg=SURF)
        self._cmd(key)
    def get(self): return self._var.get()

class SectionHeader(tk.Frame):
    def __init__(self, parent, title, subtitle="", **kw):
        super().__init__(parent, bg=kw.pop("bg", parent["bg"]))
        LB(self,title,s=11,w="bold",fg=FG).pack(side="left")
        if subtitle:
            LB(self,f"  {subtitle}",s=9,fg=FG3).pack(side="left",pady=2)
        sep(self,False).pack(side="left",fill="y",padx=(10,0),pady=4)

class PasswordEntry(tk.Frame):
    def __init__(self, parent, label_text="Password", **kw):
        super().__init__(parent, bg=kw.pop("bg", parent["bg"]))
        LB(self,label_text,s=9,fg=FG2).pack(anchor="w",pady=(0,4))
        row=FR(self,bg=self["bg"])
        row.pack(fill="x")
        self._wrap=FR(row,bg=SURF2,highlightthickness=1,highlightbackground=BORD)
        self._wrap.pack(side="left",fill="x",expand=True)
        self._var=tk.StringVar()
        self._e=tk.Entry(self._wrap,textvariable=self._var,font=F(10,m=True),
                         fg=FG,bg=SURF2,insertbackground=IND,relief="flat",
                         bd=0,highlightthickness=0,show="•")
        self._e.pack(fill="x",padx=10,pady=8)
        self._show=False
        self._eye=tk.Label(row,text="👁",font=F(11),fg=FG3,bg=parent["bg"],cursor="hand2",padx=6)
        self._eye.pack(side="left")
        self._eye.bind("<Button-1>",self._toggle)
        self._e.bind("<FocusIn>",  lambda e:self._wrap.config(highlightbackground=IND))
        self._e.bind("<FocusOut>", lambda e:self._wrap.config(highlightbackground=BORD))
    def _toggle(self,e=None):
        self._show=not self._show
        self._e.config(show="" if self._show else "•")
        self._eye.config(fg=IND if self._show else FG3)
    def get(self): return self._var.get()
    def set(self, v): self._var.set(v)

class WrapFrame(tk.Frame):
    """Frame that wraps children onto new rows like CSS flex-wrap."""
    def __init__(self, parent, gap=4, **kw):
        super().__init__(parent, **kw)
        self._gap = gap
        self.bind("<Configure>", self._rewrap)
        self._children = []

    def add(self, widget):
        self._children.append(widget)

    def _rewrap(self, e=None):
        w = self.winfo_width()
        if w < 2:
            return
        x = y = 0
        row_h = 0
        for child in self._children:
            child.update_idletasks()
            cw = child.winfo_reqwidth()
            ch = child.winfo_reqheight()
            if x + cw > w and x > 0:
                x = 0
                y += row_h + self._gap
                row_h = 0
            child.place(x=x, y=y)
            x += cw + self._gap
            row_h = max(row_h, ch)
        total_h = y + row_h
        self.config(height=max(total_h, 1))


class AlgoSelector(tk.Frame):
    CATEGORIES = [
        ("Authenticated Encryption", IND, ["AES-256-GCM","ChaCha20-Poly1305","Fernet"]),
        ("Symmetric",               BLU, ["AES-256-CBC","AES-256-CTR"]),
        ("Legacy",                  AMB, ["Blowfish-CBC","3DES-CBC"]),
        ("Asymmetric",              PUR, ["RSA-OAEP"]),
        ("Classical",               FG3, ["XOR","Caesar","Vigenère"]),
    ]
    def __init__(self, parent, var, on_change, **kw):
        super().__init__(parent, bg=kw.pop("bg", parent["bg"]))
        self._var=var; self._on_change=on_change; self._cards={}
        for cat_name, color, names in self.CATEGORIES:
            cat_row=FR(self,bg=self["bg"])
            cat_row.pack(fill="x",pady=(8,2))
            tk.Label(cat_row,text=cat_name.upper(),font=F(7,"bold"),
                     fg=color,bg=self["bg"],anchor="w").pack(side="left",padx=2)
            wrap=WrapFrame(self,gap=4,bg=self["bg"])
            wrap.pack(fill="x",pady=(0,2))
            for name in names:
                _,_,_,desc=CIPHER_MAP[name]
                card=FR(wrap,bg=SURF2,highlightthickness=1,highlightbackground=BORD,
                        cursor="hand2")
                tk.Label(card,text=name,font=F(9,"bold"),fg=FG,bg=SURF2,
                         padx=10,pady=6).pack()
                tk.Label(card,text=desc,font=F(7),fg=FG3,bg=SURF2,
                         padx=10).pack(pady=(0,6))
                card.bind("<Button-1>",lambda e,n=name:self._pick(n))
                for w in card.winfo_children(): w.bind("<Button-1>",lambda e,n=name:self._pick(n))
                wrap.add(card)
                self._cards[name]=card
        var.trace_add("write",lambda *_:self._refresh())
        self._refresh()
    def _pick(self, name):
        self._var.set(name); self._on_change()
    def _refresh(self):
        sel=self._var.get()
        for name,card in self._cards.items():
            for _,color,names in self.CATEGORIES:
                if name in names: c=color; break
            if name==sel:
                card.config(bg=SURF3,highlightbackground=c)
                for w in card.winfo_children(): w.config(bg=SURF3)
            else:
                card.config(bg=SURF2,highlightbackground=BORD)
                for w in card.winfo_children(): w.config(bg=SURF2)


class CipherTab(tk.Frame):
    def __init__(self, parent, toast, **kw):
        super().__init__(parent, **kw)
        self._toast=toast
        self._algo=tk.StringVar(value="AES-256-GCM")
        self._fmt=tk.StringVar(value="base64")
        self._build()

    def _build(self):
        outer=FR(self,bg=BG)
        outer.pack(fill="both",expand=True)

        left=FR(outer,bg=SURF,width=300)
        left.pack(side="left",fill="y")
        left.pack_propagate(False)

        tk.Frame(outer,bg=BORD,width=1).pack(side="left",fill="y")

        right=FR(outer,bg=BG)
        right.pack(side="left",fill="both",expand=True)

        self._build_left(left)
        self._build_right(right)
        self._on_algo()

    def _build_left(self, parent):
        cv=tk.Canvas(parent,bg=SURF,highlightthickness=0,bd=0)
        sb=tk.Scrollbar(parent,orient="vertical",command=cv.yview,
                        bg=SURF,troughcolor=SURF,width=6,
                        activebackground=SURF3,highlightthickness=0,bd=0)
        cv.configure(yscrollcommand=sb.set)
        sb.pack(side="right",fill="y")
        cv.pack(side="left",fill="both",expand=True)
        inner=FR(cv,bg=SURF)
        win=cv.create_window((0,0),window=inner,anchor="nw")
        cv.bind("<Configure>",lambda e:cv.itemconfig(win,width=e.width))
        inner.bind("<Configure>",lambda e:cv.configure(scrollregion=cv.bbox("all")))
        def _scroll(e): cv.yview_scroll(int(-1*(e.delta/120)),"units")
        cv.bind_all("<MouseWheel>",_scroll)

        pad=dict(padx=16)

        LB(inner,"Algorithm",s=9,fg=FG2,bg=SURF).pack(anchor="w",pady=(16,6),**pad)
        self._algo_sel=AlgoSelector(inner,self._algo,self._on_algo,bg=SURF)
        self._algo_sel.pack(fill="x",padx=12,pady=(0,8))

        sep(inner).pack(fill="x",pady=8,**pad)

        self._pw_section=FR(inner,bg=SURF)
        self._pw_widget=PasswordEntry(self._pw_section,"Password")
        self._pw_widget.pack(fill="x",padx=16,pady=(0,4))
        self._pw_section.pack(fill="x")

        self._shift_section=FR(inner,bg=SURF)
        LB(self._shift_section,"Shift (1–25)",s=9,fg=FG2,bg=SURF).pack(anchor="w",padx=16,pady=(0,4))
        sw,self._shift=entry(self._shift_section,placeholder="13")
        sw.pack(fill="x",padx=16,pady=(0,8))

        self._rsa_section=FR(inner,bg=SURF)
        self._build_rsa_section(self._rsa_section)

        sep(inner).pack(fill="x",pady=8,**pad)

        LB(inner,"Output Format",s=9,fg=FG2,bg=SURF).pack(anchor="w",pady=(0,6),**pad)
        fmt_row=FR(inner,bg=SURF)
        fmt_row.pack(anchor="w",**pad,pady=(0,12))
        RadioGroup(fmt_row,[("base64","Base64"),("hex","Hex"),("raw","Raw")],
                   self._fmt,bg=SURF).pack()

        if hasattr(self, "_algo_pill"):
            self._on_algo()

    def _build_rsa_section(self, p):
        LB(p,"Key Size",s=9,fg=FG2,bg=SURF).pack(anchor="w",padx=16,pady=(0,4))
        self._rsa_bits=tk.IntVar(value=2048)
        br=FR(p,bg=SURF); br.pack(anchor="w",padx=16,pady=(0,8))
        for b in (1024,2048,4096):
            rb=tk.Radiobutton(br,text=f"{b}-bit",variable=self._rsa_bits,value=b,
                              bg=SURF,fg=FG2,activebackground=SURF,activeforeground=FG,
                              selectcolor=SURF2,font=F(9),cursor="hand2")
            rb.pack(side="left",padx=(0,10))
        Btn(p,"Generate Keypair",self._rsa_gen,v="primary",s="sm").pack(anchor="w",padx=16,pady=(0,6))
        Btn(p,"Load .pem File",self._rsa_load,v="ghost",s="sm").pack(anchor="w",padx=16,pady=(0,10))
        LB(p,"Public Key",s=8,fg=FG3,bg=SURF).pack(anchor="w",padx=16)
        pw,self._rsa_pub=txt_box(p,h=55,fg=FG2)
        pw.pack(fill="x",padx=16,pady=(2,8))
        pw.config(height=55)
        LB(p,"Private Key",s=8,fg=FG3,bg=SURF).pack(anchor="w",padx=16)
        prw,self._rsa_priv=txt_box(p,h=55,fg=FG2)
        prw.pack(fill="x",padx=16,pady=(2,12))
        prw.config(height=55)

    def _build_right(self, parent):
        top=FR(parent,bg=BG)
        top.pack(fill="both",expand=True,padx=20,pady=16)

        in_hdr=FR(top,bg=BG)
        in_hdr.pack(fill="x",pady=(0,6))
        LB(in_hdr,"Input",s=10,w="bold",fg=FG).pack(side="left")
        Btn(in_hdr,"Load File",self._load_file,v="ghost",s="sm").pack(side="right",padx=(4,0))
        Btn(in_hdr,"Clear",lambda:self._input.delete("1.0","end"),v="ghost",s="sm").pack(side="right")

        iw,self._input=txt_box(top,placeholder="Paste text or load a file...")
        iw.pack(fill="both",expand=True,pady=(0,10))

        mid=FR(top,bg=BG)
        mid.pack(fill="x",pady=(0,10))
        Btn(mid,"🔒  Encrypt",self._do_enc,v="primary",s="lg").pack(side="left",padx=(0,10))
        Btn(mid,"🔓  Decrypt",self._do_dec,v="success",s="lg").pack(side="left",padx=(0,20))
        sep(mid,False).pack(side="left",fill="y",pady=4)
        Btn(mid,"⇅  Swap",self._swap,v="ghost",s="md").pack(side="left",padx=(10,6))
        Btn(mid,"Save Output",self._save,v="ghost",s="md").pack(side="left")

        out_hdr=FR(top,bg=BG)
        out_hdr.pack(fill="x",pady=(0,6))
        LB(out_hdr,"Output",s=10,w="bold",fg=FG).pack(side="left")
        self._algo_pill=tk.Label(out_hdr,text="AES-256-GCM",font=F(8,"bold"),
                                  fg="#fff",bg=IND,padx=8,pady=2)
        self._algo_pill.pack(side="left",padx=8)
        Btn(out_hdr,"Copy",self._copy_out,v="ghost",s="sm").pack(side="right")

        ow,self._output=txt_box(top,fg=FG2,ro=True)
        ow.pack(fill="both",expand=True)

    def _on_algo(self):
        algo=self._algo.get()
        self._pw_section.pack_forget()
        self._shift_section.pack_forget()
        self._rsa_section.pack_forget()
        if algo=="Caesar":    self._shift_section.pack(fill="x")
        elif algo=="RSA-OAEP":self._rsa_section.pack(fill="x")
        else:                 self._pw_section.pack(fill="x")
        _,_,_,desc=CIPHER_MAP[algo]
        for _,color,names in AlgoSelector.CATEGORIES:
            if algo in names: c=color; break
        self._algo_pill.config(text=algo,bg=c)

    def _enc_out(self,data):
        f=self._fmt.get()
        if f=="base64": return base64.b64encode(data).decode()
        if f=="hex":    return data.hex()
        try: return data.decode()
        except: return base64.b64encode(data).decode()+"  [fell back to base64]"

    def _dec_in(self,text):
        t=text.strip(); f=self._fmt.get()
        if f=="base64": return base64.b64decode(t)
        if f=="hex":    return bytes.fromhex(t.replace(" ",""))
        return t.encode()

    def _get_in(self): 
        t=self._input.get("1.0","end").strip()
        return "" if t=="Paste text or load a file..." else t

    def _set_out(self,text):
        self._output.config(state="normal"); self._output.delete("1.0","end")
        self._output.insert("1.0",text); self._output.config(state="disabled")

    def _do_enc(self):
        inp=self._get_in(); algo=self._algo.get()
        if not inp: self._toast.show("Enter some input text.","warn"); return
        try:
            if algo=="Caesar":
                s=int(self._shift.get() or "13")
                self._set_out(caesar_enc(inp,s)); self._toast.show(f"Caesar encrypted (shift {s}).","ok"); return
            if algo=="Vigenère":
                pw=self._pw_widget.get()
                if not pw: self._toast.show("Enter a keyword.","warn"); return
                self._set_out(vigenere(inp,pw,True)); self._toast.show("Vigenère encrypted.","ok"); return
            if algo=="RSA-OAEP":
                pub=self._rsa_pub.get("1.0","end").strip()
                if not pub: self._toast.show("Paste or generate a public key.","warn"); return
                self._set_out(self._enc_out(rsa_enc(inp.encode(),pub)))
                self._toast.show("RSA-OAEP encrypted.","ok"); return
            pw=self._pw_widget.get()
            if not pw: self._toast.show("Enter a password.","warn"); return
            enc_fn=CIPHER_MAP[algo][0]
            self._set_out(self._enc_out(enc_fn(inp.encode(),pw)))
            self._toast.show(f"{algo} encrypted successfully.","ok")
        except Exception as e: self._toast.show(f"Encrypt error: {e}","err")

    def _do_dec(self):
        inp=self._get_in(); algo=self._algo.get()
        if not inp: self._toast.show("Enter some input text.","warn"); return
        try:
            if algo=="Caesar":
                s=int(self._shift.get() or "13")
                self._set_out(caesar_enc(inp,-s)); self._toast.show(f"Caesar decrypted (shift -{s}).","ok"); return
            if algo=="Vigenère":
                pw=self._pw_widget.get()
                if not pw: self._toast.show("Enter the keyword.","warn"); return
                self._set_out(vigenere(inp,pw,False)); self._toast.show("Vigenère decrypted.","ok"); return
            if algo=="RSA-OAEP":
                priv=self._rsa_priv.get("1.0","end").strip()
                if not priv: self._toast.show("Paste or generate a private key.","warn"); return
                self._set_out(rsa_dec(self._dec_in(inp),priv).decode(errors="replace"))
                self._toast.show("RSA-OAEP decrypted.","ok"); return
            pw=self._pw_widget.get()
            if not pw: self._toast.show("Enter the password.","warn"); return
            dec_fn=CIPHER_MAP[algo][1]
            self._set_out(dec_fn(self._dec_in(inp),pw).decode(errors="replace"))
            self._toast.show(f"{algo} decrypted successfully.","ok")
        except Exception as e: self._toast.show(f"Decrypt error: {e}","err")

    def _rsa_gen(self):
        try:
            priv,pub=rsa_keygen(self._rsa_bits.get())
            self._rsa_pub.delete("1.0","end"); self._rsa_pub.insert("1.0",pub)
            self._rsa_priv.delete("1.0","end"); self._rsa_priv.insert("1.0",priv)
            self._toast.show(f"{self._rsa_bits.get()}-bit RSA keypair generated.","ok")
        except Exception as e: self._toast.show(str(e),"err")

    def _rsa_load(self):
        p=filedialog.askopenfilename(filetypes=[("PEM","*.pem"),("All","*.*")])
        if not p: return
        d=open(p).read()
        if "PRIVATE" in d: self._rsa_priv.delete("1.0","end"); self._rsa_priv.insert("1.0",d); self._toast.show("Private key loaded.","ok")
        else: self._rsa_pub.delete("1.0","end"); self._rsa_pub.insert("1.0",d); self._toast.show("Public key loaded.","ok")

    def _load_file(self):
        p=filedialog.askopenfilename()
        if not p: return
        raw=open(p,"rb").read()
        try: text=raw.decode()
        except: text=base64.b64encode(raw).decode(); self._toast.show("Binary file loaded as Base64.","info")
        self._input.delete("1.0","end"); self._input.insert("1.0",text)
        self._toast.show(f"Loaded: {os.path.basename(p)}","ok")

    def _save(self):
        out=self._output.get("1.0","end").strip()
        if not out: self._toast.show("Nothing to save.","warn"); return
        p=filedialog.asksaveasfilename(defaultextension=".txt",filetypes=[("Text","*.txt"),("All","*.*")])
        if p: open(p,"w").write(out); self._toast.show(f"Saved → {os.path.basename(p)}","ok")

    def _copy_out(self):
        out=self._output.get("1.0","end").strip()
        self.clipboard_clear(); self.clipboard_append(out)
        self._toast.show("Copied to clipboard.","info")

    def _swap(self):
        inp=self._get_in(); out=self._output.get("1.0","end").strip()
        self._input.delete("1.0","end"); self._input.insert("1.0",out)
        self._set_out(inp); self._toast.show("Swapped.","info")


class HashTab(tk.Frame):
    ALGOS=["MD5","SHA-1","SHA-256","SHA-384","SHA-512","SHA3-256","SHA3-512","BLAKE2b","BLAKE2s"]
    def __init__(self, parent, toast, **kw):
        super().__init__(parent, **kw)
        self._toast=toast; self._build()

    def _build(self):
        p=FR(self,bg=BG); p.pack(fill="both",expand=True,padx=24,pady=20)

        row1=FR(p,bg=BG); row1.pack(fill="x",pady=(0,16))
        col1=FR(row1,bg=BG); col1.pack(side="left",fill="both",expand=True,padx=(0,16))
        col2=FR(row1,bg=BG,width=280); col2.pack(side="left",fill="y"); col2.pack_propagate(False)

        LB(col1,"Text to Hash",s=10,w="bold",fg=FG).pack(anchor="w",pady=(0,6))
        iw,self._hash_in=txt_box(col1,h=8,placeholder="Enter text to hash...")
        iw.pack(fill="both",expand=True)

        LB(col2,"Algorithm",s=10,w="bold",fg=FG).pack(anchor="w",pady=(0,6))
        self._hash_algo=tk.StringVar(value="SHA-256")
        for a in self.ALGOS:
            rb=tk.Radiobutton(col2,text=a,variable=self._hash_algo,value=a,
                              bg=BG,fg=FG2,activebackground=BG,activeforeground=FG,
                              selectcolor=SURF2,font=F(10),cursor="hand2")
            rb.pack(anchor="w",pady=2)

        Btn(p,"Hash Text",self._do_hash,v="primary",s="lg").pack(anchor="w",pady=(12,8))
        Btn(p,"Hash File",self._hash_file,v="ghost",s="md").pack(anchor="w",pady=(0,16))

        sep(p).pack(fill="x",pady=(0,16))

        LB(p,"HMAC Signing",s=10,w="bold",fg=FG).pack(anchor="w",pady=(0,8))
        hr=FR(p,bg=BG); hr.pack(fill="x",pady=(0,8))
        hc1=FR(hr,bg=BG); hc1.pack(side="left",fill="both",expand=True,padx=(0,12))
        hc2=FR(hr,bg=BG); hc2.pack(side="left",fill="both",expand=True)
        LB(hc1,"Message",s=9,fg=FG2).pack(anchor="w",pady=(0,4))
        mw,self._hmac_msg=txt_box(hc1,h=5)
        mw.pack(fill="both",expand=True)
        LB(hc2,"Secret Key",s=9,fg=FG2).pack(anchor="w",pady=(0,4))
        kw2,self._hmac_key=txt_box(hc2,h=5)
        kw2.pack(fill="both",expand=True)

        hmac_row=FR(p,bg=BG); hmac_row.pack(fill="x",pady=(8,0))
        LB(hmac_row,"Algorithm",s=9,fg=FG2).pack(side="left",padx=(0,8))
        self._hmac_algo=tk.StringVar(value="SHA-256")
        RadioGroup(hmac_row,[("SHA-256","SHA-256"),("SHA-512","SHA-512"),("SHA-1","SHA-1"),("MD5","MD5")],
                   self._hmac_algo,bg=BG).pack(side="left")
        Btn(p,"Sign with HMAC",self._do_hmac,v="primary",s="md").pack(anchor="w",pady=(8,16))

        sep(p).pack(fill="x",pady=(0,16))

        LB(p,"Results",s=10,w="bold",fg=FG).pack(anchor="w",pady=(0,8))
        rw,self._hash_out=txt_box(p,h=8,fg=IND_L,ro=True)
        rw.pack(fill="x")
        Btn(p,"Copy Result",self._copy,v="ghost",s="sm").pack(anchor="w",pady=(6,0))

    def _do_hash(self):
        t=self._hash_in.get("1.0","end").strip()
        if not t or t=="Enter text to hash...": self._toast.show("Enter text.","warn"); return
        a=self._hash_algo.get()
        res=hash_text(t,a)
        self._set_out(f"Algorithm:  {a}\nInput len:  {len(t)} chars\n\n{res}")
        self._toast.show(f"{a} hash computed.","ok")

    def _hash_file(self):
        p=filedialog.askopenfilename()
        if not p: return
        raw=open(p,"rb").read()
        a=self._hash_algo.get()
        fns={"MD5":hashlib.md5,"SHA-1":hashlib.sha1,"SHA-256":hashlib.sha256,
             "SHA-384":hashlib.sha384,"SHA-512":hashlib.sha512,
             "SHA3-256":hashlib.sha3_256,"SHA3-512":hashlib.sha3_512,
             "BLAKE2b":lambda d:hashlib.blake2b(d,digest_size=64),
             "BLAKE2s":lambda d:hashlib.blake2s(d,digest_size=32)}
        h=fns[a](raw).hexdigest()
        self._set_out(f"File:       {os.path.basename(p)}\nSize:       {len(raw):,} bytes\nAlgorithm:  {a}\n\n{h}")
        self._toast.show(f"File hashed ({a}).","ok")

    def _do_hmac(self):
        msg=self._hmac_msg.get("1.0","end").strip()
        key=self._hmac_key.get("1.0","end").strip()
        if not msg or not key: self._toast.show("Enter message and key.","warn"); return
        res=hmac_sign(msg,key,self._hmac_algo.get())
        self._set_out(f"HMAC-{self._hmac_algo.get()}\nKey len:    {len(key)} chars\nMsg len:    {len(msg)} chars\n\n{res}")
        self._toast.show("HMAC computed.","ok")

    def _set_out(self,t):
        self._hash_out.config(state="normal"); self._hash_out.delete("1.0","end")
        self._hash_out.insert("1.0",t); self._hash_out.config(state="disabled")

    def _copy(self):
        self.clipboard_clear(); self.clipboard_append(self._hash_out.get("1.0","end").strip())
        self._toast.show("Copied.","info")


class KeysTab(tk.Frame):
    def __init__(self, parent, toast, **kw):
        super().__init__(parent, **kw)
        self._toast=toast; self._build()

    def _build(self):
        p=FR(self,bg=BG); p.pack(fill="both",expand=True,padx=24,pady=20)

        top=FR(p,bg=BG); top.pack(fill="x",pady=(0,16))

        rsa_card=FR(top,bg=SURF,highlightthickness=1,highlightbackground=BORD)
        rsa_card.pack(side="left",fill="both",expand=True,padx=(0,12))
        self._build_rsa_card(rsa_card)

        ec_card=FR(top,bg=SURF,highlightthickness=1,highlightbackground=BORD)
        ec_card.pack(side="left",fill="both",expand=True)
        self._build_ec_card(ec_card)

        sep(p).pack(fill="x",pady=(0,16))

        sig_card=FR(p,bg=SURF,highlightthickness=1,highlightbackground=BORD)
        sig_card.pack(fill="x",pady=(0,16))
        self._build_sign_card(sig_card)

    def _build_rsa_card(self, p):
        LB(p,"RSA Key Generation",s=10,w="bold",fg=FG,bg=SURF).pack(anchor="w",padx=16,pady=(14,4))
        LB(p,"PKCS#8 format · OAEP encryption",s=8,fg=FG3,bg=SURF).pack(anchor="w",padx=16,pady=(0,10))
        sep(p).pack(fill="x")
        LB(p,"Key Size",s=9,fg=FG2,bg=SURF).pack(anchor="w",padx=16,pady=(10,4))
        self._rsa_bits=tk.IntVar(value=2048)
        br=FR(p,bg=SURF); br.pack(anchor="w",padx=16,pady=(0,10))
        for b in (1024,2048,4096):
            tk.Radiobutton(br,text=f"{b}-bit",variable=self._rsa_bits,value=b,
                           bg=SURF,fg=FG2,activebackground=SURF,selectcolor=SURF2,
                           font=F(9),cursor="hand2").pack(side="left",padx=(0,12))
        Btn(p,"Generate RSA Keypair",self._gen_rsa,v="primary",s="sm").pack(anchor="w",padx=16,pady=(0,10))
        Btn(p,"Save Keys…",self._save_rsa,v="ghost",s="sm").pack(anchor="w",padx=16,pady=(0,16))
        LB(p,"Public Key",s=8,fg=FG3,bg=SURF).pack(anchor="w",padx=16)
        pw,self._rsa_pub=txt_box(p,h=80,fg=CYN); pw.pack(fill="x",padx=16,pady=(2,8)); pw.config(height=80)
        LB(p,"Private Key",s=8,fg=FG3,bg=SURF).pack(anchor="w",padx=16)
        prw,self._rsa_priv=txt_box(p,h=80,fg=PUR); prw.pack(fill="x",padx=16,pady=(2,16)); prw.config(height=80)

    def _build_ec_card(self, p):
        LB(p,"EC & Ed25519 Keys",s=10,w="bold",fg=FG,bg=SURF).pack(anchor="w",padx=16,pady=(14,4))
        LB(p,"Elliptic curve · ECDH · signatures",s=8,fg=FG3,bg=SURF).pack(anchor="w",padx=16,pady=(0,10))
        sep(p).pack(fill="x")
        LB(p,"Curve",s=9,fg=FG2,bg=SURF).pack(anchor="w",padx=16,pady=(10,4))
        self._ec_curve=tk.StringVar(value="P-256")
        RadioGroup(p,[("P-256","P-256"),("P-384","P-384"),("P-521","P-521")],
                   self._ec_curve,bg=SURF).pack(anchor="w",padx=16,pady=(0,10))
        Btn(p,"Generate EC Keypair",self._gen_ec,v="primary",s="sm").pack(anchor="w",padx=16,pady=(0,6))
        Btn(p,"Generate Ed25519",self._gen_ed25519,v="ghost",s="sm").pack(anchor="w",padx=16,pady=(0,10))
        LB(p,"Public Key",s=8,fg=FG3,bg=SURF).pack(anchor="w",padx=16)
        pw,self._ec_pub=txt_box(p,h=80,fg=CYN); pw.pack(fill="x",padx=16,pady=(2,8)); pw.config(height=80)
        LB(p,"Private Key",s=8,fg=FG3,bg=SURF).pack(anchor="w",padx=16)
        prw,self._ec_priv=txt_box(p,h=80,fg=PUR); prw.pack(fill="x",padx=16,pady=(2,16)); prw.config(height=80)

    def _build_sign_card(self, p):
        LB(p,"RSA Sign & Verify",s=10,w="bold",fg=FG,bg=SURF).pack(anchor="w",padx=16,pady=(14,4))
        LB(p,"PSS padding · SHA-256",s=8,fg=FG3,bg=SURF).pack(anchor="w",padx=16,pady=(0,10))
        sep(p).pack(fill="x")
        inner=FR(p,bg=SURF); inner.pack(fill="x",padx=16,pady=12)
        c1=FR(inner,bg=SURF); c1.pack(side="left",fill="both",expand=True,padx=(0,12))
        c2=FR(inner,bg=SURF); c2.pack(side="left",fill="both",expand=True,padx=(0,12))
        c3=FR(inner,bg=SURF); c3.pack(side="left",fill="both",expand=True)
        LB(c1,"Message",s=9,fg=FG2,bg=SURF).pack(anchor="w",pady=(0,4))
        mw,self._sign_msg=txt_box(c1,h=80); mw.pack(fill="both",expand=True); mw.config(height=80)
        LB(c2,"Private Key (sign) / Public Key (verify)",s=9,fg=FG2,bg=SURF).pack(anchor="w",pady=(0,4))
        kw2,self._sign_key=txt_box(c2,h=80,fg=FG2); kw2.pack(fill="both",expand=True); kw2.config(height=80)
        LB(c3,"Signature (Base64)",s=9,fg=FG2,bg=SURF).pack(anchor="w",pady=(0,4))
        sw,self._sign_sig=txt_box(c3,h=80,fg=IND_L); sw.pack(fill="both",expand=True); sw.config(height=80)
        btn_row=FR(p,bg=SURF); btn_row.pack(anchor="w",padx=16,pady=(0,16))
        Btn(btn_row,"Sign",self._do_sign,v="primary",s="sm").pack(side="left",padx=(0,8))
        Btn(btn_row,"Verify",self._do_verify,v="ghost",s="sm").pack(side="left",padx=(0,8))
        self._verify_result=LB(btn_row,"",s=10,w="bold",fg=FG2,bg=SURF)
        self._verify_result.pack(side="left",padx=8)

    def _gen_rsa(self):
        try:
            priv,pub=rsa_keygen(self._rsa_bits.get())
            self._rsa_pub.delete("1.0","end"); self._rsa_pub.insert("1.0",pub)
            self._rsa_priv.delete("1.0","end"); self._rsa_priv.insert("1.0",priv)
            self._toast.show(f"{self._rsa_bits.get()}-bit RSA keypair generated.","ok")
        except Exception as e: self._toast.show(str(e),"err")

    def _save_rsa(self):
        priv=self._rsa_priv.get("1.0","end").strip()
        pub=self._rsa_pub.get("1.0","end").strip()
        if not priv and not pub: self._toast.show("Generate keys first.","warn"); return
        d=filedialog.askdirectory(title="Select folder to save keys")
        if not d: return
        if priv: open(os.path.join(d,"private_key.pem"),"w").write(priv)
        if pub:  open(os.path.join(d,"public_key.pem"),"w").write(pub)
        self._toast.show(f"Keys saved to {os.path.basename(d)}/","ok")

    def _gen_ec(self):
        try:
            priv,pub=ec_keygen(self._ec_curve.get())
            self._ec_pub.delete("1.0","end"); self._ec_pub.insert("1.0",pub)
            self._ec_priv.delete("1.0","end"); self._ec_priv.insert("1.0",priv)
            self._toast.show(f"EC {self._ec_curve.get()} keypair generated.","ok")
        except Exception as e: self._toast.show(str(e),"err")

    def _gen_ed25519(self):
        try:
            priv,pub=ed25519_keygen()
            self._ec_pub.delete("1.0","end"); self._ec_pub.insert("1.0",pub)
            self._ec_priv.delete("1.0","end"); self._ec_priv.insert("1.0",priv)
            self._toast.show("Ed25519 keypair generated.","ok")
        except Exception as e: self._toast.show(str(e),"err")

    def _do_sign(self):
        msg=self._sign_msg.get("1.0","end").strip()
        key=self._sign_key.get("1.0","end").strip()
        if not msg or not key: self._toast.show("Enter message and private key.","warn"); return
        try:
            sig=rsa_sign(msg.encode(),key)
            self._sign_sig.delete("1.0","end"); self._sign_sig.insert("1.0",base64.b64encode(sig).decode())
            self._toast.show("Message signed (PSS/SHA-256).","ok")
        except Exception as e: self._toast.show(str(e),"err")

    def _do_verify(self):
        msg=self._sign_msg.get("1.0","end").strip()
        key=self._sign_key.get("1.0","end").strip()
        sig_b64=self._sign_sig.get("1.0","end").strip()
        if not all([msg,key,sig_b64]): self._toast.show("Enter message, public key, and signature.","warn"); return
        try:
            ok=rsa_verify(msg.encode(),base64.b64decode(sig_b64),key)
            if ok:
                self._verify_result.config(text="✓  Valid",fg=GRN)
                self._toast.show("Signature is valid.","ok")
            else:
                self._verify_result.config(text="✗  Invalid",fg=RED)
                self._toast.show("Signature is invalid.","err")
        except Exception as e: self._toast.show(str(e),"err")


class PasswordTab(tk.Frame):
    def __init__(self, parent, toast, **kw):
        super().__init__(parent, **kw)
        self._toast=toast; self._build()

    def _build(self):
        cv=tk.Canvas(self,bg=BG,highlightthickness=0,bd=0)
        sb=tk.Scrollbar(self,orient="vertical",command=cv.yview,
                        bg=BG,troughcolor=BG,width=8,
                        activebackground=SURF3,highlightthickness=0,bd=0)
        cv.configure(yscrollcommand=sb.set)
        sb.pack(side="right",fill="y")
        cv.pack(side="left",fill="both",expand=True)
        p=FR(cv,bg=BG)
        win=cv.create_window((0,0),window=p,anchor="nw")
        cv.bind("<Configure>",lambda e:cv.itemconfig(win,width=e.width))
        p.bind("<Configure>",lambda e:cv.configure(scrollregion=cv.bbox("all")))
        def _scroll(e): cv.yview_scroll(int(-1*(e.delta/120)),"units")
        cv.bind_all("<MouseWheel>",_scroll)

        inner=FR(p,bg=BG); inner.pack(fill="x",padx=24,pady=20)

        top=FR(inner,bg=BG); top.pack(fill="x",pady=(0,16))

        gen_card=FR(top,bg=SURF,highlightthickness=1,highlightbackground=BORD)
        gen_card.pack(side="left",fill="both",expand=True,padx=(0,12))
        self._build_gen_card(gen_card)

        chk_card=FR(top,bg=SURF,highlightthickness=1,highlightbackground=BORD)
        chk_card.pack(side="left",fill="both",expand=True)
        self._build_check_card(chk_card)

        sep(inner).pack(fill="x",pady=(0,16))

        kdf_card=FR(inner,bg=SURF,highlightthickness=1,highlightbackground=BORD)
        kdf_card.pack(fill="x",pady=(0,20))
        self._build_kdf_card(kdf_card)

    def _build_gen_card(self, p):
        LB(p,"Password Generator",s=10,w="bold",fg=FG,bg=SURF).pack(anchor="w",padx=16,pady=(14,4))
        LB(p,"Cryptographically secure random generation",s=8,fg=FG3,bg=SURF).pack(anchor="w",padx=16,pady=(0,10))
        sep(p).pack(fill="x")
        i=FR(p,bg=SURF); i.pack(fill="x",padx=16,pady=12)

        LB(i,"Length",s=9,fg=FG2,bg=SURF).pack(anchor="w",pady=(0,4))
        self._len_var=tk.IntVar(value=24)
        lrow=FR(i,bg=SURF); lrow.pack(fill="x",pady=(0,10))
        self._len_scale=tk.Scale(lrow,from_=8,to=128,orient="horizontal",
                                  variable=self._len_var,bg=SURF,fg=FG,
                                  troughcolor=SURF2,activebackground=IND,
                                  highlightthickness=0,bd=0,sliderlength=18,
                                  showvalue=True,font=F(8))
        self._len_scale.pack(fill="x")

        self._use_upper=tk.BooleanVar(value=True)
        self._use_lower=tk.BooleanVar(value=True)
        self._use_digits=tk.BooleanVar(value=True)
        self._use_symbols=tk.BooleanVar(value=True)

        for var,lbl in ((self._use_upper,"Uppercase A–Z"),(self._use_lower,"Lowercase a–z"),
                         (self._use_digits,"Numbers 0–9"),(self._use_symbols,"Symbols !@#$…")):
            tk.Checkbutton(i,text=lbl,variable=var,bg=SURF,fg=FG2,
                           activebackground=SURF,selectcolor=SURF2,
                           font=F(9),cursor="hand2").pack(anchor="w",pady=2)

        Btn(i,"Generate Password",self._generate,v="primary",s="md").pack(anchor="w",pady=(10,6))

        LB(i,"Generated Password",s=9,fg=FG2,bg=SURF).pack(anchor="w",pady=(6,4))
        pw,self._gen_out=txt_box(i,h=50,mono=True,ro=True,fg=GRN)
        pw.pack(fill="x"); pw.config(height=50)
        Btn(i,"Copy",self._copy_gen,v="ghost",s="sm").pack(anchor="w",pady=(4,0))

    def _build_check_card(self, p):
        LB(p,"Password Strength",s=10,w="bold",fg=FG,bg=SURF).pack(anchor="w",padx=16,pady=(14,4))
        LB(p,"Real-time strength analysis",s=8,fg=FG3,bg=SURF).pack(anchor="w",padx=16,pady=(0,10))
        sep(p).pack(fill="x")
        i=FR(p,bg=SURF); i.pack(fill="x",padx=16,pady=12)

        LB(i,"Password",s=9,fg=FG2,bg=SURF).pack(anchor="w",pady=(0,4))
        self._pw_check=PasswordEntry(i,"")
        self._pw_check.pack(fill="x",pady=(0,12))
        self._pw_check._e.bind("<KeyRelease>",lambda e:self._check_pw())

        self._strength_label=LB(i,"",s=14,w="bold",fg=FG2,bg=SURF)
        self._strength_label.pack(anchor="w",pady=(0,4))

        self._bar_frame=FR(i,bg=SURF2,height=8,highlightthickness=1,highlightbackground=BORD)
        self._bar_frame.pack(fill="x",pady=(0,10))
        self._bar_fill=FR(self._bar_frame,bg=FG3,height=6)
        self._bar_fill.place(x=0,y=1,relwidth=0,height=6)

        self._tips_frame=FR(i,bg=SURF)
        self._tips_frame.pack(fill="x")

    def _build_kdf_card(self, p):
        LB(p,"Key Derivation (KDF)",s=10,w="bold",fg=FG,bg=SURF).pack(anchor="w",padx=16,pady=(14,4))
        LB(p,"Derive cryptographic keys from passwords · PBKDF2 or Scrypt",s=8,fg=FG3,bg=SURF).pack(anchor="w",padx=16,pady=(0,10))
        sep(p).pack(fill="x")
        inner=FR(p,bg=SURF); inner.pack(fill="x",padx=16,pady=12)

        c1=FR(inner,bg=SURF); c1.pack(side="left",fill="x",expand=True,padx=(0,12))
        c2=FR(inner,bg=SURF); c2.pack(side="left",fill="x",expand=True,padx=(0,12))
        c3=FR(inner,bg=SURF); c3.pack(side="left",fill="x",expand=True)

        LB(c1,"Password",s=9,fg=FG2,bg=SURF).pack(anchor="w",pady=(0,4))
        self._kdf_pw=PasswordEntry(c1,"")
        self._kdf_pw.pack(fill="x")

        LB(c2,"KDF Algorithm",s=9,fg=FG2,bg=SURF).pack(anchor="w",pady=(0,4))
        self._kdf_algo=tk.StringVar(value="PBKDF2")
        RadioGroup(c2,[("PBKDF2","PBKDF2-SHA256"),("Scrypt","Scrypt")],
                   self._kdf_algo,bg=SURF).pack(anchor="w")

        LB(c3,"Key Length (bytes)",s=9,fg=FG2,bg=SURF).pack(anchor="w",pady=(0,4))
        self._kdf_len=tk.StringVar(value="32")
        RadioGroup(c3,[("16","16"),("32","32"),("64","64")],
                   self._kdf_len,bg=SURF).pack(anchor="w")

        Btn(p,"Derive Key",self._derive,v="primary",s="sm").pack(anchor="w",padx=16,pady=(0,8))
        LB(p,"Derived Key (hex)",s=9,fg=FG2,bg=SURF).pack(anchor="w",padx=16,pady=(0,4))
        kw2,self._kdf_out=txt_box(p,h=40,mono=True,fg=IND_L,ro=True)
        kw2.pack(fill="x",padx=16,pady=(0,16)); kw2.config(height=40)

    def _generate(self):
        try:
            pw=gen_password(self._len_var.get(),self._use_upper.get(),
                           self._use_lower.get(),self._use_digits.get(),self._use_symbols.get())
            self._gen_out.config(state="normal"); self._gen_out.delete("1.0","end")
            self._gen_out.insert("1.0",pw); self._gen_out.config(state="disabled")
            self._toast.show(f"{len(pw)}-char password generated.","ok")
        except Exception as e: self._toast.show(str(e),"err")

    def _copy_gen(self):
        pw=self._gen_out.get("1.0","end").strip()
        if pw: self.clipboard_clear(); self.clipboard_append(pw); self._toast.show("Copied.","info")

    def _check_pw(self):
        pw=self._pw_check.get()
        if not pw:
            self._strength_label.config(text=""); self._bar_fill.place(relwidth=0); return
        label,color,score,tips=pw_strength(pw)
        self._strength_label.config(text=label,fg=color)
        self._bar_fill.place(relwidth=min(score/7,1),height=6)
        self._bar_fill.config(bg=color)
        for w in self._tips_frame.winfo_children(): w.destroy()
        for tip in tips:
            LB(self._tips_frame,f"→  {tip}",s=8,fg=AMB,bg=SURF,anchor="w").pack(fill="x",pady=1)

    def _derive(self):
        pw=self._kdf_pw.get()
        if not pw: self._toast.show("Enter a password.","warn"); return
        try:
            n=int(self._kdf_len.get())
            salt=secrets.token_bytes(16)
            if self._kdf_algo.get()=="PBKDF2": k=pbkdf2(pw,salt,n)
            else: k=scrypt_kdf(pw,salt,n)
            result=f"Algorithm:  {self._kdf_algo.get()}\nKey length: {n} bytes\nSalt:       {salt.hex()}\n\nKey:        {k.hex()}"
            self._kdf_out.config(state="normal"); self._kdf_out.delete("1.0","end")
            self._kdf_out.insert("1.0",result); self._kdf_out.config(state="disabled")
            self._toast.show("Key derived.","ok")
        except Exception as e: self._toast.show(str(e),"err")


class AnalyzerTab(tk.Frame):
    def __init__(self, parent, toast, **kw):
        super().__init__(parent, **kw)
        self._toast=toast; self._build()

    def _build(self):
        p=FR(self,bg=BG); p.pack(fill="both",expand=True,padx=24,pady=20)

        LB(p,"Text / Data Analyzer",s=11,w="bold",fg=FG).pack(anchor="w",pady=(0,4))
        LB(p,"Detect encoding, measure entropy, inspect ciphertext structure",s=9,fg=FG3).pack(anchor="w",pady=(0,16))

        top=FR(p,bg=BG); top.pack(fill="x",pady=(0,12))
        LB(top,"Input",s=10,w="bold",fg=FG).pack(side="left",pady=(0,4))
        Btn(top,"Analyze",self._analyze,v="primary",s="sm").pack(side="right")
        Btn(top,"Clear",lambda:self._in.delete("1.0","end"),v="ghost",s="sm").pack(side="right",padx=(0,8))

        iw,self._in=txt_box(p,h=8,placeholder="Paste any text, hash, ciphertext, or encoded data...")
        iw.pack(fill="x",pady=(0,16))

        sep(p).pack(fill="x",pady=(0,16))

        self._stats_frame=FR(p,bg=BG); self._stats_frame.pack(fill="x",pady=(0,16))
        self._build_stat_grid()

        sep(p).pack(fill="x",pady=(0,16))

        LB(p,"Format Detection",s=10,w="bold",fg=FG).pack(anchor="w",pady=(0,8))
        self._fmt_frame=FR(p,bg=BG); self._fmt_frame.pack(fill="x",pady=(0,16))

        sep(p).pack(fill="x",pady=(0,16))

        LB(p,"Base64 Decode Preview",s=10,w="bold",fg=FG).pack(anchor="w",pady=(0,8))
        pw,self._preview=txt_box(p,h=6,fg=FG2,ro=True)
        pw.pack(fill="x")

    def _build_stat_grid(self):
        LB(self._stats_frame,"Statistics",s=10,w="bold",fg=FG).pack(anchor="w",pady=(0,10))
        grid=FR(self._stats_frame,bg=BG); grid.pack(fill="x")
        self._stat_cards={}
        stats=[("Characters","—"),("Bytes","—"),("Entropy","—"),("Unique Bytes","—"),("Printable","—")]
        for i,(name,val) in enumerate(stats):
            card=FR(grid,bg=SURF,highlightthickness=1,highlightbackground=BORD)
            card.grid(row=0,column=i,padx=(0,8),pady=4,sticky="nsew")
            grid.columnconfigure(i,weight=1)
            LB(card,name,s=8,fg=FG3,bg=SURF).pack(pady=(10,2))
            v=LB(card,"—",s=16,w="bold",fg=IND_L,bg=SURF); v.pack(pady=(0,10))
            self._stat_cards[name]=v

    def _analyze(self):
        t=self._in.get("1.0","end").strip()
        if not t or t=="Paste any text, hash, ciphertext, or encoded data...":
            self._toast.show("Enter some text.","warn"); return
        a=analyze_text(t)
        self._stat_cards["Characters"].config(text=f"{a['length']:,}")
        self._stat_cards["Bytes"].config(text=f"{a['bytes']:,}")
        self._stat_cards["Entropy"].config(text=f"{a['entropy']}")
        self._stat_cards["Unique Bytes"].config(text=f"{a['unique_bytes']}")
        self._stat_cards["Printable"].config(text=f"{a['printable']:,}")

        for w in self._fmt_frame.winfo_children(): w.destroy()
        detections=[]
        if a["b64_valid"]:     detections.append(("Base64",GRN,"Valid Base64 encoding"))
        if a["hex_valid"]:     detections.append(("Hex",BLU,"Valid hex string"))
        if len(t)==32:         detections.append(("MD5",AMB,"Length matches MD5 hash"))
        if len(t)==40:         detections.append(("SHA-1",AMB,"Length matches SHA-1 hash"))
        if len(t)==64:         detections.append(("SHA-256",IND,"Length matches SHA-256 hash"))
        if len(t)==128:        detections.append(("SHA-512",IND,"Length matches SHA-512 hash"))
        if t.startswith("-----BEGIN"): detections.append(("PEM",PUR,"PEM key or certificate"))
        if t.startswith("gAAAAA"):    detections.append(("Fernet",GRN,"Looks like Fernet token"))
        if not detections:     detections.append(("Unknown",FG3,"No specific format detected"))

        for item in detections:
            tag,color,desc=item
            row=FR(self._fmt_frame,bg=SURF,highlightthickness=1,highlightbackground=BORD)
            row.pack(fill="x",pady=3)
            tk.Label(row,text=tag,font=F(9,"bold"),fg="#fff",bg=color if color not in (FG3,"—") else SURF3,
                     padx=10,pady=6).pack(side="left")
            LB(row,desc,s=9,fg=FG2,bg=SURF,padx=12).pack(side="left")

        self._preview.config(state="normal"); self._preview.delete("1.0","end")
        if a["b64_valid"]:
            try:
                decoded=base64.b64decode(t)
                try: self._preview.insert("1.0",decoded.decode())
                except: self._preview.insert("1.0",decoded.hex())
            except: self._preview.insert("1.0","(decode failed)")
        else:
            self._preview.insert("1.0","(input is not valid Base64)")
        self._preview.config(state="disabled")
        self._toast.show("Analysis complete.","ok")


class App(tk.Tk):
    def __init__(self):
        super().__init__()
        self.title("Cryptool")
        self.configure(bg=BG)
        self.minsize(1100,700)
        self._build()
        w,h=1280,840
        self.geometry(f"{w}x{h}+{(self.winfo_screenwidth()-w)//2}+{(self.winfo_screenheight()-h)//2}")

    def _build(self):
        self._build_navbar()
        self._content=FR(self,bg=BG)
        self._content.pack(fill="both",expand=True)
        self._toast=Toast(self)

        tabs=[
            ("cipher","Cipher","🔒"),
            ("hash","Hash","#"),
            ("keys","Keys","🔑"),
            ("password","Password","★"),
            ("analyzer","Analyzer","⚡"),
        ]
        self._tabs={}
        builders={"cipher":CipherTab,"hash":HashTab,"keys":KeysTab,
                  "password":PasswordTab,"analyzer":AnalyzerTab}
        for key,_,_ in tabs:
            t=builders[key](self._content,self._toast,bg=BG)
            self._tabs[key]=t

        self._tabbar=TabBar(self,tabs,self._switch_tab,bg=SURF)
        self._tabbar.pack(fill="x",before=self._content)
        sep(self,True).pack(fill="x",before=self._content)

        self._switch_tab("cipher")

    def _build_navbar(self):
        nav=FR(self,bg=SURF)
        nav.pack(fill="x")
        sep(self,True).pack(fill="x")
        inner=FR(nav,bg=SURF)
        inner.pack(fill="x",padx=20,pady=0)
        logo_row=FR(inner,bg=SURF); logo_row.pack(side="left",pady=12)
        dot=FR(logo_row,bg=IND,width=10,height=10); dot.pack(side="left",padx=(0,10)); dot.pack_propagate(False)
        LB(logo_row,"Cryptool",s=13,w="bold",fg=FG,bg=SURF).pack(side="left")
        LB(logo_row,"v3",s=9,fg=FG3,bg=SURF).pack(side="left",padx=(4,16),pady=2)
        LB(inner,"Advanced Cryptography Suite",s=9,fg=FG3,bg=SURF).pack(side="left",pady=14)
        badges=FR(inner,bg=SURF); badges.pack(side="right",pady=14)
        for tag,color in [("AES",IND),("RSA",PUR),("ChaCha20",CYN),("HMAC",GRN),("KDF",AMB)]:
            tk.Label(badges,text=tag,font=F(8,"bold"),fg=color,bg=SURF2,
                     padx=8,pady=3).pack(side="left",padx=3)

    def _switch_tab(self, key):
        for k,t in self._tabs.items():
            if k==key: t.pack(fill="both",expand=True)
            else: t.pack_forget()


if __name__ == "__main__":
    app = App()
    app.mainloop()
