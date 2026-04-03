import os
import io
import socket
import base64
import secrets
import hashlib
import time
import json
import zipfile
import argparse
from pathlib import Path
from functools import wraps

import qrcode
from flask import (
    Flask, request, jsonify, send_from_directory,
    redirect, url_for, make_response, abort
)
from werkzeug.utils import secure_filename

# ── Config ─────────────────────────────────────────────────────────────────────

PORT            = 5000
BASE_DIR        = Path(__file__).parent.resolve()
UPLOAD_DIR      = BASE_DIR / "shared_files"
CHUNKS_DIR      = BASE_DIR / ".chunks"
SESSION_TTL     = 8 * 3600          # 8 hours in seconds
CHUNK_SIZE_HINT = 5 * 1024 * 1024   # 5 MB (client-side hint only)

UPLOAD_DIR.mkdir(exist_ok=True)
CHUNKS_DIR.mkdir(exist_ok=True)

app = Flask(__name__)
app.config["MAX_CONTENT_LENGTH"] = None   # no hard limit — streaming writes handle memory

# ── Startup secrets ─────────────────────────────────────────────────────────────

SECRET_KEY  = secrets.token_hex(32)        # signs session tokens
SESSION_PIN = str(secrets.randbelow(900000) + 100000)   # 6-digit PIN, never 0XXXXX
SESSIONS    = {}   # token -> {expires, ip}

# ── Helpers ────────────────────────────────────────────────────────────────────

def get_lan_ip():
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.settimeout(1)
        s.connect(("8.8.8.8", 80))
        ip = s.getsockname()[0]
        s.close()
        return ip
    except Exception:
        pass
    try:
        for info in socket.getaddrinfo(socket.gethostname(), None):
            ip = info[4][0]
            if ":" not in ip and not ip.startswith("127."):
                return ip
    except Exception:
        pass
    return "127.0.0.1"

def make_qr(url: str) -> str:
    qr = qrcode.QRCode(version=1, box_size=7, border=2,
                       error_correction=qrcode.constants.ERROR_CORRECT_L)
    qr.add_data(url)
    qr.make(fit=True)
    img = qr.make_image(fill_color="#0d0d0d", back_color="#f5f0e8")
    buf = io.BytesIO()
    img.save(buf, format="PNG")
    return base64.b64encode(buf.getvalue()).decode()

def sign_token(raw: str) -> str:
    return hashlib.sha256(f"{raw}{SECRET_KEY}".encode()).hexdigest()[:16]

def create_session(ip: str) -> str:
    raw   = secrets.token_hex(16)
    token = f"{raw}.{sign_token(raw)}"
    SESSIONS[token] = {"expires": time.time() + SESSION_TTL, "ip": ip}
    return token

def validate_session(token: str) -> bool:
    if not token or token not in SESSIONS:
        return False
    sess = SESSIONS[token]
    if time.time() > sess["expires"]:
        del SESSIONS[token]
        return False
    return True

def purge_expired():
    now = time.time()
    expired = [t for t, s in SESSIONS.items() if now > s["expires"]]
    for t in expired:
        del SESSIONS[t]

# ── Auth decorator ─────────────────────────────────────────────────────────────

def require_auth(f):
    @wraps(f)
    def wrapper(*args, **kwargs):
        purge_expired()
        token = request.cookies.get("as_token") or request.args.get("token")
        if not validate_session(token):
            if request.path.startswith("/api") or request.method != "GET":
                return jsonify({"error": "unauthorized"}), 401
            return redirect(f"/login?next={request.path}")
        return f(*args, **kwargs)
    return wrapper

# ── File size helper ───────────────────────────────────────────────────────────

def fmt_size(b: int) -> str:
    for unit in ("B", "KB", "MB", "GB", "TB"):
        if b < 1024:
            return f"{b:.1f} {unit}" if unit != "B" else f"{b} B"
        b /= 1024
    return f"{b:.2f} PB"

# ── HTML: Login page ───────────────────────────────────────────────────────────

LOGIN_HTML = r"""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8"/>
<meta name="viewport" content="width=device-width,initial-scale=1"/>
<title>AirShare — Authenticate</title>
<style>
@import url('https://fonts.googleapis.com/css2?family=DM+Mono:wght@400;500&family=Syne:wght@700;800&display=swap');
*,*::before,*::after{box-sizing:border-box;margin:0;padding:0}
:root{
  --bg:#0d0d0d;--s1:#141414;--s2:#1c1c1c;--br:#272727;
  --ac:#c8f135;--ac2:#a8d620;--tx:#f0f0f0;--mu:#585858;
  --er:#ff5252;--r:14px;
}
body{
  background:var(--bg);color:var(--tx);
  font-family:'DM Mono',monospace;
  min-height:100vh;display:flex;align-items:center;justify-content:center;
  padding:1.5rem;
}
/* noise grain overlay */
body::before{
  content:'';position:fixed;inset:0;
  background-image:url("data:image/svg+xml,%3Csvg viewBox='0 0 200 200' xmlns='http://www.w3.org/2000/svg'%3E%3Cfilter id='n'%3E%3CfeTurbulence type='fractalNoise' baseFrequency='0.9' numOctaves='4' stitchTiles='stitch'/%3E%3C/filter%3E%3Crect width='100%25' height='100%25' filter='url(%23n)' opacity='0.04'/%3E%3C/svg%3E");
  pointer-events:none;z-index:0;opacity:.4;
}
.wrap{
  width:100%;max-width:420px;position:relative;z-index:1;
  animation:fadeUp .4s ease both;
}
@keyframes fadeUp{from{opacity:0;transform:translateY(18px)}to{opacity:1;transform:none}}
.logo{
  font-family:'Syne',sans-serif;font-size:2rem;font-weight:800;
  letter-spacing:-1px;margin-bottom:2rem;text-align:center;
}
.logo em{color:var(--ac);font-style:normal}
.card{
  background:var(--s1);border:1px solid var(--br);
  border-radius:var(--r);padding:1.8rem;margin-bottom:1rem;
}
.lbl{font-size:10px;text-transform:uppercase;letter-spacing:1.5px;color:var(--mu);margin-bottom:1rem}
/* PIN inputs */
.pin-row{display:flex;gap:8px;justify-content:center;margin-bottom:1.2rem}
.pin-row input{
  width:46px;height:56px;text-align:center;font-size:1.4rem;font-family:'DM Mono',monospace;
  background:var(--s2);border:1.5px solid var(--br);border-radius:9px;
  color:var(--tx);outline:none;transition:border-color .15s,background .15s;
  caret-color:var(--ac);
}
.pin-row input:focus{border-color:var(--ac);background:#161e04}
.pin-row input.filled{border-color:#3a4a1a;background:#111a04}
.pin-row input.err{border-color:var(--er)!important;animation:shake .3s ease}
@keyframes shake{0%,100%{transform:translateX(0)}25%{transform:translateX(-5px)}75%{transform:translateX(5px)}}
.btn{
  width:100%;padding:.85rem;background:var(--ac);color:#0d0d0d;
  border:none;border-radius:9px;font-family:'DM Mono',monospace;
  font-size:13px;font-weight:500;cursor:pointer;
  transition:background .15s,transform .1s;
}
.btn:hover{background:var(--ac2)}
.btn:active{transform:scale(.98)}
.btn:disabled{background:var(--br);color:var(--mu);cursor:not-allowed}
.errmsg{font-size:11px;color:var(--er);text-align:center;min-height:16px;margin-top:.6rem}
.divider{display:flex;align-items:center;gap:.8rem;margin:.2rem 0 1rem;color:var(--mu);font-size:10px;text-transform:uppercase;letter-spacing:1px}
.divider::before,.divider::after{content:'';flex:1;height:1px;background:var(--br)}
.hint{font-size:10px;color:var(--mu);text-align:center;margin-top:.5rem;line-height:1.6}
.qr-card{background:var(--s1);border:1px solid var(--br);border-radius:var(--r);padding:1.5rem;text-align:center}
.qr-frame{
  background:#f5f0e8;border-radius:10px;padding:10px;
  display:inline-block;margin:.8rem 0;
}
.qr-frame img{width:160px;height:160px;display:block}
</style>
</head>
<body>
<div class="wrap">
  <div class="logo">Air<em>Share</em></div>

  <div class="qr-card">
    <div class="lbl">Scan QR to auto-authenticate</div>
    <div class="qr-frame"><img src="data:image/png;base64,__QR__" alt="qr"/></div>
    <div class="hint">Scanning opens AirShare already signed in</div>
  </div>

  <div style="margin:1rem 0">
    <div class="divider">or enter PIN</div>
  </div>

  <div class="card">
    <div class="lbl">6-digit access PIN</div>
    <div class="pin-row" id="pinRow">
      <input maxlength="1" inputmode="numeric" pattern="[0-9]" autocomplete="off"/>
      <input maxlength="1" inputmode="numeric" pattern="[0-9]" autocomplete="off"/>
      <input maxlength="1" inputmode="numeric" pattern="[0-9]" autocomplete="off"/>
      <input maxlength="1" inputmode="numeric" pattern="[0-9]" autocomplete="off"/>
      <input maxlength="1" inputmode="numeric" pattern="[0-9]" autocomplete="off"/>
      <input maxlength="1" inputmode="numeric" pattern="[0-9]" autocomplete="off"/>
    </div>
    <button class="btn" id="submitBtn" disabled onclick="submitPin()">Unlock</button>
    <div class="errmsg" id="errMsg"></div>
    <div class="hint">PIN displayed in your terminal</div>
  </div>
</div>
<script>
const inputs = [...document.querySelectorAll('.pin-row input')];
const btn    = document.getElementById('submitBtn');
const err    = document.getElementById('errMsg');
const next   = new URLSearchParams(location.search).get('next') || '/';

inputs.forEach((inp, i) => {
  inp.addEventListener('input', e => {
    inp.value = inp.value.replace(/\D/g, '').slice(-1);
    inp.classList.toggle('filled', inp.value !== '');
    if (inp.value && i < inputs.length - 1) inputs[i+1].focus();
    btn.disabled = inputs.some(x => !x.value);
    err.textContent = '';
  });
  inp.addEventListener('keydown', e => {
    if (e.key === 'Backspace' && !inp.value && i > 0) inputs[i-1].focus();
    if (e.key === 'Enter' && !btn.disabled) submitPin();
  });
  inp.addEventListener('paste', e => {
    e.preventDefault();
    const digits = (e.clipboardData.getData('text').replace(/\D/g,'')).slice(0,6);
    digits.split('').forEach((d,j) => { if(inputs[j]){inputs[j].value=d;inputs[j].classList.add('filled');} });
    btn.disabled = inputs.some(x => !x.value);
    inputs[Math.min(digits.length, 5)].focus();
  });
});
inputs[0].focus();

async function submitPin() {
  const pin = inputs.map(x => x.value).join('');
  btn.disabled = true; btn.textContent = 'Checking…';
  try {
    const r = await fetch('/api/auth/pin', {
      method:'POST',
      headers:{'Content-Type':'application/json'},
      body: JSON.stringify({pin})
    });
    const d = await r.json();
    if (r.ok) {
      document.cookie = `as_token=${d.token};path=/;max-age=${8*3600};SameSite=Lax`;
      location.href = next;
    } else {
      inputs.forEach(x => x.classList.add('err'));
      setTimeout(()=>inputs.forEach(x=>x.classList.remove('err')),400);
      err.textContent = 'Incorrect PIN. Try again.';
      inputs.forEach(x=>{x.value='';x.classList.remove('filled');});
      inputs[0].focus();
      btn.textContent = 'Unlock'; btn.disabled = true;
    }
  } catch {
    err.textContent = 'Network error'; btn.textContent = 'Unlock'; btn.disabled = false;
  }
}
</script>
</body>
</html>"""

# ── HTML: Main app ─────────────────────────────────────────────────────────────

MAIN_HTML = r"""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8"/>
<meta name="viewport" content="width=device-width,initial-scale=1"/>
<title>AirShare</title>
<style>
@import url('https://fonts.googleapis.com/css2?family=DM+Mono:wght@400;500&family=Syne:wght@700;800&display=swap');
*,*::before,*::after{box-sizing:border-box;margin:0;padding:0}
:root{
  --bg:#0d0d0d;--s1:#141414;--s2:#1c1c1c;--s3:#222;--br:#272727;
  --ac:#c8f135;--ac2:#a8d620;--tx:#f0f0f0;--mu:#585858;
  --er:#ff5252;--r:14px;
}
body{
  background:var(--bg);color:var(--tx);font-family:'DM Mono',monospace;
  min-height:100vh;padding:1.5rem;max-width:900px;margin:0 auto;
  padding-bottom:6rem;
}
body::before{
  content:'';position:fixed;inset:0;
  background-image:url("data:image/svg+xml,%3Csvg viewBox='0 0 200 200' xmlns='http://www.w3.org/2000/svg'%3E%3Cfilter id='n'%3E%3CfeTurbulence type='fractalNoise' baseFrequency='0.9' numOctaves='4' stitchTiles='stitch'/%3E%3C/filter%3E%3Crect width='100%25' height='100%25' filter='url(%23n)' opacity='0.04'/%3E%3C/svg%3E");
  pointer-events:none;z-index:0;opacity:.35;
}
.page{position:relative;z-index:1}

/* ── Header ── */
header{display:flex;justify-content:space-between;align-items:center;margin-bottom:1.8rem;padding-bottom:1rem;border-bottom:1px solid var(--br)}
.logo{font-family:'Syne',sans-serif;font-size:1.6rem;font-weight:800;letter-spacing:-1px}
.logo em{color:var(--ac);font-style:normal}
.hdr-right{display:flex;align-items:center;gap:.8rem}
.badge{font-size:10px;background:var(--s2);border:1px solid var(--br);border-radius:99px;padding:4px 10px;color:var(--mu)}
.badge span{color:var(--ac)}
.logout{font-size:10px;background:none;border:1px solid var(--br);border-radius:6px;padding:5px 10px;color:var(--mu);cursor:pointer;transition:color .15s,border-color .15s}
.logout:hover{color:var(--er);border-color:var(--er)}

/* ── Top grid ── */
.top-grid{display:grid;grid-template-columns:1fr 1fr;gap:1rem;margin-bottom:1rem}
@media(max-width:580px){.top-grid{grid-template-columns:1fr}}
.card{background:var(--s1);border:1px solid var(--br);border-radius:var(--r);padding:1.3rem}
.lbl{font-size:10px;text-transform:uppercase;letter-spacing:1.5px;color:var(--mu);margin-bottom:.9rem}

/* ── QR card ── */
.qr-frame{background:#f5f0e8;border-radius:10px;padding:8px;display:inline-block;margin-bottom:.7rem}
.qr-frame img{width:150px;height:150px;display:block}
.url-chip{
  font-size:11px;background:var(--s2);border:1px solid var(--br);border-radius:7px;
  padding:7px 11px;color:var(--ac);cursor:pointer;word-break:break-all;
  transition:background .15s;text-align:center;
}
.url-chip:hover{background:#1a2208}
.hint{font-size:10px;color:var(--mu);text-align:center;margin-top:5px}

/* ── Drop zone ── */
.drop{
  border:1.5px dashed var(--br);border-radius:var(--r);
  padding:2rem 1rem;text-align:center;position:relative;
  cursor:pointer;transition:border-color .2s,background .2s;
  min-height:160px;display:flex;flex-direction:column;align-items:center;justify-content:center;gap:.5rem;
}
.drop.over{border-color:var(--ac);background:#0f1a03}
.drop input{position:absolute;inset:0;opacity:0;cursor:pointer;width:100%;height:100%}
.drop-ic{
  width:38px;height:38px;border:1.5px solid var(--br);border-radius:10px;
  display:flex;align-items:center;justify-content:center;font-size:18px;
  transition:border-color .2s;
}
.drop.over .drop-ic{border-color:var(--ac)}
.drop p{font-size:12px;color:var(--mu);line-height:1.6}
.drop p b{color:var(--tx)}

/* ── Upload queue ── */
#queue{display:flex;flex-direction:column;gap:6px;margin-top:.8rem}
.qi{
  display:flex;align-items:center;gap:9px;
  background:var(--s2);border:1px solid var(--br);border-radius:8px;padding:8px 11px;
  animation:slideIn .2s ease both;
}
@keyframes slideIn{from{opacity:0;transform:translateY(-6px)}to{opacity:1;transform:none}}
.qi-name{flex:1;font-size:11px;white-space:nowrap;overflow:hidden;text-overflow:ellipsis}
.qi-bar{flex:0 0 80px;height:4px;background:var(--br);border-radius:99px;overflow:hidden}
.qi-fill{height:100%;background:var(--ac);border-radius:99px;width:0%;transition:width .1s}
.qi-pct{font-size:10px;color:var(--mu);flex:0 0 32px;text-align:right}
.qi-done{color:var(--ac);font-size:12px}
.qi-err{color:var(--er);font-size:10px}

/* ── Files section ── */
.files-hdr{
  display:flex;align-items:center;gap:.6rem;
  margin-bottom:.7rem;flex-wrap:wrap;
}
.files-hdr .sec{font-family:'Syne',sans-serif;font-size:1rem;font-weight:700;flex:1}
.count-badge{font-size:10px;background:var(--s2);border:1px solid var(--br);border-radius:99px;padding:3px 9px;color:var(--mu)}
.rbtn{
  font-size:10px;color:var(--mu);background:none;border:1px solid var(--br);
  border-radius:6px;padding:4px 9px;cursor:pointer;
  transition:color .15s,border-color .15s;
}
.rbtn:hover{color:var(--tx);border-color:var(--ac)}

/* ── File list ── */
#flist{display:flex;flex-direction:column;gap:5px}
.fi{
  display:flex;align-items:center;gap:10px;
  background:var(--s1);border:1.5px solid var(--br);border-radius:10px;
  padding:10px 12px;cursor:grab;
  transition:border-color .15s,background .15s,transform .1s;
  animation:slideIn .2s ease both;
  user-select:none;
}
.fi:active{cursor:grabbing}
.fi.selected{border-color:var(--ac);background:#0f1a03}
.fi.dragging{opacity:.4;transform:scale(.98)}
.fi.drag-over{border-color:var(--ac);background:#0c1603}
.fi-cb{
  width:18px;height:18px;border:1.5px solid var(--br);border-radius:5px;
  display:flex;align-items:center;justify-content:center;flex-shrink:0;
  transition:border-color .15s,background .15s;cursor:pointer;
}
.fi.selected .fi-cb{border-color:var(--ac);background:var(--ac)}
.fi.selected .fi-cb::after{content:'✓';font-size:10px;color:#0d0d0d;font-weight:700}
.fic{
  width:30px;height:30px;background:var(--s2);border:1px solid var(--br);
  border-radius:7px;display:flex;align-items:center;justify-content:center;
  font-size:14px;flex-shrink:0;
}
.fnfo{flex:1;min-width:0}
.fn{font-size:12px;font-weight:500;white-space:nowrap;overflow:hidden;text-overflow:ellipsis}
.fm{font-size:10px;color:var(--mu);margin-top:2px}
.fa{display:flex;gap:5px;flex-shrink:0}
.bdl{
  font-size:11px;background:var(--ac);color:#0d0d0d;border:none;
  border-radius:6px;padding:5px 11px;cursor:pointer;font-weight:500;
  transition:background .15s;
}
.bdl:hover{background:var(--ac2)}
.bde{
  font-size:11px;background:none;color:var(--mu);border:1px solid var(--br);
  border-radius:6px;padding:5px 9px;cursor:pointer;
  transition:color .15s,border-color .15s;
}
.bde:hover{color:var(--er);border-color:var(--er)}
.empty{
  text-align:center;padding:2.5rem;font-size:12px;color:var(--mu);
  border:1.5px dashed var(--br);border-radius:var(--r);
}

/* ── Bulk action bar ── */
#bulkBar{
  position:fixed;bottom:1.5rem;left:50%;transform:translateX(-50%) translateY(80px);
  background:var(--s1);border:1px solid var(--br);border-radius:12px;
  padding:.8rem 1.2rem;display:flex;align-items:center;gap:.8rem;
  box-shadow:0 8px 32px rgba(0,0,0,.6);z-index:100;
  transition:transform .25s cubic-bezier(.34,1.56,.64,1),opacity .2s;
  opacity:0;pointer-events:none;white-space:nowrap;
}
#bulkBar.visible{transform:translateX(-50%) translateY(0);opacity:1;pointer-events:all}
.bcount{font-size:11px;color:var(--mu)}
.bcount span{color:var(--ac);font-weight:500}
.bbar-btn{
  font-size:11px;border-radius:7px;padding:6px 12px;cursor:pointer;
  border:none;font-family:'DM Mono',monospace;transition:background .15s;
}
.bbar-dl{background:var(--ac);color:#0d0d0d;font-weight:500}
.bbar-dl:hover{background:var(--ac2)}
.bbar-de{background:var(--s2);color:var(--er);border:1px solid var(--br)}
.bbar-de:hover{background:#1a0808;border-color:var(--er)}
.bbar-cl{background:none;color:var(--mu);border:1px solid var(--br)}
.bbar-cl:hover{color:var(--tx)}
.bulk-sep{width:1px;height:20px;background:var(--br)}

/* ── Toast ── */
.toast{
  position:fixed;bottom:1.2rem;right:1.2rem;
  background:var(--s1);border:1px solid var(--br);border-radius:9px;
  padding:9px 15px;font-size:11px;color:var(--tx);
  opacity:0;transform:translateY(8px);
  transition:opacity .2s,transform .2s;pointer-events:none;z-index:200;
}
.toast.on{opacity:1;transform:translateY(0)}

/* ── Select all row ── */
.sel-row{display:flex;align-items:center;gap:.5rem;margin-bottom:.5rem;padding:0 2px}
.sel-all-cb{
  width:16px;height:16px;border:1.5px solid var(--br);border-radius:4px;
  cursor:pointer;display:flex;align-items:center;justify-content:center;
  transition:border-color .15s,background .15s;flex-shrink:0;
}
.sel-all-cb.checked{border-color:var(--ac);background:var(--ac)}
.sel-all-cb.checked::after{content:'✓';font-size:9px;color:#0d0d0d;font-weight:700}
.sel-all-lbl{font-size:10px;color:var(--mu);cursor:pointer}
</style>
</head>
<body>
<div class="page">
<header>
  <div class="logo">Air<em>Share</em></div>
  <div class="hdr-right">
    <div class="badge">Session: <span id="sessionExpiry"></span></div>
    <button class="logout" onclick="logout()">Sign out</button>
  </div>
</header>

<div class="top-grid">
  <!-- QR -->
  <div class="card">
    <div class="lbl">Scan to connect (auto-authenticated)</div>
    <div class="qr-frame"><img src="data:image/png;base64,__QR__" alt="qr"/></div>
    <div class="url-chip" onclick="copyUrl()">__URL__</div>
    <div class="hint">tap to copy · others need PIN</div>
  </div>

  <!-- Upload -->
  <div class="card">
    <div class="lbl">Share files</div>
    <div class="drop" id="dz">
      <input type="file" id="fi" multiple/>
      <div class="drop-ic">＋</div>
      <p><b>Click or drag</b> files here<br>Chunked · resumable · unlimited size</p>
    </div>
    <div id="queue"></div>
  </div>
</div>

<!-- Files -->
<div class="card">
  <div class="files-hdr">
    <span class="sec">Shared files</span>
    <span class="count-badge" id="countBadge">0 files</span>
    <button class="rbtn" onclick="load()">↻ refresh</button>
  </div>
  <div class="sel-row" id="selRow" style="display:none">
    <div class="sel-all-cb" id="selAllCb" onclick="toggleSelectAll()"></div>
    <span class="sel-all-lbl" onclick="toggleSelectAll()">Select all</span>
  </div>
  <div id="flist"><div class="empty">No files yet — drop something above</div></div>
</div>
</div>

<!-- Bulk bar -->
<div id="bulkBar">
  <span class="bcount">Selected: <span id="selCount">0</span></span>
  <div class="bulk-sep"></div>
  <button class="bbar-btn bbar-dl" onclick="bulkDownload()">↓ Download each</button>
  <button class="bbar-btn bbar-de" onclick="bulkDelete()">✕ Delete</button>
  <button class="bbar-btn bbar-cl" onclick="clearSelection()">Cancel</button>
</div>

<div class="toast" id="toast"></div>

<script>
// ── State ───────────────────────────────────────────────────────────────────
let FILES = [];
let SELECTED = new Set();
let ORDER = JSON.parse(localStorage.getItem('as_order') || '[]');
let dragSrc = null;

// ── Session timer ────────────────────────────────────────────────────────────
(function(){
  const expiry = Date.now() + 8 * 3600 * 1000;
  function tick(){
    const left = Math.max(0, expiry - Date.now());
    const h = String(Math.floor(left/3600000)).padStart(2,'0');
    const m = String(Math.floor((left%3600000)/60000)).padStart(2,'0');
    document.getElementById('sessionExpiry').textContent = h+':'+m;
  }
  tick(); setInterval(tick, 30000);
})();

// ── Toast ────────────────────────────────────────────────────────────────────
function toast(msg) {
  const t = document.getElementById('toast');
  t.textContent = msg; t.classList.add('on');
  clearTimeout(t._t); t._t = setTimeout(()=>t.classList.remove('on'), 2400);
}

// ── Copy URL ─────────────────────────────────────────────────────────────────
function copyUrl() {
  const url = '__URL__';
  navigator.clipboard?.writeText(url).then(()=>toast('URL copied!')) ||
    (()=>{const e=document.createElement('textarea');e.value=url;document.body.appendChild(e);e.select();document.execCommand('copy');document.body.removeChild(e);toast('URL copied!');})();
}

// ── Logout ───────────────────────────────────────────────────────────────────
async function logout() {
  await fetch('/api/auth/logout', {method:'POST'});
  document.cookie = 'as_token=;path=/;max-age=0';
  location.href = '/login';
}

// ── Chunked upload ───────────────────────────────────────────────────────────
const CHUNK = 5 * 1024 * 1024; // 5 MB

function makeQueueItem(name) {
  const id = 'qi-' + Math.random().toString(36).slice(2);
  const el = document.createElement('div');
  el.className = 'qi'; el.id = id;
  el.innerHTML = `<span class="qi-name" title="${name}">${name}</span>
    <div class="qi-bar"><div class="qi-fill" id="${id}-fill"></div></div>
    <span class="qi-pct" id="${id}-pct">0%</span>`;
  document.getElementById('queue').appendChild(el);
  return id;
}

function updateQueueItem(id, pct, done, err) {
  const fill = document.getElementById(id+'-fill');
  const pctEl = document.getElementById(id+'-pct');
  const row   = document.getElementById(id);
  if (!fill) return;
  if (err) { pctEl.className='qi-err'; pctEl.textContent='✕'; return; }
  fill.style.width = pct + '%';
  if (done) {
    pctEl.className='qi-done'; pctEl.textContent='✓';
    setTimeout(()=>row?.remove(), 1800);
  } else {
    pctEl.textContent = pct + '%';
  }
}

async function uploadFile(file, qid) {
  const fileId = Math.random().toString(36).slice(2) + Date.now();
  const total  = Math.ceil(file.size / CHUNK) || 1;

  for (let i = 0; i < total; i++) {
    const blob  = file.slice(i * CHUNK, (i + 1) * CHUNK);
    const fd    = new FormData();
    fd.append('fileId',      fileId);
    fd.append('chunkIndex',  i);
    fd.append('totalChunks', total);
    fd.append('filename',    file.name);
    fd.append('chunk',       blob, file.name);

    let tries = 0;
    while (tries < 3) {
      try {
        const r = await fetch('/api/upload/chunk', {method:'POST', body:fd});
        if (!r.ok) throw new Error(r.status);
        break;
      } catch(e) {
        tries++;
        if (tries === 3) { updateQueueItem(qid, 0, false, true); return; }
        await new Promise(res => setTimeout(res, 800 * tries));
      }
    }
    updateQueueItem(qid, Math.round(((i+1)/total)*100), i+1===total, false);
  }
  toast(`✓ ${file.name} shared`);
  setTimeout(load, 400);
}

function upload(files) {
  for (const f of files) {
    const qid = makeQueueItem(f.name);
    uploadFile(f, qid);
  }
}

const dz = document.getElementById('dz');
const fi = document.getElementById('fi');
dz.addEventListener('dragover', e=>{e.preventDefault();dz.classList.add('over')});
dz.addEventListener('dragleave', ()=>dz.classList.remove('over'));
dz.addEventListener('drop', e=>{e.preventDefault();dz.classList.remove('over');upload(e.dataTransfer.files)});
fi.addEventListener('change', ()=>{upload(fi.files);fi.value=''});

// ── File icons ───────────────────────────────────────────────────────────────
const IC = {
  pdf:'📄',mp4:'🎬',mov:'🎬',mkv:'🎬',avi:'🎬',
  mp3:'🎵',wav:'🎵',flac:'🎵',aac:'🎵',
  zip:'📦',rar:'📦','7z':'📦',tar:'📦',gz:'📦',
  png:'🖼',jpg:'🖼',jpeg:'🖼',gif:'🖼',webp:'🖼',svg:'🖼',
  doc:'📝',docx:'📝',txt:'📝',md:'📝',
  py:'🐍',js:'📜',ts:'📜',html:'🌐',css:'🎨',json:'📋',
  xls:'📊',xlsx:'📊',csv:'📊',ppt:'📊',pptx:'📊',
};
const icon = n => IC[n.split('.').pop().toLowerCase()] || '📁';

function fsize(b) {
  const u = ['B','KB','MB','GB','TB'];
  let i=0; while(b>=1024&&i<u.length-1){b/=1024;i++}
  return (i===0?b:b.toFixed(1))+' '+u[i];
}

// ── Drag-to-reorder ──────────────────────────────────────────────────────────
function saveOrder() {
  ORDER = FILES.map(f=>f.name);
  localStorage.setItem('as_order', JSON.stringify(ORDER));
}

function applyOrder(files) {
  const idx = {};
  ORDER.forEach((n,i)=>idx[n]=i);
  return [...files].sort((a,b)=>{
    const ai = idx[a.name]??9999, bi = idx[b.name]??9999;
    return ai-bi || a.name.localeCompare(b.name);
  });
}

// ── Selection ────────────────────────────────────────────────────────────────
function toggleSelect(name) {
  if (SELECTED.has(name)) SELECTED.delete(name); else SELECTED.add(name);
  updateBulkBar();
  render();
}

function toggleSelectAll() {
  if (SELECTED.size === FILES.length) {
    SELECTED.clear();
  } else {
    FILES.forEach(f=>SELECTED.add(f.name));
  }
  updateBulkBar(); render();
}

function clearSelection() {
  SELECTED.clear(); updateBulkBar(); render();
}

function updateBulkBar() {
  const bar = document.getElementById('bulkBar');
  const n   = SELECTED.size;
  document.getElementById('selCount').textContent = n;
  bar.classList.toggle('visible', n > 0);
  const cb = document.getElementById('selAllCb');
  cb.classList.toggle('checked', n > 0 && n === FILES.length);
}

// ── Bulk actions ─────────────────────────────────────────────────────────────
function bulkDownload() {
  const names = [...SELECTED];
  names.forEach((name, i) => {
    setTimeout(() => {
      const a = document.createElement('a');
      a.href = '/api/download/' + encodeURIComponent(name);
      a.download = name; document.body.appendChild(a);
      a.click(); document.body.removeChild(a);
    }, i * 350);
  });
  toast(`Downloading ${names.length} file(s)…`);
}

async function bulkDelete() {
  const names = [...SELECTED];
  if (!confirm(`Delete ${names.length} file(s)? This cannot be undone.`)) return;
  await Promise.all(names.map(n =>
    fetch('/api/delete/'+encodeURIComponent(n), {method:'DELETE'})
  ));
  toast(`Deleted ${names.length} file(s)`);
  SELECTED.clear(); updateBulkBar(); load();
}

// ── Render ───────────────────────────────────────────────────────────────────
function render() {
  const el = document.getElementById('flist');
  const sr = document.getElementById('selRow');

  document.getElementById('countBadge').textContent =
    FILES.length + ' file' + (FILES.length!==1?'s':'');

  if (!FILES.length) {
    el.innerHTML = '<div class="empty">No files yet — drop something above</div>';
    sr.style.display = 'none'; return;
  }
  sr.style.display = 'flex';

  el.innerHTML = FILES.map(f => {
    const sel = SELECTED.has(f.name);
    const safe = f.name.replace(/\\/g,'\\\\').replace(/'/g,"\\'");
    return `<div class="fi${sel?' selected':''}"
        draggable="true"
        data-name="${f.name.replace(/"/g,'&quot;')}"
        onclick="toggleSelect('${safe}')"
        ondragstart="onDragStart(event,'${safe}')"
        ondragover="onDragOver(event)"
        ondragleave="onDragLeave(event)"
        ondrop="onDrop(event,'${safe}')">
      <div class="fi-cb"></div>
      <div class="fic">${icon(f.name)}</div>
      <div class="fnfo">
        <div class="fn" title="${f.name}">${f.name}</div>
        <div class="fm">${fsize(f.size)}</div>
      </div>
      <div class="fa" onclick="event.stopPropagation()">
        <button class="bdl" onclick="dlFile('${safe}')">↓ get</button>
        <button class="bde" onclick="delFile('${safe}')">✕</button>
      </div>
    </div>`;
  }).join('');
}

// ── Drag-to-reorder handlers ─────────────────────────────────────────────────
function onDragStart(e, name) {
  dragSrc = name;
  setTimeout(()=>{
    const el = document.querySelector(`[data-name="${name}"]`);
    el?.classList.add('dragging');
  },0);
}
function onDragOver(e) {
  e.preventDefault();
  e.currentTarget.classList.add('drag-over');
}
function onDragLeave(e) {
  e.currentTarget.classList.remove('drag-over');
}
function onDrop(e, targetName) {
  e.preventDefault();
  e.currentTarget.classList.remove('drag-over');
  if (dragSrc === targetName) return;
  const from = FILES.findIndex(f=>f.name===dragSrc);
  const to   = FILES.findIndex(f=>f.name===targetName);
  if (from<0||to<0) return;
  const [item] = FILES.splice(from,1);
  FILES.splice(to,0,item);
  saveOrder(); render();
}

// ── Individual actions ───────────────────────────────────────────────────────
function dlFile(name) {
  const a = document.createElement('a');
  a.href = '/api/download/'+encodeURIComponent(name);
  a.download = name; document.body.appendChild(a);
  a.click(); document.body.removeChild(a);
}

async function delFile(name) {
  if (!confirm('Delete '+name+'?')) return;
  await fetch('/api/delete/'+encodeURIComponent(name),{method:'DELETE'});
  toast('Deleted'); SELECTED.delete(name); updateBulkBar(); load();
}

// ── Load files ───────────────────────────────────────────────────────────────
async function load() {
  try {
    const r = await fetch('/api/files');
    if (r.status===401) { location.href='/login'; return; }
    const data = await r.json();
    FILES = applyOrder(data);
    // remove stale selections
    SELECTED.forEach(n=>{ if(!FILES.find(f=>f.name===n)) SELECTED.delete(n); });
    updateBulkBar(); render();
  } catch {}
}

load();
setInterval(load, 5000);
</script>
</body>
</html>"""

# ── Routes: Auth ───────────────────────────────────────────────────────────────

@app.route("/login")
def login_page():
    ip  = get_lan_ip()
    url = f"http://{ip}:{PORT}"
    # QR token auto-login URL
    token    = create_session("qr-device")
    qr_url   = f"{url}/?token={token}"
    qr_b64   = make_qr(qr_url)
    html = LOGIN_HTML.replace("__QR__", qr_b64).replace("__URL__", url)
    return html

@app.route("/api/auth/pin", methods=["POST"])
def auth_pin():
    data = request.get_json(silent=True) or {}
    if str(data.get("pin","")).strip() == SESSION_PIN:
        token = create_session(request.remote_addr)
        return jsonify({"status":"ok","token":token})
    return jsonify({"error":"invalid pin"}), 401

@app.route("/api/auth/logout", methods=["POST"])
def auth_logout():
    token = request.cookies.get("as_token")
    if token and token in SESSIONS:
        del SESSIONS[token]
    return jsonify({"status":"ok"})

# ── Routes: Main app ───────────────────────────────────────────────────────────

@app.route("/")
@require_auth
def index():
    ip    = get_lan_ip()
    url   = f"http://{ip}:{PORT}"
    qr_b64 = make_qr(url)
    html  = MAIN_HTML.replace("__QR__", qr_b64).replace("__URL__", url)
    resp  = make_response(html)
    # Bake token into cookie if it came via QR URL param
    token = request.args.get("token")
    if token and validate_session(token):
        resp.set_cookie("as_token", token, max_age=SESSION_TTL, samesite="Lax")
    return resp

# ── Routes: API (all require auth) ─────────────────────────────────────────────

@app.route("/api/upload/chunk", methods=["POST"])
@require_auth
def upload_chunk():
    file_id     = request.form.get("fileId","").strip()
    chunk_index = int(request.form.get("chunkIndex", 0))
    total       = int(request.form.get("totalChunks", 1))
    filename    = secure_filename(request.form.get("filename","upload"))
    chunk_data  = request.files.get("chunk")

    if not file_id or not chunk_data:
        return jsonify({"error":"missing data"}), 400

    # Save chunk
    chunk_dir = CHUNKS_DIR / file_id
    chunk_dir.mkdir(exist_ok=True)
    chunk_data.save(chunk_dir / f"{chunk_index:05d}")

    # Reassemble when all chunks received
    saved_chunks = list(chunk_dir.iterdir())
    if len(saved_chunks) >= total:
        dest = UPLOAD_DIR / filename
        with open(dest, "wb") as out:
            for i in range(total):
                chunk_path = chunk_dir / f"{i:05d}"
                with open(chunk_path, "rb") as c:
                    while True:
                        buf = c.read(1024 * 1024)
                        if not buf: break
                        out.write(buf)
        # Clean up chunks
        for p in chunk_dir.iterdir():
            p.unlink()
        chunk_dir.rmdir()
        return jsonify({"status":"complete","filename":filename})

    return jsonify({"status":"chunk_saved","index":chunk_index})

@app.route("/api/files")
@require_auth
def list_files():
    out = []
    for p in UPLOAD_DIR.iterdir():
        if p.is_file():
            out.append({"name":p.name,"size":p.stat().st_size})
    return jsonify(sorted(out, key=lambda x: x["name"].lower()))

@app.route("/api/download/<path:filename>")
@require_auth
def download(filename):
    name = secure_filename(filename)
    path = UPLOAD_DIR / name
    if not path.is_file():
        return jsonify({"error":"not found"}), 404
    return send_from_directory(UPLOAD_DIR, name, as_attachment=True, conditional=True)

@app.route("/api/delete/<path:filename>", methods=["DELETE"])
@require_auth
def delete_file(filename):
    name = secure_filename(filename)
    path = UPLOAD_DIR / name
    if path.is_file():
        path.unlink()
    return jsonify({"status":"ok"})

# ── Startup ────────────────────────────────────────────────────────────────────

if __name__ == "__main__":
    ip = get_lan_ip()
    print(f"""
╔══════════════════════════════════════════════╗
║              AirShare  ✦  Ready              ║
╠══════════════════════════════════════════════╣
║  URL  →  http://{ip}:{PORT:<27}║
║  PIN  →  {SESSION_PIN:<38}║
╠══════════════════════════════════════════════╣
║  Sessions expire after 8 hours               ║
║  PIN regenerates on every restart            ║
╠══════════════════════════════════════════════╣
║  Firewall (if devices can't connect):        ║
║  Windows: netsh advfirewall firewall add     ║
║    rule name=AirShare dir=in action=allow    ║
║    protocol=TCP localport={PORT}                  ║
║  Linux:   sudo ufw allow {PORT}                   ║
║  Mac:     System Settings > Firewall         ║
╚══════════════════════════════════════════════╝
""")
    app.run(host="0.0.0.0", port=PORT, threaded=True, debug=False)