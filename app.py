import os
import socket
import io
import base64
import qrcode
from flask import Flask, request, jsonify, send_from_directory
from werkzeug.utils import secure_filename

# ── Config ─────────────────────────────────────────────────────────────────────

PORT       = 5000
BASE_DIR   = os.path.dirname(os.path.abspath(__file__))
UPLOAD_DIR = os.path.join(BASE_DIR, "shared_files")
os.makedirs(UPLOAD_DIR, exist_ok=True)

app = Flask(__name__)
app.config["MAX_CONTENT_LENGTH"] = 4 * 1024 * 1024 * 1024  # 4 GB

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

def make_qr(url):
    qr = qrcode.QRCode(version=1, box_size=7, border=2,
                       error_correction=qrcode.constants.ERROR_CORRECT_L)
    qr.add_data(url)
    qr.make(fit=True)
    img = qr.make_image(fill_color="black", back_color="white")
    buf = io.BytesIO()
    img.save(buf, format="PNG")
    return base64.b64encode(buf.getvalue()).decode()

# ── HTML ───────────────────────────────────────────────────────────────────────

PAGE = """<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8"/>
<meta name="viewport" content="width=device-width, initial-scale=1.0"/>
<title>AirShare</title>
<style>
@import url('https://fonts.googleapis.com/css2?family=DM+Mono:wght@400;500&family=Syne:wght@700&display=swap');
*,*::before,*::after{box-sizing:border-box;margin:0;padding:0}
:root{--bg:#0d0d0d;--s1:#161616;--s2:#1e1e1e;--br:#2a2a2a;--ac:#c8f135;--tx:#f0f0f0;--mu:#666;--er:#ff4f4f;--r:12px}
body{background:var(--bg);color:var(--tx);font-family:'DM Mono',monospace;min-height:100vh;padding:1.5rem;max-width:820px;margin:0 auto}
h1{font-family:'Syne',sans-serif;font-size:1.7rem;letter-spacing:-0.5px;margin-bottom:1.5rem;border-bottom:1px solid var(--br);padding-bottom:1rem}
h1 em{color:var(--ac);font-style:normal}
.grid{display:grid;grid-template-columns:1fr 1fr;gap:1rem;margin-bottom:1rem}
@media(max-width:560px){.grid{grid-template-columns:1fr}}
.card{background:var(--s1);border:1px solid var(--br);border-radius:var(--r);padding:1.1rem}
.lbl{font-size:10px;text-transform:uppercase;letter-spacing:1.2px;color:var(--mu);margin-bottom:.8rem}
.qr-box{background:#fff;border-radius:8px;padding:8px;display:flex;justify-content:center;margin-bottom:.7rem}
.qr-box img{width:154px;height:154px;display:block}
.chip{font-size:11px;background:var(--s2);border:1px solid var(--br);border-radius:6px;padding:6px 10px;color:var(--ac);text-align:center;cursor:pointer;word-break:break-all;transition:background .15s}
.chip:hover{background:#252a14}
.hint{font-size:10px;color:var(--mu);text-align:center;margin-top:5px}
.drop{border:1.5px dashed var(--br);border-radius:var(--r);padding:1.8rem 1rem;text-align:center;position:relative;cursor:pointer;transition:border-color .2s,background .2s}
.drop.over{border-color:var(--ac);background:#192008}
.drop input{position:absolute;inset:0;opacity:0;cursor:pointer;width:100%;height:100%}
.drop-ic{width:34px;height:34px;border:1.5px solid var(--br);border-radius:8px;display:flex;align-items:center;justify-content:center;margin:0 auto .6rem;font-size:17px}
.drop p{font-size:13px;color:var(--mu);line-height:1.5}
.drop p b{color:var(--tx)}
.pbar-wrap{margin-top:.8rem;background:var(--s2);border-radius:99px;height:5px;overflow:hidden;display:none}
.pbar{height:100%;background:var(--ac);border-radius:99px;width:0%;transition:width .15s}
.smsg{font-size:11px;margin-top:6px;color:var(--mu);text-align:center;min-height:14px}
.row{display:flex;justify-content:space-between;align-items:center;margin-bottom:.6rem}
.sec{font-size:12px;font-weight:500;color:var(--tx)}
.rbtn{font-size:10px;color:var(--mu);background:none;border:1px solid var(--br);border-radius:5px;padding:3px 8px;cursor:pointer;transition:color .15s,border-color .15s}
.rbtn:hover{color:var(--tx);border-color:var(--ac)}
#flist{display:flex;flex-direction:column;gap:5px}
.fi{display:flex;align-items:center;gap:9px;background:var(--s2);border:1px solid var(--br);border-radius:8px;padding:9px 11px}
.fic{width:28px;height:28px;background:var(--s1);border:1px solid var(--br);border-radius:6px;display:flex;align-items:center;justify-content:center;font-size:13px;flex-shrink:0}
.fnfo{flex:1;min-width:0}
.fn{font-size:12px;font-weight:500;white-space:nowrap;overflow:hidden;text-overflow:ellipsis}
.fm{font-size:10px;color:var(--mu);margin-top:1px}
.fa{display:flex;gap:5px;flex-shrink:0}
.bdl{font-size:11px;background:var(--ac);color:#0d0d0d;border:none;border-radius:5px;padding:5px 10px;cursor:pointer;font-weight:500;transition:background .15s}
.bdl:hover{background:#d4f84a}
.bde{font-size:11px;background:none;color:var(--mu);border:1px solid var(--br);border-radius:5px;padding:5px 8px;cursor:pointer;transition:color .15s,border-color .15s}
.bde:hover{color:var(--er);border-color:var(--er)}
.empty{text-align:center;padding:1.8rem;font-size:12px;color:var(--mu)}
.toast{position:fixed;bottom:1.2rem;right:1.2rem;background:var(--s1);border:1px solid var(--br);border-radius:8px;padding:9px 14px;font-size:11px;color:var(--tx);opacity:0;transform:translateY(6px);transition:opacity .2s,transform .2s;pointer-events:none;z-index:999}
.toast.on{opacity:1;transform:translateY(0)}
</style>
</head>
<body>
<h1>Air<em>Share</em></h1>
<div class="grid">
  <div class="card">
    <div class="lbl">Scan to connect</div>
    <div class="qr-box"><img src="data:image/png;base64,__QR__" alt="qr"/></div>
    <div class="chip" onclick="copyUrl()">__URL__</div>
    <div class="hint">tap to copy</div>
  </div>
  <div class="card">
    <div class="lbl">Share a file</div>
    <div class="drop" id="dz">
      <input type="file" id="fi" multiple/>
      <div class="drop-ic">+</div>
      <p><b>Click or drag</b> files here</p>
    </div>
    <div class="pbar-wrap" id="pw"><div class="pbar" id="pb"></div></div>
    <div class="smsg" id="sm"></div>
  </div>
</div>
<div class="card">
  <div class="row">
    <span class="sec">Shared files</span>
    <button class="rbtn" onclick="load()">refresh</button>
  </div>
  <div id="flist"><div class="empty">No files yet</div></div>
</div>
<div class="toast" id="toast"></div>
<script>
const dz=document.getElementById('dz'),fi=document.getElementById('fi'),
      pw=document.getElementById('pw'),pb=document.getElementById('pb'),
      sm=document.getElementById('sm');

function toast(msg){
  const t=document.getElementById('toast');
  t.textContent=msg; t.classList.add('on');
  clearTimeout(t._t); t._t=setTimeout(()=>t.classList.remove('on'),2200);
}

function copyUrl(){
  const url='__URL__';
  if(navigator.clipboard){navigator.clipboard.writeText(url).then(()=>toast('Copied!'));}
  else{const e=document.createElement('textarea');e.value=url;document.body.appendChild(e);e.select();document.execCommand('copy');document.body.removeChild(e);toast('Copied!');}
}

dz.addEventListener('dragover',e=>{e.preventDefault();dz.classList.add('over');});
dz.addEventListener('dragleave',()=>dz.classList.remove('over'));
dz.addEventListener('drop',e=>{e.preventDefault();dz.classList.remove('over');upload(e.dataTransfer.files);});
fi.addEventListener('change',()=>{upload(fi.files);fi.value='';});

function upload(files){
  if(!files.length)return;
  const fd=new FormData();
  for(const f of files)fd.append('files',f);
  pw.style.display='block';pb.style.width='0%';sm.textContent='Uploading...';
  const xhr=new XMLHttpRequest();
  xhr.open('POST','/upload');
  xhr.upload.onprogress=e=>{if(e.lengthComputable)pb.style.width=Math.round(e.loaded/e.total*100)+'%';};
  xhr.onload=()=>{
    if(xhr.status===200){sm.textContent='Done!';toast('Shared!');load();setTimeout(()=>{pw.style.display='none';sm.textContent='';},1500);}
    else{sm.textContent='Failed ('+xhr.status+')';}
  };
  xhr.onerror=()=>{sm.textContent='Check WiFi connection';};
  xhr.send(fd);
}

const IC={pdf:'📄',mp4:'🎬',mov:'🎬',mkv:'🎬',avi:'🎬',mp3:'🎵',wav:'🎵',flac:'🎵',
  zip:'📦',rar:'📦','7z':'📦',tar:'📦',gz:'📦',png:'🖼',jpg:'🖼',jpeg:'🖼',
  gif:'🖼',webp:'🖼',doc:'📝',docx:'📝',txt:'📝',md:'📝',
  py:'🐍',js:'📜',html:'🌐',json:'📋'};

function icon(n){return IC[n.split('.').pop().toLowerCase()]||'📁';}
function fsize(b){
  if(b<1024)return b+' B';
  if(b<1048576)return (b/1024).toFixed(1)+' KB';
  if(b<1073741824)return (b/1048576).toFixed(1)+' MB';
  return (b/1073741824).toFixed(2)+' GB';
}

function dlFile(name){
  const a=document.createElement('a');
  a.href='/download/'+encodeURIComponent(name);
  a.download=name;
  document.body.appendChild(a);
  a.click();
  document.body.removeChild(a);
}

function delFile(name){
  if(!confirm('Delete '+name+'?'))return;
  fetch('/delete/'+encodeURIComponent(name),{method:'DELETE'}).then(()=>{toast('Deleted');load();});
}

function load(){
  fetch('/files').then(r=>r.json()).then(data=>{
    const el=document.getElementById('flist');
    if(!data.length){el.innerHTML='<div class="empty">No files yet</div>';return;}
    el.innerHTML=data.map(f=>{
      const safe=f.name.replace(/\\\\/g,'\\\\\\\\').replace(/'/g,"\\\\'");
      return '<div class="fi"><div class="fic">'+icon(f.name)+'</div><div class="fnfo"><div class="fn" title="'+f.name+'">'+f.name+'</div><div class="fm">'+fsize(f.size)+'</div></div><div class="fa"><button class="bdl" onclick="dlFile(\\''+safe+'\\')">&#8595; get</button><button class="bde" onclick="delFile(\\''+safe+'\\')">&#10005;</button></div></div>';
    }).join('');
  }).catch(()=>{});
}

load();
setInterval(load,5000);
</script>
</body>
</html>"""

# ── Routes ─────────────────────────────────────────────────────────────────────

@app.route("/")
def index():
    ip  = get_lan_ip()
    url = f"http://{ip}:{PORT}"
    html = PAGE.replace("__QR__", make_qr(url)).replace("__URL__", url)
    return html

@app.route("/upload", methods=["POST"])
def upload():
    saved = []
    for f in request.files.getlist("files"):
        if f.filename:
            name = secure_filename(f.filename)
            f.save(os.path.join(UPLOAD_DIR, name))
            saved.append(name)
    return jsonify({"status": "ok", "saved": saved})

@app.route("/files")
def list_files():
    out = []
    for name in os.listdir(UPLOAD_DIR):
        path = os.path.join(UPLOAD_DIR, name)
        if os.path.isfile(path):
            out.append({"name": name, "size": os.path.getsize(path)})
    return jsonify(sorted(out, key=lambda x: x["name"].lower()))

@app.route("/download/<path:filename>")
def download(filename):
    name = secure_filename(filename)
    if not os.path.isfile(os.path.join(UPLOAD_DIR, name)):
        return jsonify({"error": "not found"}), 404
    return send_from_directory(UPLOAD_DIR, name, as_attachment=True)

@app.route("/delete/<path:filename>", methods=["DELETE"])
def delete(filename):
    name = secure_filename(filename)
    path = os.path.join(UPLOAD_DIR, name)
    if os.path.isfile(path):
        os.remove(path)
    return jsonify({"status": "ok"})

# ── Run ────────────────────────────────────────────────────────────────────────

if __name__ == "__main__":
    ip = get_lan_ip()
    print(f"""
  AirShare is running
  Open this on any device on the same WiFi:

    http://{ip}:{PORT}

  If device says unreachable, open firewall:
  Windows -> run as admin:
    netsh advfirewall firewall add rule name=AirShare dir=in action=allow protocol=TCP localport={PORT}
  Linux   -> sudo ufw allow {PORT}
  Mac     -> System Settings > Firewall > allow Python
""")
    app.run(host="0.0.0.0", port=PORT, threaded=True, debug=False)