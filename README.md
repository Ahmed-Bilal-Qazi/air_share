# AirShare

A lightweight, self-hosted file sharing app for local networks. Open it in a browser, scan a QR code or enter a PIN, and start transferring files instantly between any devices on the same Wi-Fi.

No accounts. No cloud. Just direct sharing over LAN.

---

## Quick Start — No Installation Required

A prebuilt portable executable is included in this repo:

```
airshare.exe
```

**Double-click it.** No Python, no pip, no setup. A console window opens showing:

```
║  URL  →  http://192.168.x.x:5000        ║
║  PIN  →  123456                          ║
```

Open the URL on any device on the same network, scan the QR or enter the PIN, and start sharing.

> **Firewall prompt:** Windows may ask to allow network access the first time — click Allow.

---

## Features

- QR-based instant access (auto-authenticated link)
- PIN authentication with 8-hour sessions
- Chunked parallel uploads — 8 threads × 32 MB chunks
- Parallel range-request downloads — 6 threads × 16 MB slices
- Resume-friendly transfers with automatic retry
- Drag-and-drop interface with upload progress and speed display
- Multi-file upload support
- Bulk download and delete
- Drag-to-reorder file list (order saved in browser)
- Mobile-aware download (native download manager on iOS/Android)
- Smart LAN IP detection (prefers 192.168.x.x, falls back gracefully)
- Production WSGI server via Waitress (32 threads) when available
- Local file storage — all data stays on the host machine

---

## Running from Source

If you'd rather run the Python script directly:

**Requirements:** Python 3.8+ · same network for all devices

```bash
pip install flask qrcode[pil] waitress
python app.py
```

**Optional but recommended:**

```bash
pip install waitress    # production WSGI server, much better than Flask dev
pip install netifaces   # more accurate LAN IP detection on multi-interface systems
```

### CLI Options

```bash
python app.py --port 8080           # use a different port (default: 5000)
python app.py --ip 192.168.1.42     # override LAN IP if auto-detection picks wrong interface
```

---

## How It Works

AirShare runs a local Flask server and exposes a simple web interface.

On startup the server generates:
- a **local URL** based on your detected LAN IP
- a **temporary 6-digit PIN** (rotates on every restart)
- a **QR code** that embeds a fresh auto-login token

Clients connect via browser:
- Scan QR → instantly authenticated, no PIN needed
- Enter PIN manually → session created

Files are uploaded in 32 MB chunks in parallel and reassembled server-side. Downloads use parallel range requests for maximum throughput. All data stays on the host machine.

---

## Project Structure

```
.
├── app.py              # Main application (run this from source)
├── airshare.exe        # Portable executable — no Python needed
├── shared_files/       # Uploaded files are stored here
└── .chunks/            # Temporary chunk storage (auto-cleaned after upload)
```

The `shared_files/` folder is created automatically next to wherever `app.py` or `airshare.exe` is run from. To change the storage location, move the executable.

---

## Configuration

At the top of `app.py`:

```python
PORT            = 5000
SESSION_TTL     = 8 * 3600          # session length in seconds (default: 8 hours)
CHUNK_SIZE_HINT = 32 * 1024 * 1024  # upload chunk size hint sent to client (32 MB)
STREAM_BUF      = 4 * 1024 * 1024   # server-side read buffer for streaming (4 MB)
```

Client-side transfer constants (inside the embedded JS):

```
Upload : 8 parallel threads · 32 MB chunks
Download : 6 parallel threads · 16 MB range slices
```

---

## Connecting Devices

1. Make sure all devices are on the **same Wi-Fi network**
2. Open the URL shown in the terminal (e.g. `http://192.168.1.x:5000`)
3. Authenticate via QR scan or PIN
4. Share files

If the URL isn't reachable from another device, check your firewall:

```bat
# Windows — allow port 5000 inbound
netsh advfirewall firewall add rule name="AirShare" dir=in action=allow protocol=TCP localport=5000

# Linux
sudo ufw allow 5000

# macOS — System Settings → Network → Firewall
```

If the wrong IP is shown (common on machines with VPN or multiple network interfaces):

```bash
python app.py --ip YOUR_WIFI_IP
# or just double-click and it uses the detected IP — use --ip to override
```

---

## Security Notes

- Sessions expire automatically (default: 8 hours)
- PIN is randomly generated and resets on every restart
- Files are only accessible to authenticated sessions on the local network
- Filenames are sanitized via `werkzeug.utils.secure_filename` before saving
- Designed for **trusted local environments** — not intended for public/internet exposure

---

## Limitations

- No encryption in transit (HTTP, not HTTPS)
- No user accounts or per-user permissions
- Not designed for WAN or internet-facing use
- Files persist until manually deleted

---

## Possible Improvements

- HTTPS / TLS support
- File previews (images, text, video)
- Upload progress persistence across page reloads
- User roles or access control
- Expiring download links
- ZIP download for bulk selections

---

## Building the EXE Yourself

The included `airshare.exe` was built with PyInstaller. To rebuild it:

```bash
pip install pyinstaller flask waitress "qrcode[pil]" pillow werkzeug
pyinstaller --onefile --console --name airshare app.py
```

Or use the provided `build_exe.bat` if it's included in the repo — double-click and it handles everything automatically.

> **Antivirus note:** PyInstaller executables sometimes trigger Windows Defender as a false positive. This is a known issue with PyInstaller-bundled apps. Add an exception if needed.

---