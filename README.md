# AirShare

A lightweight, self-hosted file sharing app for local networks. Open it in a browser, scan a QR code or enter a PIN, and start transferring files instantly between devices.

No accounts. No cloud. Just direct sharing over LAN.

---

## Features

* QR-based instant access
* PIN authentication for controlled entry
* Chunked uploads (handles large files reliably)
* Resume-friendly transfers
* Drag-and-drop interface
* Multi-file upload support
* Bulk download and delete
* Local file storage
* No external dependencies beyond Python packages

---

## How It Works

AirShare runs a local Flask server and exposes a simple web interface.

* The server generates:

  * a **local URL**
  * a **temporary PIN**
  * a **QR code for auto-authentication**

* Clients connect via browser:

  * Scan QR → instantly logged in
  * Enter PIN → session created

* Files are uploaded in chunks and reassembled server-side.

* All data stays on the host machine.

---

## Requirements

* Python 3.8+
* Same network for all devices

Install dependencies:

```bash
pip install flask qrcode
```

---

## Run the App

```bash
python app_version_2.py
```

On startup, you’ll see:

* Local URL (e.g. `http://192.168.x.x:5000`)
* 6-digit PIN

Open the URL in any device on the same network.

---

## Usage

### Connect

* Scan the QR code (auto login), or
* Enter the PIN manually

### Upload Files

* Drag & drop files into the upload area
* Or click to select files

Uploads are chunked automatically.

### Manage Files

* Download individual files
* Select multiple files for bulk actions
* Delete files directly from the UI
* Reorder files via drag-and-drop (stored locally in browser)

---

## Project Structure

```
.
├── app_version_2.py     # Main application
├── shared_files/        # Stored uploaded files
└── .chunks/             # Temporary chunk storage
```

---

## Configuration

Inside the script:

```python
PORT = 5000
SESSION_TTL = 8 * 3600
CHUNK_SIZE_HINT = 5 * 1024 * 1024
```

You can adjust:

* Port
* Session duration
* Chunk size (client hint)

---

## Security Notes

* Sessions expire automatically (default: 8 hours)
* PIN resets on every server restart
* Files are only accessible within the network
* Filenames are sanitized before saving

This is designed for trusted local environments, not public exposure.

---

## Limitations

* No encryption beyond local network transport
* No user accounts or permissions system
* Not optimized for WAN or internet-facing use
* Files persist until manually deleted

---

## Possible Improvements

* HTTPS support
* File previews
* Upload progress persistence
* User roles or access control
* Expiring file links

---

## License

MIT License (or add your preferred license)

---
