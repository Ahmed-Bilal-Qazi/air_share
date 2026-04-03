# AirShare

A lightweight, local network file-sharing tool built with Flask. It lets you transfer files between devices on the same WiFi—no accounts, no cloud, no setup beyond running a single script.

It works by spinning up a small web server on your machine and exposing a simple interface accessible via browser. A QR code makes connecting from phones effortless.

---

## Features

* Instant file sharing over local network
* Drag-and-drop upload interface
* QR code for quick mobile access
* No external dependencies beyond Python packages
* Supports large files (up to 4 GB)
* Download and delete files from any connected device
* Clean, minimal UI with real-time updates

---

## How It Works

* The server runs on your machine (port `5000`)
* It detects your local IP address
* Other devices on the same WiFi can connect via browser
* Files are stored locally in a `shared_files/` directory

No data ever leaves your network.

---

## Requirements

* Python 3.8+
* pip

---

## Installation

Clone the repository:

```bash
git clone https://github.com/Ahmed-Bilal-Qazi/airshare.git
cd airshare
```

Install dependencies:

```bash
pip install flask qrcode
```

---

## Usage

Run the app:

```bash
python app.py
```

You’ll see output like:

```
AirShare is running
Open this on any device on the same WiFi:

http://192.168.x.x:5000
```

Open that URL in your browser or scan the QR code.

---

## Interface Overview

* **QR Code Panel**

  * Scan with phone to connect instantly
  * Tap-to-copy URL

* **Upload Area**

  * Drag & drop files or click to select
  * Upload progress bar included

* **Shared Files List**

  * View all uploaded files
  * Download or delete any file
  * Auto-refresh every 5 seconds

---

## Project Structure

```
.
├── app.py            # Main application
├── shared_files/     # Uploaded files (auto-created)
```

---

## API Endpoints

* `GET /`
  Serves the main UI

* `POST /upload`
  Upload one or more files

* `GET /files`
  Returns list of shared files

* `GET /download/<filename>`
  Downloads a file

* `DELETE /delete/<filename>`
  Deletes a file

---

## Configuration

Inside `app.py`:

```python
PORT = 5000
```

You can change the port if needed.

Max file size:

```python
app.config["MAX_CONTENT_LENGTH"] = 4 * 1024 * 1024 * 1024  # 4 GB
```

---

## Firewall Notes

If other devices can’t connect, your firewall may be blocking access.

### Windows (run as admin)

```bash
netsh advfirewall firewall add rule name=AirShare dir=in action=allow protocol=TCP localport=5000
```

### Linux

```bash
sudo ufw allow 5000
```

### macOS

Allow Python in:

```
System Settings → Network → Firewall
```

---

## Limitations

* Works only on the same local network
* No authentication or encryption
* Files are publicly accessible to anyone on the network
* No resumable uploads

---

## Security Considerations

This tool is intentionally simple. Use it only on trusted networks.

If you need more control, consider adding:

* password protection
* HTTPS support
* file expiration logic

---

## Possible Improvements

* Upload resume support
* File previews (images, videos)
* Progress indicators for downloads
* Multi-user session awareness
* Optional authentication layer

---

## License

MIT License (or update as needed)

---

## Summary

AirShare is built for one thing: quick, frictionless file transfer between devices nearby. No login screens, no pairing, no cloud delays—just open, upload, and download.
