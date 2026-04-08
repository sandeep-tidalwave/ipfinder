# LAN IP Finder Dashboard (Offline)

Simple offline dashboard to discover devices on your current local network and show:
- Device name (reverse DNS if available)
- IP address
- MAC address (when available)
- Vendor/category grouping for cameras, gateway, and other devices

No cloud APIs are used.

## Features
- Offline local network scan
- Web dashboard UI
- JSON API endpoint
- CSV export download
- Works with common Linux setups

## Tech
- Python
- Flask (dashboard + API)
- psutil (network interface info)

## Setup
1. Create and activate a virtual environment:
   ```bash
   python3 -m venv .venv
   source .venv/bin/activate
   ```
2. Install dependencies:
   ```bash
   pip install -r requirements.txt
   ```
3. Run the app:
   ```bash
   python app.py
   ```
4. Open browser:
   - http://127.0.0.1:5000

## One-command launcher
Run the project with dependency installation in one step:
```bash
bash run.sh
```

The script creates `.venv` if needed, installs packages from `requirements.txt`, and starts the dashboard.

## CSV export
Use the "Download CSV" button in the dashboard header to export all discovered devices in a spreadsheet-friendly format.

## Notes
- Best results when run with permission to access network details.
- Host names depend on reverse DNS / local resolver availability.
- The scanner targets private IPv4 subnets from active interfaces.
