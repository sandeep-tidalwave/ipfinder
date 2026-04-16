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
- Discovery now uses ICMP + common TCP port probing and can optionally use `nmap -sn` for better coverage.
- The scanner auto-detects reachable private subnets from your Linux route table and scans them.
- For common `192.168.x.1` and `192.168.x.254` router setups, the scanner auto-probes both gateway patterns to detect additional series networks behind the same router.

## Scan Other Routed Subnets
To include additional subnets (for example another series/segment routed from your LAN), set:

```bash
export IPFINDER_EXTRA_SUBNETS="192.168.2.0/24,192.168.3.0/24"
python app.py
```

This variable is optional. Invalid CIDRs are ignored and shown as warnings in scan results.
Use it only when you want to force-add networks that are not present in the route table.

To disable automatic router-series detection:

```bash
export IPFINDER_AUTO_ROUTER_SERIES=0
```
