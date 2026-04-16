import ipaddress
import re
import io
import socket
import subprocess
import threading
import json
import os
import html
import shutil
from datetime import datetime
import urllib.error
import urllib.request
from concurrent.futures import ThreadPoolExecutor, as_completed
from dataclasses import dataclass
from itertools import islice
from typing import Dict, List, Set, Tuple

import psutil
from flask import Flask, Response, jsonify, render_template, request

try:
    from reportlab.lib.pagesizes import letter
    from reportlab.platypus import SimpleDocTemplate, Table, TableStyle, Paragraph, Spacer
    from reportlab.lib import colors
    from reportlab.lib.styles import getSampleStyleSheet
except ImportError:
    pass

try:
    from mac_vendor_lookup import MacLookup
    mac_lookup = MacLookup()
    try:
        mac_lookup.update_vendors()  # Pre-warm cache to avoid thread collisions
    except Exception:
        pass
except ImportError:
    mac_lookup = None

app = Flask(__name__)
scan_lock = threading.Lock()

CUSTOM_NAMES_FILE = "custom_names.json"

def load_custom_names() -> Dict[str, str]:
    if os.path.exists(CUSTOM_NAMES_FILE):
        try:
            with open(CUSTOM_NAMES_FILE, "r") as f:
                return json.load(f)
        except Exception:
            pass
    return {}

def save_custom_name(mac: str, name: str):
    names = load_custom_names()
    names[mac.lower()] = name
    with open(CUSTOM_NAMES_FILE, "w") as f:
        json.dump(names, f, indent=2)

IGNORED_IFACE_PREFIXES = (
    "lo",
    "docker",
    "br-",
    "veth",
    "virbr",
    "vmnet",
    "vboxnet",
    "zt",
    "tailscale",
)

ZERO_MAC = "00:00:00:00:00:00"
UNAVAILABLE_MAC = "--"

DISCOVERY_TCP_PORTS = (80, 443, 554, 8000, 37777)

OUI_VENDOR_HINTS = {
    # Common camera vendors (not exhaustive)
    "40:19:20": "Hikvision",
    "44:19:b6": "Hikvision",
    "bc:ad:28": "Hikvision",
    "d4:6e:5c": "Hikvision",
    "ec:03:73": "Hikvision",
    "fc:1f:19": "Hikvision",
    "00:23:63": "Hikvision",
    "3c:ef:8c": "Dahua",
    "a0:bd:1d": "Dahua",
    "00:12:09": "AXIS",
}

CPPLUS_OUI_PREFIXES = {
    "5c:35:48",
}

CAMERA_NAME_HINTS = (
    "camera",
    "cam",
    "cctv",
    "dvr",
    "nvr",
    "ipc",
    "hik",
    "dahua",
    "cpplus",
)

FUZZY_VENDOR_HINTS = {
    "CP PLUS": (
        "cpplus",
        "cp-plus",
        "cp plus",
        "cppluse",
        "cp pluse",
        "c p plus",
        "cplus",
    ),
    "Hikvision": (
        "hikvision",
        "hik vison",
        "hikvison",
        "hik",
    ),
    "Dahua": (
        "dahua",
        "da hua",
    ),
    "AXIS": (
        "axis",
    ),
}

VENDOR_ALIASES = {
    "aditya infotech": "CP PLUS",
    "aditya-infotech": "CP PLUS",
}


@dataclass
class Device:
    ip: str
    name: str
    mac: str
    vendor: str
    group: str


def _normalize_hint_text(value: str) -> str:
    return re.sub(r"[^a-z0-9]", "", value.lower())


def _contains_hint(value: str, hints: Tuple[str, ...]) -> bool:
    lowered = value.lower()
    normalized = _normalize_hint_text(value)
    for hint in hints:
        if hint.lower() in lowered:
            return True
        if _normalize_hint_text(hint) in normalized:
            return True
    return False


def _canonical_vendor_name(vendor: str) -> str:
    lowered = vendor.lower().strip()
    normalized = _normalize_hint_text(lowered)
    for alias, canonical in VENDOR_ALIASES.items():
        if alias in lowered or _normalize_hint_text(alias) == normalized:
            return canonical
    return vendor


def _is_port_open(ip: str, port: int, timeout: float = 0.35) -> bool:
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.settimeout(timeout)
    try:
        return sock.connect_ex((ip, port)) == 0
    except OSError:
        return False
    finally:
        sock.close()


def _http_fingerprint(ip: str, timeout: float = 1.2) -> str:
    req = urllib.request.Request(f"http://{ip}/", headers={"User-Agent": "ipfinder/1.0"})
    try:
        with urllib.request.urlopen(req, timeout=timeout) as resp:
            server = (resp.headers.get("Server") or "").lower()
            body = resp.read(3072).decode("utf-8", errors="ignore").lower()
            return f"{server} {body}"
    except urllib.error.HTTPError as exc:
        # Many cameras return 401 with useful fingerprint headers/body.
        server = (exc.headers.get("Server") or "").lower()
        auth = (exc.headers.get("WWW-Authenticate") or "").lower()
        try:
            body = exc.read(3072).decode("utf-8", errors="ignore").lower()
        except OSError:
            body = ""
        return f"{server} {auth} {body}"
    except (urllib.error.URLError, TimeoutError, OSError):
        return ""


def _probe_camera_vendor(ip: str) -> str:
    # Fast network hints before HTTP probe.
    has_rtsp = _is_port_open(ip, 554)
    has_hik_port = _is_port_open(ip, 8000)
    has_http = _is_port_open(ip, 80)

    fingerprint = _http_fingerprint(ip) if has_http else ""

    if "hikvision" in fingerprint or "hik" in fingerprint or has_hik_port:
        return "Hikvision"
    if "dahua" in fingerprint:
        return "Dahua"
    if any(tag in fingerprint for tag in ("cpplus", "cp-plus", "cp plus")):
        return "CP PLUS"
    if "axis" in fingerprint:
        return "AXIS"

    if has_rtsp:
        return "Unknown Camera"

    return ""


def _probe_device_type(ip: str) -> str:
    has_http = _is_port_open(ip, 80)
    if not has_http:
        return ""
    fingerprint = _http_fingerprint(ip)
    if "nvr" in fingerprint:
        return "NVR"
    if "dvr" in fingerprint:
        return "DVR"
    if "camera" in fingerprint or "ipc" in fingerprint:
        return "Camera"
    return ""


def _is_private_ipv4(ip: str) -> bool:
    try:
        return ipaddress.ip_address(ip).is_private
    except ValueError:
        return False


def _get_local_subnets() -> List[ipaddress.IPv4Network]:
    subnets: List[ipaddress.IPv4Network] = []
    seen: Set[str] = set()

    for iface_name, iface_addrs in psutil.net_if_addrs().items():
        lowered = iface_name.lower()
        if any(lowered.startswith(prefix) for prefix in IGNORED_IFACE_PREFIXES):
            continue

        ipv4 = None
        netmask = None

        for addr in iface_addrs:
            if addr.family == socket.AF_INET:
                ipv4 = addr.address
                netmask = addr.netmask
                break

        if not ipv4 or not netmask:
            continue
        if ipv4.startswith("127."):
            continue
        if not _is_private_ipv4(ipv4):
            continue

        try:
            network = ipaddress.IPv4Network(f"{ipv4}/{netmask}", strict=False)
        except ValueError:
            continue

        key = str(network)
        if key not in seen:
            seen.add(key)
            subnets.append(network)

    return subnets


def _get_primary_local_ip() -> str:
    fallback = "127.0.0.1"

    for iface_name, iface_addrs in psutil.net_if_addrs().items():
        lowered = iface_name.lower()
        if any(lowered.startswith(prefix) for prefix in IGNORED_IFACE_PREFIXES):
            continue

        for addr in iface_addrs:
            if addr.family != socket.AF_INET:
                continue
            if addr.address.startswith("127."):
                continue
            fallback = addr.address
            if _is_private_ipv4(addr.address):
                return addr.address

    return fallback


def _ping_ip(ip: str, timeout_sec: int = 1) -> bool:
    cmd = ["ping", "-c", "1", "-W", str(timeout_sec), ip]
    result = subprocess.run(cmd, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    return result.returncode == 0


def _host_responds(ip: str) -> bool:
    if _ping_ip(ip):
        return True

    # Some devices block ICMP but still expose web/RTSP or vendor service ports.
    for port in DISCOVERY_TCP_PORTS:
        if _is_port_open(ip, port, timeout=0.35):
            return True

    return False


def _nmap_discover_hosts(subnet: ipaddress.IPv4Network, timeout_sec: int = 60) -> Set[str]:
    if shutil.which("nmap") is None:
        return set()

    cmd = [
        "nmap",
        "-sn",
        "-n",
        "--max-retries",
        "1",
        "--host-timeout",
        "1200ms",
        str(subnet),
    ]
    try:
        proc = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout_sec)
    except (subprocess.SubprocessError, OSError):
        return set()

    text = f"{proc.stdout}\n{proc.stderr}"
    return set(re.findall(r"Nmap scan report for ((?:\d{1,3}\.){3}\d{1,3})", text))


def _get_extra_subnets() -> Tuple[List[ipaddress.IPv4Network], List[str]]:
    raw = os.environ.get("IPFINDER_EXTRA_SUBNETS", "").strip()
    if not raw:
        return [], []

    results: List[ipaddress.IPv4Network] = []
    warnings: List[str] = []

    for item in raw.split(","):
        cidr = item.strip()
        if not cidr:
            continue
        try:
            network = ipaddress.IPv4Network(cidr, strict=False)
        except ValueError:
            warnings.append(f"Ignored invalid subnet in IPFINDER_EXTRA_SUBNETS: {cidr}")
            continue
        results.append(network)

    return results, warnings


def _get_routed_private_subnets() -> Tuple[List[ipaddress.IPv4Network], List[str]]:
    warnings: List[str] = []
    try:
        proc = subprocess.run(
            ["ip", "-4", "route", "show"],
            capture_output=True,
            text=True,
            check=False,
        )
    except (OSError, subprocess.SubprocessError):
        return [], ["Could not read route table for automatic subnet detection."]

    if proc.returncode != 0:
        return [], ["Could not read route table for automatic subnet detection."]

    subnets: List[ipaddress.IPv4Network] = []
    for raw_line in proc.stdout.splitlines():
        line = raw_line.strip()
        if not line or line.startswith("default"):
            continue

        parts = line.split()
        cidr = parts[0]
        if "/" not in cidr:
            continue

        try:
            subnet = ipaddress.IPv4Network(cidr, strict=False)
        except ValueError:
            continue

        if not subnet.is_private:
            continue
        if subnet.is_link_local:
            continue

        dev = ""
        if "dev" in parts:
            dev_index = parts.index("dev")
            if dev_index + 1 < len(parts):
                dev = parts[dev_index + 1].lower()
        if dev and any(dev.startswith(prefix) for prefix in IGNORED_IFACE_PREFIXES):
            continue

        subnets.append(subnet)

    return subnets, warnings


def _discover_router_series_subnets(timeout_sec: int = 1) -> Tuple[List[ipaddress.IPv4Network], List[str]]:
    warnings: List[str] = []
    if os.environ.get("IPFINDER_AUTO_ROUTER_SERIES", "1").strip().lower() in {"0", "false", "no"}:
        return [], warnings

    try:
        default_out = subprocess.run(
            ["ip", "-4", "route", "show", "default"],
            capture_output=True,
            text=True,
            check=False,
        )
    except (OSError, subprocess.SubprocessError):
        return [], warnings

    if default_out.returncode != 0:
        return [], warnings

    match = re.search(r"default via ((?:\d{1,3}\.){3}\d{1,3})", default_out.stdout)
    if not match:
        return [], warnings

    try:
        gateway_ip = ipaddress.IPv4Address(match.group(1))
    except ipaddress.AddressValueError:
        return [], warnings

    gw_parts = str(gateway_ip).split(".")
    if len(gw_parts) != 4:
        return [], warnings

    # Heuristic for common SME deployments: 192.168.<series>.1 or .254 gateway addresses.
    if gw_parts[0] != "192" or gw_parts[1] != "168":
        return [], warnings

    default_host_octet = gw_parts[3]
    if default_host_octet not in {"1", "254"}:
        return [], warnings

    host_octets = {"1", "254", default_host_octet}
    candidates = [f"192.168.{i}.{h}" for i in range(0, 256) for h in host_octets]
    candidates.append(str(gateway_ip))
    candidates = sorted(set(candidates))

    alive_gateway_ips: Set[str] = set()
    with ThreadPoolExecutor(max_workers=64) as pool:
        futures = {pool.submit(_host_responds, ip): ip for ip in candidates}
        for future in as_completed(futures):
            ip = futures[future]
            try:
                if future.result():
                    alive_gateway_ips.add(ip)
            except Exception:
                pass

    subnets: List[ipaddress.IPv4Network] = []
    for ip in sorted(alive_gateway_ips):
        parts = ip.split(".")
        try:
            subnets.append(ipaddress.IPv4Network(f"{parts[0]}.{parts[1]}.{parts[2]}.0/24", strict=False))
        except ValueError:
            continue

    if subnets:
        warnings.append("Auto-detected additional router series subnets from reachable gateway interfaces.")

    return subnets, warnings


def _get_target_subnets() -> Tuple[List[ipaddress.IPv4Network], List[str]]:
    discovered = _get_local_subnets()
    routed, route_warnings = _get_routed_private_subnets()
    router_series, router_series_warnings = _discover_router_series_subnets()
    extra, env_warnings = _get_extra_subnets()

    merged: List[ipaddress.IPv4Network] = []
    seen: Set[str] = set()
    for subnet in discovered + routed + router_series + extra:
        key = str(subnet)
        if key in seen:
            continue
        seen.add(key)
        merged.append(subnet)

    warnings = route_warnings + router_series_warnings + env_warnings
    return merged, warnings


def _ip_in_any_subnet(ip: str, subnets: List[ipaddress.IPv4Network]) -> bool:
    try:
        addr = ipaddress.IPv4Address(ip)
    except ValueError:
        return False
    return any(addr in subnet for subnet in subnets)


def _prime_arp_table(subnets: List[ipaddress.IPv4Network], max_hosts_per_subnet: int = 512) -> Tuple[Set[str], List[str]]:
    targets: List[str] = []
    warnings: List[str] = []
    for subnet in subnets:
        sampled_hosts = [str(h) for h in islice(subnet.hosts(), max_hosts_per_subnet + 1)]
        if len(sampled_hosts) > max_hosts_per_subnet:
            sampled_hosts = sampled_hosts[:max_hosts_per_subnet]
            warnings.append(f"Subnet {subnet} truncated to first {max_hosts_per_subnet} hosts for fast scan.")
        targets.extend(sampled_hosts)

    alive_ips: Set[str] = set()

    with ThreadPoolExecutor(max_workers=64) as pool:
        futures = {pool.submit(_host_responds, ip): ip for ip in targets}
        for future in as_completed(futures):
            ip = futures[future]
            try:
                if future.result():
                    alive_ips.add(ip)
            except Exception:
                pass

    nmap_available = shutil.which("nmap") is not None
    if not nmap_available:
        warnings.append("Install 'nmap' to improve host discovery coverage.")
    else:
        for subnet in subnets:
            host_count = max(0, subnet.num_addresses - 2)
            if host_count > 1024:
                continue
            alive_ips.update(_nmap_discover_hosts(subnet))

    return alive_ips, warnings


def _read_arp_table() -> Dict[str, str]:
    arp: Dict[str, str] = {}
    try:
        with open("/proc/net/arp", "r", encoding="utf-8") as f:
            lines = f.readlines()[1:]
    except OSError:
        return arp

    for line in lines:
        parts = line.split()
        if len(parts) < 6:
            continue
        ip = parts[0]
        flags = parts[2].lower()
        mac = parts[3].lower()
        if flags != "0x2":
            continue
        if not re.fullmatch(r"([0-9a-f]{2}:){5}[0-9a-f]{2}", mac):
            continue
        if mac == ZERO_MAC:
            continue
        arp[ip] = mac

    return arp


def _reverse_dns(ip: str) -> str:
    try:
        name = socket.gethostbyaddr(ip)[0]
        return name
    except (socket.herror, socket.gaierror, OSError):
        return "unknown"


def _mac_prefix(mac: str) -> str:
    return ":".join(mac.split(":")[:3]).lower()


def _is_locally_administered_mac(mac: str) -> bool:
    try:
        first_octet = int(mac.split(":")[0], 16)
    except (ValueError, IndexError):
        return False
    return (first_octet & 0x02) != 0


def _detect_vendor(name: str, mac: str) -> str:
    for vendor_name, hints in FUZZY_VENDOR_HINTS.items():
        if _contains_hint(name, hints):
            return vendor_name

    prefix = _mac_prefix(mac)
    if prefix in CPPLUS_OUI_PREFIXES:
        return "CP PLUS"
    if prefix in OUI_VENDOR_HINTS:
        return OUI_VENDOR_HINTS[prefix]
        
    if mac_lookup:
        try:
            vendor = mac_lookup.lookup(mac)
            if vendor:
                # Clean up overly long corporate names into friendly formats
                clean_vendor = vendor.split(",")[0].replace(" Ltd.", "").replace(" Inc", "").strip()
                return _canonical_vendor_name(clean_vendor)
        except Exception:
            pass

    return "Unknown"


def _fallback_name(ip: str, vendor: str, mac: str) -> str:
    if vendor == "Gateway":
        return "Gateway"
    if vendor in {"CP PLUS", "Hikvision", "Dahua", "AXIS", "Unknown Camera"}:
        return f"{vendor} Camera"
    if vendor != "Unknown":
        return f"{vendor} device"
    if _is_locally_administered_mac(mac):
        return "Private MAC device"
    return f"Device {ip}"


def _is_gateway_device(name: str, ip: str) -> bool:
    lowered = name.lower()
    if lowered in {"_gateway", "gateway", "router"}:
        return True
    if "gateway" in lowered or "router" in lowered:
        return True
    return False

def _is_camera(name: str, vendor: str) -> bool:
    if vendor in {"CP PLUS", "Hikvision", "Dahua", "AXIS"}:
        return True
    if vendor == "Unknown Camera":
        return True
    return _contains_hint(name, CAMERA_NAME_HINTS)

def _get_device_group(name: str, vendor: str, ip: str) -> str:
    if _is_gateway_device(name, ip):
        return "network"
    if _is_camera(name, vendor):
        return "cameras"
        
    n = name.lower()
    v = vendor.lower()
    
    # Modern iOS and Android phones use Private MAC addresses
    if "private mac" in n:
        return "mobile"
        
    if any(x in v for x in ["samsung", "oneplus", "xiaomi", "oppo", "vivo", "realme", "motorola", "huawei", "apple"]):
        return "mobile"
        
    if any(x in v for x in ["intel", "dell", "hp", "hewlett", "asus", "acer", "lenovo", "micro-star", "gigabyte", "microsoft"]):
        return "computers"
        
    return "unknown"


def discover_devices() -> Tuple[List[Device], List[str], List[str]]:
    subnets, warnings = _get_target_subnets()
    if not subnets:
        return [], ["No private IPv4 subnet detected."], []

    alive_ips, prime_warnings = _prime_arp_table(subnets)
    arp = _read_arp_table()
    warnings.extend(prime_warnings)

    candidate_ips: Set[str] = set(alive_ips)
    candidate_ips.update(arp.keys())
    candidate_ips = {ip for ip in candidate_ips if _ip_in_any_subnet(ip, subnets)}

    custom_names = load_custom_names()

    def process_device(ip: str, mac: str) -> Device:
        name = _reverse_dns(ip)
        vendor = _detect_vendor(name, mac)
        
        if vendor == "Unknown":
            probed_vendor = _probe_camera_vendor(ip)
            if probed_vendor:
                vendor = probed_vendor
                
        if name == "unknown" and vendor in {"CP PLUS", "Hikvision", "Dahua", "AXIS"}:
            dev_type = _probe_device_type(ip)
            if dev_type:
                name = f"{vendor} {dev_type}"

        if name == "unknown":
            name = _fallback_name(ip, vendor, mac)

        custom = custom_names.get(mac.lower()) if mac not in {UNAVAILABLE_MAC, ZERO_MAC} else None
        if custom:
            name = custom

        group = _get_device_group(name, vendor, ip)
        if group == "network":
            vendor = "Gateway"

        return Device(ip=ip, mac=mac, name=name, vendor=vendor, group=group)

    devices: List[Device] = []
    with ThreadPoolExecutor(max_workers=32) as pool:
        futures = [
            pool.submit(process_device, ip, arp.get(ip, UNAVAILABLE_MAC))
            for ip in candidate_ips
        ]
        for future in as_completed(futures):
            devices.append(future.result())

    devices.sort(key=lambda d: tuple(int(x) for x in d.ip.split(".")))

    mac_counts = {}
    for d in devices:
        if d.mac in {UNAVAILABLE_MAC, ZERO_MAC}:
            continue
        mac_counts[d.mac] = mac_counts.get(d.mac, 0) + 1
    duplicates = [m for m, count in mac_counts.items() if count > 1]
    if duplicates:
        warnings.append(f"Detected duplicate MAC addresses ({', '.join(duplicates)}). This could indicate network repeating or spoofing.")

    if not devices:
        warnings.append("No active devices discovered yet. Try running as root or scan again.")

    return devices, warnings, [str(s) for s in subnets]


def _device_payload(device: Device) -> Dict[str, str]:
    return {
        "ip": device.ip,
        "name": device.name,
        "mac": device.mac,
        "vendor": device.vendor,
        "group": device.group,
    }


@app.route("/")
def index():
    operator_name = os.environ.get("USER", os.environ.get("USERNAME", "unknown"))
    return render_template("index.html", local_ip=_get_primary_local_ip(), operator_name=operator_name)


@app.route("/api/rename", methods=["POST"])
def api_rename():
    data = request.json
    mac = data.get("mac")
    name = data.get("name")
    if not mac or not name:
        return jsonify({"ok": False, "error": "Missing mac or name"}), 400
    save_custom_name(mac, name)
    return jsonify({"ok": True})


@app.route("/api/scan")
def api_scan():
    with scan_lock:
        devices, warnings, scanned_subnets = discover_devices()

    local_ip = _get_primary_local_ip()
    scan_time = datetime.now().strftime("%b %d, %Y %H:%M:%S")

    grouped = {
        "network": [],
        "cameras": [],
        "computers": [],
        "mobile": [],
        "unknown": []
    }
    for d in devices:
        if d.group in grouped:
            grouped[d.group].append(_device_payload(d))
        else:
            grouped["unknown"].append(_device_payload(d))

    return jsonify(
        {
            "count": len(devices),
            "local_ip": local_ip,
            "scan_time": scan_time,
            **grouped,
            "warnings": warnings,
            "scanned_subnets": scanned_subnets,
        }
    )



@app.route("/api/export.pdf")
def api_export_pdf():
    site_location = request.args.get("location", "Unknown Location")
    
    with scan_lock:
        devices, _, _ = discover_devices()

    buffer = io.BytesIO()
    doc = SimpleDocTemplate(buffer, pagesize=letter, rightMargin=30, leftMargin=30, topMargin=40, bottomMargin=40)
    
    styles = getSampleStyleSheet()
    elements = []

    title = Paragraph("<b>Network Device Audit Report</b>", styles['Title'])
    elements.append(title)
    elements.append(Spacer(1, 12))

    meta_text = f"""<b>Site Location:</b> {html.escape(site_location)}<br/>
<b>Scanner Operator:</b> {html.escape(os.environ.get("USER", os.environ.get("USERNAME", "unknown")))}<br/>
<b>Host Machine:</b> {html.escape(socket.gethostname())} (IP: {_get_primary_local_ip()})<br/>
<b>Scan Time:</b> {datetime.now().strftime("%Y-%m-%d %H:%M:%S")}<br/>"""
    
    elements.append(Paragraph(meta_text, styles['Normal']))
    elements.append(Spacer(1, 24))

    data = [["Category", "Device Name", "Vendor", "IP Address", "MAC Address"]]
    category_names = {
        "network": "Network",
        "cameras": "Cameras",
        "computers": "Computers",
        "mobile": "Mobile",
        "unknown": "Unknown"
    }
    
    category_order = {"network": 0, "cameras": 1, "computers": 2, "mobile": 3, "unknown": 4}
    
    def sort_key(d):
        try:
            ip_val = int(ipaddress.IPv4Address(d.ip))
        except:
            ip_val = 0
        return (category_order.get(d.group, 99), ip_val)
        
    sorted_devices = sorted(devices, key=sort_key)

    cell_style = styles['Normal'].clone("Cell")
    cell_style.fontSize = 9
    cell_style.leading = 11

    for device in sorted_devices:
        data.append([
            category_names.get(device.group, "Other"),
            Paragraph(html.escape(device.name), cell_style),
            Paragraph(html.escape(device.vendor), cell_style),
            device.ip,
            device.mac
        ])

    table = Table(data, colWidths=[70, 160, 100, 95, 115])
    table.setStyle(TableStyle([
        ('BACKGROUND', (0, 0), (-1, 0), colors.HexColor("#1168f3")),
        ('TEXTCOLOR', (0, 0), (-1, 0), colors.whitesmoke),
        ('ALIGN', (0, 0), (-1, -1), 'LEFT'),
        ('VALIGN', (0, 0), (-1, -1), 'MIDDLE'),
        ('FONTNAME', (0, 0), (-1, 0), 'Helvetica-Bold'),
        ('BOTTOMPADDING', (0, 0), (-1, 0), 8),
        ('TOPPADDING', (0, 0), (-1, 0), 8),
        ('BOTTOMPADDING', (0, 1), (-1, -1), 4),
        ('TOPPADDING', (0, 1), (-1, -1), 4),
        ('BACKGROUND', (0, 1), (-1, -1), colors.HexColor("#f7f9fc")),
        ('GRID', (0, 0), (-1, -1), 0.5, colors.lightgrey),
        ('FONTSIZE', (0, 1), (-1, -1), 9),
    ]))
    
    elements.append(table)
    doc.build(elements)
    
    pdf_bytes = buffer.getvalue()
    buffer.close()
    
    headers = {
        "Content-Disposition": 'attachment; filename="scan-report.pdf"',
        "Content-Type": "application/pdf",
    }
    return Response(pdf_bytes, headers=headers)


@app.route("/api/ping/<path:ip>")
def api_ping(ip: str):
    try:
        ipaddress.ip_address(ip)
    except ValueError:
        return jsonify({"ok": False, "message": "Invalid IP address."}), 400

    result = subprocess.run(
        ["ping", "-c", "1", "-W", "1", ip],
        capture_output=True,
        text=True,
    )
    output = f"{result.stdout}\n{result.stderr}"
    latency_match = re.search(r"time[=<]([0-9.]+)\s*ms", output)
    latency_ms = float(latency_match.group(1)) if latency_match else None

    return jsonify(
        {
            "ok": result.returncode == 0,
            "ip": ip,
            "latency_ms": latency_ms,
            "message": "Reachable" if result.returncode == 0 else "No reply",
        }
    )


if __name__ == "__main__":
    app.run(host="127.0.0.1", port=5000, debug=True)
