const scanBtn = document.getElementById("scanBtn");
const csvBtn = document.getElementById("csvBtn");
const themeToggle = document.getElementById("themeToggle");
const searchInput = document.getElementById("searchInput");
const localIpValue = document.getElementById("localIpValue");
const gatewayDevicesEl = document.getElementById("gatewayDevices");
const cpplusDevicesEl = document.getElementById("cpplusDevices");
const otherCameraDevicesEl = document.getElementById("otherCameraDevices");
const otherDeviceDevicesEl = document.getElementById("otherDeviceDevices");
const meta = document.getElementById("meta");
const warningsEl = document.getElementById("warnings");
const totalDevicesStat = document.getElementById("totalDevicesStat");
const totalCamerasStat = document.getElementById("totalCamerasStat");
const onlineDevicesStat = document.getElementById("onlineDevicesStat");
const lastScanStat = document.getElementById("lastScanStat");
const gatewayCount = document.getElementById("gatewayCount");
const cpplusCount = document.getElementById("cpplusCount");
const otherCameraCount = document.getElementById("otherCameraCount");
const otherDeviceCount = document.getElementById("otherDeviceCount");

const state = {
  gateway_devices: [],
  cpplus_cameras: [],
  other_cameras: [],
  other_devices: [],
  local_ip: document.body.dataset.localIp || "127.0.0.1",
  scan_time: "--",
};

const icons = {
  camera: `
    <svg viewBox="0 0 24 24" aria-hidden="true"><path d="M9 5.5 10.2 4h3.6L15 5.5h3A2.5 2.5 0 0 1 20.5 8v8A2.5 2.5 0 0 1 18 18.5H6A2.5 2.5 0 0 1 3.5 16V8A2.5 2.5 0 0 1 6 5.5h3Zm3 9a3 3 0 1 0 0-6 3 3 0 0 0 0 6Z"/></svg>
  `,
  gateway: `
    <svg viewBox="0 0 24 24" aria-hidden="true"><path d="M12 2 4 7v10l8 5 8-5V7l-8-5Zm0 3 5 3.1v7.8L12 19l-5-3.1V8.1L12 5Zm-1 3h2v4h3l-4 5-4-5h3V8Z"/></svg>
  `,
  device: `
    <svg viewBox="0 0 24 24" aria-hidden="true"><path d="M5 5.5A2.5 2.5 0 0 1 7.5 3h9A2.5 2.5 0 0 1 19 5.5v11A2.5 2.5 0 0 1 16.5 19H7.5A2.5 2.5 0 0 1 5 16.5v-11ZM8 6h8v8H8V6Zm1 10.5h6V18H9v-1.5Z"/></svg>
  `,
  mobile: `
    <svg viewBox="0 0 24 24" aria-hidden="true"><path d="M8 2.5A2.5 2.5 0 0 0 5.5 5v14A2.5 2.5 0 0 0 8 21.5h8a2.5 2.5 0 0 0 2.5-2.5V5A2.5 2.5 0 0 0 16 2.5H8Zm0 2h8a.5.5 0 0 1 .5.5v13H7.5V5A.5.5 0 0 1 8 4.5Zm4 14a1 1 0 1 0 0 .1 1 1 0 0 0 0-.1Z"/></svg>
  `,
};

function escapeHtml(value) {
  return String(value)
    .replaceAll("&", "&amp;")
    .replaceAll("<", "&lt;")
    .replaceAll(">", "&gt;")
    .replaceAll('"', "&quot;")
    .replaceAll("'", "&#39;");
}

function iconForDevice(device) {
  const group = device.group || "other_devices";
  if (group === "gateway_devices") {
    return icons.gateway;
  }
  if (group === "cpplus_cameras" || group === "other_cameras") {
    return icons.camera;
  }
  if (device.vendor && /private/i.test(device.vendor)) {
    return icons.mobile;
  }
  return icons.device;
}

function normalizeDevice(device) {
  const searchable = [device.name, device.ip, device.mac, device.vendor, device.group]
    .filter(Boolean)
    .join(" ")
    .toLowerCase();

  return { ...device, searchable };
}

function deviceAccentClass(device) {
  if (device.group === "gateway_devices") return "device-card--network";
  if (device.group === "cpplus_cameras") return "device-card--cpplus";
  if (device.group === "other_cameras") return "device-card--hikvision";
  if (device.vendor && /private/i.test(device.vendor)) return "device-card--private";
  return "device-card--unknown";
}

function renderDeviceCard(device) {
  const safeIp = escapeHtml(device.ip);
  const safeName = escapeHtml(device.name || "Unknown");
  const safeVendor = escapeHtml(device.vendor || "Unknown");
  const safeMac = escapeHtml(device.mac || "--");
  const openUrl = `http://${device.ip}`;

  return `
    <article class="device-card ${deviceAccentClass(device)}" data-search="${escapeHtml(device.searchable)}" data-ip="${safeIp}">
      <div class="device-card-top">
        <div class="device-icon">${iconForDevice(device)}</div>
        <div class="device-headline">
          <h3>${safeName}</h3>
          <p>${safeVendor}</p>
        </div>
        ${device.group === "gateway_devices" ? '<span class="gateway-badge">Gateway</span>' : ''}
      </div>

      <div class="device-specs">
        <div><span>IP Address</span><strong>${safeIp}</strong></div>
        <div><span>MAC Address</span><strong>${safeMac}</strong></div>
      </div>

      <div class="device-status-row">
        <span class="status-dot status-dot-online"></span>
        <span class="status-label">Online</span>
        <span class="latency-pill">Latency: <strong class="latency-value">--</strong></span>
      </div>

      <div class="device-actions">
        <button type="button" class="mini-btn" data-action="ping">Ping</button>
        <button type="button" class="mini-btn" data-action="open" data-url="${escapeHtml(openUrl)}">Open</button>
        <button type="button" class="mini-btn" data-action="configure" data-url="${escapeHtml(openUrl)}">Configure</button>
      </div>
    </article>
  `;
}

function updateSection(sectionEl, devices, emptyMessage) {
  if (!devices.length) {
    sectionEl.innerHTML = `<div class="empty-state">${escapeHtml(emptyMessage)}</div>`;
    return;
  }

  sectionEl.innerHTML = devices.map(renderDeviceCard).join("");
}

function setTheme(theme) {
  document.body.dataset.theme = theme;
  localStorage.setItem("lan-dashboard-theme", theme);
  themeToggle.textContent = theme === "dark" ? "Light mode" : "Dark mode";
}

function getTheme() {
  return localStorage.getItem("lan-dashboard-theme") ||
    (window.matchMedia && window.matchMedia("(prefers-color-scheme: dark)").matches ? "dark" : "light");
}

function updateStats(data) {
  const totalDevices = data.count || 0;
  const totalCameras = (data.cpplus_cameras?.length || 0) + (data.other_cameras?.length || 0);
  const onlineDevices = totalDevices;

  totalDevicesStat.textContent = String(totalDevices);
  totalCamerasStat.textContent = String(totalCameras);
  onlineDevicesStat.textContent = String(onlineDevices);
  lastScanStat.textContent = data.scan_time || "--";

  gatewayCount.textContent = String(data.gateway_devices?.length || 0);
  cpplusCount.textContent = String(data.cpplus_cameras?.length || 0);
  otherCameraCount.textContent = String(data.other_cameras?.length || 0);
  otherDeviceCount.textContent = String(data.other_devices?.length || 0);
}

function renderAll() {
  const query = searchInput.value.trim().toLowerCase();

  const filteredGateway = state.gateway_devices.filter((device) => device.searchable.includes(query));
  const filteredCpplus = state.cpplus_cameras.filter((device) => device.searchable.includes(query));
  const filteredOtherCameras = state.other_cameras.filter((device) => device.searchable.includes(query));
  const filteredOtherDevices = state.other_devices.filter((device) => device.searchable.includes(query));

  updateSection(gatewayDevicesEl, filteredGateway, "No gateway or router devices found.");
  updateSection(cpplusDevicesEl, filteredCpplus, "No CP PLUS cameras found.");
  updateSection(otherCameraDevicesEl, filteredOtherCameras, "No other camera devices found.");
  updateSection(otherDeviceDevicesEl, filteredOtherDevices, "No other devices found.");

  document.querySelectorAll(".category-card").forEach((card) => {
    const key = card.dataset.section;
    const hasItems =
      (key === "gateway_devices" && filteredGateway.length > 0) ||
      (key === "cpplus_cameras" && filteredCpplus.length > 0) ||
      (key === "other_cameras" && filteredOtherCameras.length > 0) ||
      (key === "other_devices" && filteredOtherDevices.length > 0);

    if (query) {
      card.open = hasItems;
    }
  });
}

function downloadCsv() {
  window.location.href = "/api/export.csv";
}

async function pingDevice(button) {
  const card = button.closest(".device-card");
  const ip = card?.dataset.ip;
  const latencyValue = card?.querySelector(".latency-value");
  const statusDot = card?.querySelector(".status-dot");
  const statusLabel = card?.querySelector(".status-label");

  if (!ip) return;

  button.disabled = true;
  button.textContent = "Pinging...";

  try {
    const res = await fetch(`/api/ping/${encodeURIComponent(ip)}`);
    const data = await res.json();

    if (data.ok) {
      latencyValue.textContent = `${Math.round(data.latency_ms ?? 0)} ms`;
      statusLabel.textContent = "Online";
      statusDot.classList.remove("status-dot-offline");
      statusDot.classList.add("status-dot-online");
    } else {
      latencyValue.textContent = "Timeout";
      statusLabel.textContent = "Offline";
      statusDot.classList.remove("status-dot-online");
      statusDot.classList.add("status-dot-offline");
    }
  } catch (error) {
    latencyValue.textContent = "Error";
    statusLabel.textContent = "Offline";
    statusDot.classList.remove("status-dot-online");
    statusDot.classList.add("status-dot-offline");
  } finally {
    button.disabled = false;
    button.textContent = "Ping";
  }
}

async function configureDevice(button) {
  const url = button.dataset.url;
  try {
    await navigator.clipboard.writeText(url);
    const previous = button.textContent;
    button.textContent = "Copied";
    setTimeout(() => {
      button.textContent = previous;
    }, 900);
  } catch (error) {
    window.open(url, "_blank", "noopener");
  }
}

function bindCardActions() {
  document.querySelectorAll(".device-card button[data-action]").forEach((button) => {
    if (button.dataset.bound === "1") return;
    button.dataset.bound = "1";

    button.addEventListener("click", async () => {
      const action = button.dataset.action;
      if (action === "ping") {
        await pingDevice(button);
      } else if (action === "open") {
        window.open(button.dataset.url, "_blank", "noopener");
      } else if (action === "configure") {
        await configureDevice(button);
      }
    });
  });
}

async function scan() {
  scanBtn.disabled = true;
  warningsEl.textContent = "";
  meta.textContent = "Scanning your local network...";
  document.body.classList.add("is-scanning");

  try {
    const res = await fetch("/api/scan");
    if (!res.ok) {
      throw new Error(`HTTP ${res.status}`);
    }

    const data = await res.json();
    state.gateway_devices = (data.gateway_devices || []).map(normalizeDevice);
    state.cpplus_cameras = (data.cpplus_cameras || []).map(normalizeDevice);
    state.other_cameras = (data.other_cameras || []).map(normalizeDevice);
    state.other_devices = (data.other_devices || []).map(normalizeDevice);
    state.local_ip = data.local_ip || state.local_ip;
    state.scan_time = data.scan_time || state.scan_time;

    localIpValue.textContent = state.local_ip;
    updateStats(data);
    renderAll();
    bindCardActions();

    meta.textContent = `Found ${data.count} active device(s). Last scan: ${state.scan_time}`;

    if (data.warnings && data.warnings.length) {
      warningsEl.textContent = data.warnings.join(" ");
    }
  } catch (err) {
    meta.textContent = "Scan failed.";
    warningsEl.textContent = `Error: ${err.message}`;
  } finally {
    scanBtn.disabled = false;
    document.body.classList.remove("is-scanning");
  }
}

searchInput.addEventListener("input", renderAll);
themeToggle.addEventListener("click", () => {
  setTheme(document.body.dataset.theme === "dark" ? "light" : "dark");
});
scanBtn.addEventListener("click", scan);
csvBtn.addEventListener("click", downloadCsv);

setTheme(getTheme());
renderAll();
