const scanBtn = document.getElementById("scanBtn");
const pdfBtn = document.getElementById("pdfBtn");
const themeToggle = document.getElementById("themeToggle");
const searchInput = document.getElementById("searchInput");
const localIpValue = document.getElementById("localIpValue");
const gatewayCount = document.getElementById("networkCount");
const camerasCount = document.getElementById("camerasCount");
const computersCount = document.getElementById("computersCount");
const mobileCount = document.getElementById("mobileCount");
const unknownCount = document.getElementById("unknownCount");

const networkDevicesEl = document.getElementById("networkDevices");
const camerasDevicesEl = document.getElementById("camerasDevices");
const computersDevicesEl = document.getElementById("computersDevices");
const mobileDevicesEl = document.getElementById("mobileDevices");
const unknownDevicesEl = document.getElementById("unknownDevices");

const meta = document.getElementById("meta");
const warningsEl = document.getElementById("warnings");
const totalDevicesStat = document.getElementById("totalDevicesStat");
const totalCamerasStat = document.getElementById("totalCamerasStat");
const onlineDevicesStat = document.getElementById("onlineDevicesStat");
const lastScanStat = document.getElementById("lastScanStat");

const state = {
  network: [],
  cameras: [],
  computers: [],
  mobile: [],
  unknown: [],
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
  computer: `
    <svg viewBox="0 0 24 24" aria-hidden="true"><path d="M20 18c1.1 0 2-.9 2-2V6c0-1.1-.9-2-2-2H4c-1.1 0-2 .9-2 2v10c0 1.1.9 2 2 2H0v2h24v-2h-4zM4 6h16v10H4V6z"/></svg>
  `
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
  const group = device.group || "unknown";
  if (group === "network") return icons.gateway;
  if (group === "cameras") return icons.camera;
  if (group === "computers") return icons.computer;
  if (group === "mobile") return icons.mobile;
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
  if (device.group === "network") return "device-card--network";
  if (device.group === "cameras") return "device-card--cameras";
  if (device.group === "computers") return "device-card--computers";
  if (device.group === "mobile") return "device-card--mobile";
  return "device-card--unknown";
}

function isImportant(device) {
  const v = (device.vendor || "").toLowerCase();
  const n = (device.name || "").toLowerCase();
  return n.includes("nvr") || n.includes("camera") || v.includes("nvidia");
}

function renderDeviceCard(device) {
  const safeIp = escapeHtml(device.ip);
  const safeName = escapeHtml(device.name || "Unknown");
  const safeVendor = escapeHtml(device.vendor || "Unknown");
  const safeMac = escapeHtml(device.mac || "--");
  const openUrl = `http://${device.ip}`;
  const importantClass = isImportant(device) ? "device-card--important" : "";

  return `
    <article class="device-card ${deviceAccentClass(device)} ${importantClass}" data-search="${escapeHtml(device.searchable)}" data-ip="${safeIp}">
      <div class="device-card-top">
        <div class="device-icon">${iconForDevice(device)}</div>
        <div class="device-headline">
          <h3>${safeName}</h3>
          <p>${safeVendor}</p>
        </div>
        ${device.group === "network" ? '<span class="gateway-badge">Network</span>' : ''}
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
        <button type="button" class="mini-btn" data-action="rename" data-mac="${safeMac}">Rename</button>
        <button type="button" class="mini-btn" data-action="ping">Ping</button>
        <button type="button" class="mini-btn" data-action="open" data-url="${escapeHtml(openUrl)}">Open</button>
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
  const totalCameras = (data.cameras?.length || 0);

  totalDevicesStat.textContent = String(totalDevices);
  totalCamerasStat.textContent = String(totalCameras);
  onlineDevicesStat.textContent = String(totalDevices);
  lastScanStat.textContent = data.scan_time || "--";

  gatewayCount.textContent = String(data.network?.length || 0);
  camerasCount.textContent = String(data.cameras?.length || 0);
  computersCount.textContent = String(data.computers?.length || 0);
  mobileCount.textContent = String(data.mobile?.length || 0);
  unknownCount.textContent = String(data.unknown?.length || 0);
}

function renderAll() {
  const query = searchInput.value.trim().toLowerCase();

  const filteredNetwork = state.network.filter((d) => d.searchable.includes(query));
  const filteredCameras = state.cameras.filter((d) => d.searchable.includes(query));
  const filteredComputers = state.computers.filter((d) => d.searchable.includes(query));
  const filteredMobile = state.mobile.filter((d) => d.searchable.includes(query));
  const filteredUnknown = state.unknown.filter((d) => d.searchable.includes(query));

  updateSection(networkDevicesEl, filteredNetwork, "No network devices found.");
  updateSection(camerasDevicesEl, filteredCameras, "No cameras found.");
  updateSection(computersDevicesEl, filteredComputers, "No computers found.");
  updateSection(mobileDevicesEl, filteredMobile, "No mobile devices found.");
  updateSection(unknownDevicesEl, filteredUnknown, "No unknown devices found.");

  document.querySelectorAll(".category-card").forEach((card) => {
    const key = card.dataset.section;
    const hasItems =
      (key === "network" && filteredNetwork.length > 0) ||
      (key === "cameras" && filteredCameras.length > 0) ||
      (key === "computers" && filteredComputers.length > 0) ||
      (key === "mobile" && filteredMobile.length > 0) ||
      (key === "unknown" && filteredUnknown.length > 0);

    if (query) {
      card.open = hasItems;
    }
  });
}

function downloadPdf() {
  const location = prompt("Enter the Site Location for this scan report (e.g. 1st Floor Office, Home Network):", "Local Network");
  if (location !== null) {
    window.location.href = `/api/export.pdf?location=${encodeURIComponent(location)}`;
  }
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
      } else if (action === "rename") {
        const newName = prompt("Enter a friendly name for this device:");
        if (newName && newName.trim()) {
           try {
             await fetch("/api/rename", {
               method: "POST",
               headers: { "Content-Type": "application/json" },
               body: JSON.stringify({ mac: button.dataset.mac, name: newName.trim() })
             });
             scan();
           } catch(e) {
             alert("Error saving name");
           }
        }
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
    state.network = (data.network || []).map(normalizeDevice);
    state.cameras = (data.cameras || []).map(normalizeDevice);
    state.computers = (data.computers || []).map(normalizeDevice);
    state.mobile = (data.mobile || []).map(normalizeDevice);
    state.unknown = (data.unknown || []).map(normalizeDevice);
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
pdfBtn.addEventListener("click", downloadPdf);

setTheme(getTheme());
renderAll();
