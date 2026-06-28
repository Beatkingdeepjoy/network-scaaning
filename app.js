/* =========================================================
   NetSentry Scanner Console — App Logic
   Talks to the Flask API at API_BASE. Drives the radar sweep,
   live feed log, results grid, and host detail drawer.
========================================================= */

const API_BASE = "http://localhost:5000";

const el = {
  subnetInput:   document.getElementById("subnetInput"),
  scanBtn:       document.getElementById("scanBtn"),
  statusDot:     document.getElementById("statusDot"),
  statusText:    document.getElementById("statusText"),
  historyList:   document.getElementById("historyList"),
  sweepGroup:    document.getElementById("sweepGroup"),
  blipLayer:     document.getElementById("blipLayer"),
  liveHostCount: document.getElementById("liveHostCount"),
  feedLog:       document.getElementById("feedLog"),
  resultsGrid:   document.getElementById("resultsGrid"),
  resultsMeta:   document.getElementById("resultsMeta"),
  drawer:        document.getElementById("drawer"),
  drawerBackdrop:document.getElementById("drawerBackdrop"),
  drawerClose:   document.getElementById("drawerClose"),
  drawerContent: document.getElementById("drawerContent"),
};

let currentHosts = [];   // hosts from the most recently completed scan
let scanInFlight = false;

/* ---------------- Engine status check ---------------- */

async function checkEngineStatus(){
  try{
    const res = await fetch(`${API_BASE}/api/status`);
    const data = await res.json();
    el.statusDot.className = "status-dot " + (data.engine === "nmap" ? "online" : "fallback");
    el.statusText.textContent = data.engine === "nmap"
      ? "nmap engine ready"
      : "fallback engine (no nmap found)";
  }catch(err){
    el.statusDot.className = "status-dot";
    el.statusText.textContent = "API unreachable — is app.py running?";
  }
}

/* ---------------- Live feed helper ---------------- */

function logFeed(message, type = "info"){
  // type: info | found | error | idle
  const placeholder = el.feedLog.querySelector(".feed-line-idle");
  if (placeholder) placeholder.remove();

  const line = document.createElement("div");
  line.className = `feed-line feed-line-${type}`;
  const timestamp = new Date().toLocaleTimeString([], { hour12: false });
  line.textContent = `[${timestamp}] ${message}`;
  el.feedLog.appendChild(line);
  el.feedLog.scrollTop = el.feedLog.scrollHeight;
}

/* ---------------- Radar blip placement ---------------- */
/* Places discovered hosts at pseudo-random but stable positions
   around the radar rings, purely for visual effect — the real
   data lives in the results grid. */

function hashStringToFloat(str){
  let hash = 0;
  for (let i = 0; i < str.length; i++){
    hash = (hash << 5) - hash + str.charCodeAt(i);
    hash |= 0;
  }
  return Math.abs(hash % 1000) / 1000;
}

function placeBlip(ip, index){
  const angle = hashStringToFloat(ip + "a") * 2 * Math.PI;
  const radius = 50 + hashStringToFloat(ip + "r") * 130;
  const cx = 200 + radius * Math.cos(angle);
  const cy = 200 + radius * Math.sin(angle);

  const g = document.createElementNS("http://www.w3.org/2000/svg", "g");
  g.classList.add("blip");
  g.style.animationDelay = `${index * 0.08}s`;

  const ping = document.createElementNS("http://www.w3.org/2000/svg", "circle");
  ping.setAttribute("cx", cx);
  ping.setAttribute("cy", cy);
  ping.setAttribute("r", "4");
  ping.classList.add("blip-ping");
  ping.style.animationDelay = `${index * 0.08}s`;

  const core = document.createElementNS("http://www.w3.org/2000/svg", "circle");
  core.setAttribute("cx", cx);
  core.setAttribute("cy", cy);
  core.setAttribute("r", "3.5");
  core.classList.add("blip-core");

  g.appendChild(ping);
  g.appendChild(core);
  el.blipLayer.appendChild(g);
}

function clearBlips(){
  el.blipLayer.innerHTML = "";
}

function bumpReadout(value){
  el.liveHostCount.textContent = value;
  el.liveHostCount.classList.remove("bump");
  // restart animation
  requestAnimationFrame(() => el.liveHostCount.classList.add("bump"));
}

/* ---------------- Results grid rendering ---------------- */

function renderResultsGrid(hosts){
  el.resultsGrid.innerHTML = "";

  if (!hosts.length){
    el.resultsGrid.innerHTML = `
      <div class="empty-state">
        <svg viewBox="0 0 48 48" class="empty-icon" fill="none">
          <circle cx="24" cy="24" r="20" stroke="currentColor" stroke-width="1.5" opacity="0.3"/>
          <circle cx="24" cy="24" r="3" fill="currentColor" opacity="0.5"/>
        </svg>
        <p>No hosts responded on this range.<br>Try a different subnet.</p>
      </div>`;
    return;
  }

  hosts.forEach((host, i) => {
    const card = document.createElement("div");
    card.className = "host-card";
    card.style.animationDelay = `${i * 0.05}s`;
    card.tabIndex = 0;
    card.setAttribute("role", "button");

    const visiblePorts = host.ports.slice(0, 4);
    const extraCount = host.ports.length - visiblePorts.length;

    card.innerHTML = `
      <div class="host-card-top">
        <span class="host-ip">${host.ip}</span>
        <span class="host-status">UP</span>
      </div>
      <div class="host-hostname">${host.hostname || "no reverse dns"}</div>
      <div class="host-ports">
        ${visiblePorts.map(p => `<span class="port-chip">${p.port}/${p.service}</span>`).join("")}
        ${extraCount > 0 ? `<span class="port-chip port-chip-more">+${extraCount} more</span>` : ""}
        ${host.ports.length === 0 ? `<span class="port-chip port-chip-more">no open ports found</span>` : ""}
      </div>
    `;

    card.addEventListener("click", () => openDrawer(host));
    card.addEventListener("keypress", (e) => { if (e.key === "Enter") openDrawer(host); });

    el.resultsGrid.appendChild(card);
  });
}

/* ---------------- Host detail drawer ---------------- */

function openDrawer(host){
  el.drawerContent.innerHTML = `
    <h3 class="drawer-ip">${host.ip}</h3>
    <p class="drawer-hostname">${host.hostname || "no reverse DNS record"} · scanned ${new Date(host.scanned_at).toLocaleTimeString()}</p>

    <div class="drawer-section-title">Open ports (${host.ports.length})</div>
    ${
      host.ports.length
        ? host.ports.map(p => `
            <div class="drawer-port-row">
              <span class="drawer-port-num">${p.port}</span>
              <span class="drawer-port-service">${p.service || "unknown"}</span>
              <span class="drawer-port-version">${[p.product, p.version].filter(Boolean).join(" ")}</span>
            </div>
          `).join("")
        : `<div class="drawer-empty-ports">No open ports detected in the scanned range.</div>`
    }
  `;

  el.drawer.classList.add("open");
  el.drawerBackdrop.classList.add("open");
}

function closeDrawer(){
  el.drawer.classList.remove("open");
  el.drawerBackdrop.classList.remove("open");
}

el.drawerClose.addEventListener("click", closeDrawer);
el.drawerBackdrop.addEventListener("click", closeDrawer);
document.addEventListener("keydown", (e) => { if (e.key === "Escape") closeDrawer(); });

/* ---------------- History list ---------------- */

function addHistoryEntry(result){
  const empty = el.historyList.querySelector(".history-empty");
  if (empty) empty.remove();

  const li = document.createElement("li");
  li.className = "history-item";
  li.tabIndex = 0;
  li.innerHTML = `
    <div class="history-item-top">
      <span>${result.subnet}</span>
      <span>${result.host_count} up</span>
    </div>
    <div class="history-item-sub">${result.engine} · ${result.duration_seconds}s</div>
  `;
  li.addEventListener("click", () => {
    renderResultsGrid(result.hosts);
    el.resultsMeta.textContent = `${result.host_count} hosts · ${result.engine} engine`;
    clearBlips();
    result.hosts.forEach((h, i) => placeBlip(h.ip, i));
    bumpReadout(result.host_count);
  });

  el.historyList.prepend(li);
}

/* ---------------- Main scan flow ---------------- */

async function runScan(){
  if (scanInFlight) return;

  const subnet = el.subnetInput.value.trim();
  if (!subnet){
    logFeed("enter a subnet first, e.g. 192.168.1.0/24", "error");
    return;
  }

  scanInFlight = true;
  el.scanBtn.classList.add("scanning");
  el.scanBtn.disabled = true;
  el.sweepGroup.classList.add("active");

  clearBlips();
  bumpReadout(0);
  el.resultsMeta.textContent = "scanning\u2026";
  logFeed(`starting scan on ${subnet}`, "info");

  try{
    const res = await fetch(`${API_BASE}/api/scan`, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ subnet }),
    });

    const data = await res.json();

    if (!res.ok){
      logFeed(`scan failed: ${data.error || "unknown error"}`, "error");
      el.resultsMeta.textContent = "scan failed";
      return;
    }

    logFeed(`engine: ${data.engine} · duration: ${data.duration_seconds}s`, "info");

    currentHosts = data.hosts;

    // Animate hosts appearing one by one, synced with the feed + radar blips
    data.hosts.forEach((host, i) => {
      setTimeout(() => {
        logFeed(`host up: ${host.ip}${host.hostname ? " (" + host.hostname + ")" : ""} — ${host.ports.length} open port${host.ports.length === 1 ? "" : "s"}`, "found");
        placeBlip(host.ip, i);
        bumpReadout(i + 1);
      }, i * 180);
    });

    setTimeout(() => {
      renderResultsGrid(data.hosts);
      el.resultsMeta.textContent = `${data.host_count} hosts · ${data.engine} engine`;
      addHistoryEntry(data);
      logFeed(`scan complete — ${data.host_count} host(s) up`, "info");
    }, data.hosts.length * 180 + 200);

  }catch(err){
    logFeed(`could not reach scanner API — is app.py running on :5000?`, "error");
    el.resultsMeta.textContent = "API unreachable";
  }finally{
    setTimeout(() => {
      el.scanBtn.classList.remove("scanning");
      el.scanBtn.disabled = false;
      el.sweepGroup.classList.remove("active");
      scanInFlight = false;
    }, (currentHosts.length * 180) + 400);
  }
}

el.scanBtn.addEventListener("click", runScan);
el.subnetInput.addEventListener("keypress", (e) => { if (e.key === "Enter") runScan(); });

/* ---------------- Init ---------------- */

checkEngineStatus();
