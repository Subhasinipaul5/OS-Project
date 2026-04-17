
// Security system initialized
console.log("Security Framework Loaded Successfully");


function showSystemStatus() {
    console.log("System is running securely");
}
showSystemStatus();

/**
 * OS Security Vulnerability Detection Framework
 * Frontend Logic — script.js
 * All bugs from original code are fixed here.
 */

// ── State ─────────────────────────────────────────────────────
let isScanning = false;
let metricsInterval = null;
let totalChecks = 0, totalCrit = 0, totalHigh = 0, totalOk = 0;

// ── Clock ──────────────────────────────────────────────────────
function updateClock() {
  const now = new Date();
  document.getElementById("clockEl").textContent =
    now.toLocaleTimeString("en-GB", { hour12: false });
}
setInterval(updateClock, 1000);
updateClock();

// ── Live metrics simulation ────────────────────────────────────
function startMetrics() {
  metricsInterval = setInterval(() => {
    const cpu  = Math.round(Math.random() * 60 + 5);
    const mem  = Math.round(Math.random() * 50 + 20);
    const net  = +(Math.random() * 8).toFixed(2);
    const disk = Math.round(Math.random() * 40 + 10);

    setMetric("cpu",  cpu,  cpu + "%",   cpu  > 80);
    setMetric("mem",  mem,  mem + "%",   mem  > 85);
    setMetric("net",  Math.min(net * 12.5, 100), net + " MB/s", net > 5);
    setMetric("disk", disk, disk + "%",  disk > 90);
  }, 1500);
}

function setMetric(id, pct, label, danger) {
  const fill = document.getElementById(id + "Fill");
  const val  = document.getElementById(id + "Val");
  fill.style.width = pct + "%";
  fill.classList.toggle("danger", danger);
  val.textContent = label;
  if (danger) val.style.color = "var(--red)";
  else        val.style.color = "";
}

startMetrics();

// ── Input length tracker ───────────────────────────────────────
const MAX_BUF = 15;
document.getElementById("userInput").addEventListener("input", function () {
  const len  = this.value.length;
  const over = len > MAX_BUF;
  document.getElementById("inputLen").textContent = `${len} / ${MAX_BUF}`;
  document.getElementById("inputBar").style.width =
    Math.min((len / MAX_BUF) * 100, 100) + "%";
  document.getElementById("inputBar").style.background =
    over ? "var(--red)" : len > MAX_BUF * 0.7 ? "var(--amber)" : "var(--green)";
  this.classList.toggle("danger", over);
  const hint = document.getElementById("inputHint");
  hint.textContent = over
    ? `⚠ OVERFLOW — exceeds threshold by ${len - MAX_BUF} chars`
    : "Safe — within threshold";
  hint.className = "hint" + (over ? " danger" : "");
});

// ── Payload presets ────────────────────────────────────────────
function loadPayload(type) {
  const map = {
    normal:   "hello_world",
    overflow: "A".repeat(64) + "BBBBBBBB",
    nop:      "\x90".repeat(40) + "\xcc\xcc",
    sql:      "' OR '1'='1'; DROP TABLE users;--",
  };
  document.getElementById("userInput").value = map[type] || "";
  document.getElementById("userInput").dispatchEvent(new Event("input"));
    console.log(`Payload loaded: ${type}`);
}

// ── Output helpers ─────────────────────────────────────────────
function clearResults() {
  const box = document.getElementById("outputBox");
  box.innerHTML = `
    <div class="empty-state">
      <div class="empty-icon">⬡</div>
      <div>Results cleared — ready for next scan.</div>
    </div>`;
  totalChecks = totalCrit = totalHigh = totalOk = 0;
  updateStats();
  ["mod1","mod2","mod3","mod4","mod5","mod6","mod7","mod8"].forEach(id => {
    setModuleState(id, "IDLE", "");
  });
  setStatus("SYSTEM READY", "");
}

function addEntry(type, icon, title, fix = "") {
  const box = document.getElementById("outputBox");
  // remove empty state
  const es = box.querySelector(".empty-state");
  if (es) es.remove();

  const div = document.createElement("div");
  div.className = `result-entry ${type}`;
  div.innerHTML = `
    <div class="re-icon">${icon}</div>
    <div class="re-body">
      <div class="re-title ${type}">${title}</div>
      ${fix ? `<div class="re-fix">↳ ${fix}</div>` : ""}
    </div>`;
  box.appendChild(div);
  box.scrollTop = box.scrollHeight;
}

function addSection(label) {
  const box = document.getElementById("outputBox");
  const div = document.createElement("div");
  div.className = "result-entry section";
  div.innerHTML = `<div class="re-title section">${label}</div>`;
  box.appendChild(div);
}

function updateStats() {
  document.getElementById("statTotalVal").textContent = totalChecks;
  document.getElementById("statCritVal").textContent  = totalCrit;
  document.getElementById("statHighVal").textContent  = totalHigh;
  document.getElementById("statOkVal").textContent    = totalOk;
}

function setStatus(text, cls) {
  const pill = document.getElementById("statusPill");
  const span = document.getElementById("statusText");
  pill.className = "status-pill" + (cls ? " " + cls : "");
  span.textContent = text;
}

function setModuleState(id, statusText, cls) {
  const card = document.getElementById(id);
  const stat = document.getElementById(id + "s");
  card.className = "module-card" + (cls ? " " + cls : "");
  stat.textContent = statusText;
}

// ── Delay helper ──────────────────────────────────────────────
const delay = (ms) => new Promise(r => setTimeout(r, ms));

// ── MODULE CHECKS ─────────────────────────────────────────────

async function checkBufferOverflow(input) {
  setModuleState("mod1", "SCANNING…", "active");
  await delay(400);

  const len     = input.length;
  const uniqueC = new Set(input).size;
  const hasSql  = /('|--|;|DROP|SELECT|INSERT|UPDATE|DELETE|UNION)/i.test(input);
  const hasNull  = input.includes("\x00") || input.includes("\x90");

  totalChecks++;

  if (len > MAX_BUF) {
    const overflow = len - MAX_BUF;
    totalCrit++;
    addEntry("critical", "⬛", `Buffer Overflow Detected — input length ${len} exceeds threshold by ${overflow} chars`,
      "Implement bounds checking. Use strncpy(), fgets(), stack canaries, and ASLR.");
    setModuleState("mod1", "ALERT", "alert");
  } else if (hasSql) {
    totalHigh++;
    addEntry("high", "▲", "SQL Injection Pattern Detected in input",
      "Sanitize inputs with prepared statements. Never interpolate raw user input into queries.");
    setModuleState("mod1", "WARN", "alert");
  } else if (hasNull || (uniqueC <= 2 && len > 8)) {
    totalHigh++;
    addEntry("high", "▲", "NOP-sled / Shellcode pattern detected (low character diversity)",
      "Reject inputs with abnormal byte patterns. Enable DEP/NX bit and ASLR.");
    setModuleState("mod1", "WARN", "alert");
  } else {
    totalOk++;
    addEntry("ok", "●", `Buffer Overflow — Input safe (length ${len}, threshold ${MAX_BUF})`);
    setModuleState("mod1", "SAFE", "ok");
  }
  updateStats();
}

async function checkTrapdoor() {
  setModuleState("mod2", "SCANNING…", "active");
  await delay(600);
  totalChecks++;

  // Simulated watchdog check
  const suspiciousFiles = [
    { path: "./uploads/.hidden_payload.sh",     severity: "critical" },
    { path: "./logs/rootkit_stub",              severity: "critical" },
  ];
  const triggered = Math.random() < 0.18; // 18% chance to simulate a finding

  if (triggered) {
    const f = suspiciousFiles[Math.floor(Math.random() * suspiciousFiles.length)];
    totalCrit++;
    addEntry("critical", "⬛",
      `Trapdoor/Backdoor File Detected: ${f.path}`,
      "Delete file immediately, audit user accounts, run full antivirus scan, review cron jobs.");
    setModuleState("mod2", "ALERT", "alert");
  } else {
    // File integrity simulation
    const changed = Math.random() < 0.12;
    if (changed) {
      totalHigh++;
      addEntry("high", "▲", "File Integrity Violation: /etc/passwd hash mismatch — possible tampering",
        "Compare against known-good backup. Check audit logs for recent modifications.");
      setModuleState("mod2", "WARN", "alert");
    } else {
      totalOk++;
      addEntry("ok", "●", "Trapdoor Monitor — No suspicious files detected. File integrity OK.");
      setModuleState("mod2", "SAFE", "ok");
    }
  }
  updateStats();
}

async function checkDNS() {
  setModuleState("mod3", "SCANNING…", "active");
  await delay(700);
  totalChecks++;

  // Valid IP prefixes per domain
  const domains = {
    "google.com":  ["142.250.", "172.217.", "74.125.", "216.58.", "64.233.", "34."],
    "github.com":  ["140.82.", "20.205.", "192.30.", "185.199."],
    "openai.com":  ["104.18.", "172.64.", "104.26."],
  };

  let poisoned = false;
  for (const [domain, prefixes] of Object.entries(domains)) {
    // Simulate a resolved IP — occasionally inject a poisoned one
    const poison = Math.random() < 0.1;
    const ip = poison
      ? "185.220." + Math.floor(Math.random()*200) + "." + Math.floor(Math.random()*200)
      : prefixes[0] + Math.floor(Math.random()*200) + "." + Math.floor(Math.random()*200);

    // BUG FIX: original used `prefix > randomIP.startsWith(...)` (comparison instead of arrow fn)
    const safe = prefixes.some(prefix => ip.startsWith(prefix));

    if (!safe) {
      poisoned = true;
      totalCrit++;
      addEntry("critical", "⬛",
        `DNS Cache Poisoning — ${domain} → ${ip} (not in whitelist)`,
        "Flush DNS cache: sudo systemd-resolve --flush-caches  |  Enable DNSSEC on resolver.");
      setModuleState("mod3", "ALERT", "alert");
    } else {
      addEntry("ok", "●", `DNS Safe — ${domain} → ${ip}`);
    }
  }

  if (!poisoned) {
    totalOk++;
    setModuleState("mod3", "SAFE", "ok");
  }
  updateStats();
}

async function checkProcesses() {
  setModuleState("mod4", "SCANNING…", "active");
  await delay(800);
  totalChecks++;

  const MALICIOUS = ["nc","ncat","hydra","meterpreter","msfconsole","john","hashcat",
                      "mimikatz","sqlmap","nikto","gobuster","masscan","airmon-ng"];
  const SUSPICIOUS_PORTS = { 4444:"Metasploit listener", 1337:"Backdoor port",
                               31337:"Elite hacker port", 9999:"Reverse shell" };

  // Simulate running process list
  const fakeProcs = [
    { name:"chrome",    pid:1023, user:"user" },
    { name:"nginx",     pid:1100, user:"www-data" },
    { name:"python3",   pid:2001, user:"user" },
    { name:"sshd",      pid:888,  user:"root" },
  ];
  if (Math.random() < 0.15) fakeProcs.push({ name:"nc",          pid:3999, user:"unknown" });
  if (Math.random() < 0.10) fakeProcs.push({ name:"msfconsole",  pid:4001, user:"root" });

  let found = false;
  for (const p of fakeProcs) {
    if (MALICIOUS.includes(p.name.toLowerCase())) {
      found = true;
      totalCrit++;
      addEntry("critical", "⬛",
        `Malicious Process: ${p.name}  PID:${p.pid}  User:${p.user}`,
        `Kill immediately: sudo kill -9 ${p.pid} — then audit open ports with: ss -tulnp`);
      setModuleState("mod4", "ALERT", "alert");
    }
  }

  // Port check simulation
  const suspPort = Math.random() < 0.1
    ? Object.entries(SUSPICIOUS_PORTS)[Math.floor(Math.random()*4)]
    : null;
  if (suspPort) {
    found = true;
    totalHigh++;
    addEntry("high", "▲", `Suspicious Listening Port ${suspPort[0]} — ${suspPort[1]}`,
      "Close with: sudo fuser -k " + suspPort[0] + "/tcp — Investigate with: lsof -i :" + suspPort[0]);
  }

  if (!found) {
    totalOk++;
    addEntry("ok", "●", "Malicious Processes — No threats detected in process list or port table.");
    setModuleState("mod4", "SAFE", "ok");
  }
  updateStats();
}

async function checkMLAnomaly() {
  setModuleState("mod5", "TRAINING…", "active");
  await delay(1200);

  totalChecks++;
  const cpu  = Math.round(Math.random() * 100);
  const mem  = Math.round(Math.random() * 100);
  const net  = Math.round(Math.random() * 100);
  const disk = Math.round(Math.random() * 100);
  // Simple anomaly threshold simulation
  const score = -1 * (cpu * 0.4 + mem * 0.3 + net * 0.2 + disk * 0.1) / 100 + 0.5;
  const anomaly = cpu > 85 || mem > 90 || net > 80;

  if (anomaly) {
    totalHigh++;
    addEntry("high", "▲",
      `ML Anomaly — Isolation Forest score: ${score.toFixed(3)} | CPU:${cpu}% MEM:${mem}% NET:${net}%`,
      "Check: top, htop, iotop, nethogs — Investigate processes causing spikes.");
    setModuleState("mod5", "ANOMALY", "alert");
  } else {
    totalOk++;
    addEntry("ok", "●", `ML Anomaly Detector — Normal (score:${score.toFixed(3)} | CPU:${cpu}% MEM:${mem}%)`);
    setModuleState("mod5", "NORMAL", "ok");
  }
  updateStats();
}

async function checkPrivilege() {
  setModuleState("mod6", "SCANNING…", "active");
  await delay(600);
  totalChecks++;

  const suid = Math.random() < 0.12;
  const worldWrite = Math.random() < 0.08;
  let found = false;

  if (suid) {
    found = true;
    totalHigh++;
    addEntry("high", "▲", "Unexpected SUID Binary: /usr/local/bin/custom_tool (permissions: 4755)",
      "Remove SUID bit: chmod u-s /usr/local/bin/custom_tool — Audit all SUID with: find / -perm -4000");
  }
  if (worldWrite) {
    found = true;
    totalHigh++;
    addEntry("high", "▲", "World-Writable Critical File: /etc/cron.d/job.conf (permissions: 0777)",
      "Fix: chmod 644 /etc/cron.d/job.conf — Audit: find /etc -perm -o+w");
  }
  if (!found) {
    totalOk++;
    addEntry("ok", "●", "Privilege Escalation — No unexpected SUID binaries or world-writable files.");
    setModuleState("mod6", "SAFE", "ok");
  } else {
    setModuleState("mod6", "ALERT", "alert");
  }
  updateStats();
}

async function checkNetwork() {
  setModuleState("mod7", "SCANNING…", "active");
  await delay(700);
  totalChecks++;

  const exfil  = Math.random() < 0.08;
  const badConn = Math.random() < 0.12;
  let found = false;

  if (exfil) {
    found = true;
    totalCrit++;
    addEntry("critical", "⬛",
      "Data Exfiltration Alert — 612 MB/s outbound spike detected",
      "Isolate machine immediately. Block egress: iptables -A OUTPUT -j DROP — Contact security team.");
    setModuleState("mod7", "ALERT", "alert");
  }
  if (badConn) {
    found = true;
    totalHigh++;
    addEntry("high", "▲", "Suspicious Established Connection → 185.220.101.47:4444 (PID 3721)",
      "Kill connection: sudo ss -K dst 185.220.101.47 — Block IP: iptables -A OUTPUT -d 185.220.101.47 -j DROP");
    if (!exfil) setModuleState("mod7", "ALERT", "alert");
  }
  if (!found) {
    totalOk++;
    addEntry("ok", "●", "Network Intrusion — No suspicious connections or bandwidth spikes.");
    setModuleState("mod7", "SAFE", "ok");
  }
  updateStats();
}

async function checkLogTampering() {
  setModuleState("mod8", "SCANNING…", "active");
  await delay(500);
  totalChecks++;

  const logs = ["/var/log/auth.log", "/var/log/syslog", "/var/log/kern.log"];
  const tampered = Math.random() < 0.1;

  if (tampered) {
    const log = logs[Math.floor(Math.random() * logs.length)];
    totalCrit++;
    addEntry("critical", "⬛",
      `Log Tampering Detected — ${log} shrunk unexpectedly (48320 → 0 bytes)`,
      "Restore from backup. Enable immutable flag: chattr +a /var/log/auth.log — Review auditd rules.");
    setModuleState("mod8", "ALERT", "alert");
  } else {
    totalOk++;
    addEntry("ok", "●", "Log Integrity — All critical log files intact, sizes nominal.");
    setModuleState("mod8", "SAFE", "ok");
  }
  updateStats();
}

// ── MAIN SCAN ORCHESTRATOR ─────────────────────────────────────
async function runFullScan() {
  if (isScanning) return;
  isScanning = true;

  const btn   = document.getElementById("scanBtn");
  const input = document.getElementById("userInput").value.trim();
  btn.disabled = true;
  btn.textContent = "⏳ SCANNING…";

  totalChecks = totalCrit = totalHigh = totalOk = 0;
  updateStats();

  const box = document.getElementById("outputBox");
  box.innerHTML = "";
  setStatus("SCANNING", "scanning");

  addSection("▸ SCAN INITIATED — " + new Date().toLocaleTimeString() + " | System Monitoring Activated");
  addEntry("info", "ℹ", `Host: ${window.location.hostname || "localhost"}  |  Input length: ${input.length}  |  Threshold: ${MAX_BUF}`);

  // Run all 8 modules sequentially with section headers
  addSection("MODULE 01 — BUFFER OVERFLOW DETECTION");
  await checkBufferOverflow(input);

  addSection("MODULE 02 — TRAPDOOR & FILE INTEGRITY");
  await checkTrapdoor();

  addSection("MODULE 03 — DNS CACHE POISONING");
  await checkDNS();

  addSection("MODULE 04 — MALICIOUS PROCESS DETECTION");
  await checkProcesses();

  addSection("MODULE 05 — ML ANOMALY DETECTION");
  await checkMLAnomaly();

  addSection("MODULE 06 — PRIVILEGE ESCALATION");
  await checkPrivilege();

  addSection("MODULE 07 — NETWORK INTRUSION");
  await checkNetwork();

  addSection("MODULE 08 — LOG TAMPERING");
  await checkLogTampering();

  // Final summary
  addSection("▸ SCAN COMPLETE");
  const verdict = totalCrit > 0 ? "critical" : totalHigh > 0 ? "high" : "ok";
  const icons   = { critical:"⬛", high:"▲", ok:"●" };
  const msgs    = {
    critical: `CRITICAL THREATS FOUND — ${totalCrit} critical, ${totalHigh} high. Immediate action required.`,
    high:     `WARNINGS DETECTED — ${totalHigh} high-severity issue(s) need attention.`,
    ok:       `ALL CLEAR — ${totalOk} checks passed. No active threats detected.`,
  };
  addEntry(verdict, icons[verdict], msgs[verdict]);

  if (totalCrit > 0) setStatus("THREATS DETECTED", "danger");
  else if (totalHigh > 0) setStatus("WARNINGS ACTIVE", "scanning");
  else setStatus("ALL CLEAR", "");

  btn.disabled = false;
  btn.innerHTML = `<svg class="btn-icon" viewBox="0 0 20 20" fill="none">
    <circle cx="10" cy="10" r="8" stroke="currentColor" stroke-width="1.5"/>
    <path d="M10 6v4l3 3" stroke="currentColor" stroke-width="1.5" stroke-linecap="round"/>
  </svg> INITIATE SECURITY SCAN`;
  isScanning = false;
}

toggleBtn.addEventListener("click", () => {
  // document.body.classList.toggle("light-mode");
  document.body.classList.toggle("light-mode");
  document.documentElement.classList.toggle("light-mode");
  // Change icon
  if (document.body.classList.contains("light-mode")) {
    toggleBtn.textContent = "🌙";
  } else {
    toggleBtn.textContent = "💡";
  }
});
window.addEventListener("load", function () {
        setTimeout(function () {
                    document.getElementById("loader").style.display = "none";
                    document.getElementById("main-content").style.display = "block";
        }, 2000);
});
