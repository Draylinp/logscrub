// LogScrub · lógica de la interfaz
// Nada de lo que se pega aquí sale del navegador: no hay peticiones de red
// (la CSP de index.html las bloquea) y el texto no se guarda en ningún sitio.
(function () {
  "use strict";

  const { scrub, CATEGORIES } = window.LogScrub;

  const SETTINGS_KEY = "logscrub.settings.v1";
  const MAX_HIGHLIGHTS = 5000; // por encima se muestra texto plano para no frenar el navegador
  const MAX_TABLE_ROWS = 1000;
  const MAX_FILE_MB = 50;

  const $ = (id) => document.getElementById(id);
  const el = {
    categories: $("categories"),
    keepPrivate: $("keepPrivate"),
    keepSpecial: $("keepSpecial"),
    input: $("input"),
    output: $("output"),
    status: $("status"),
    stats: $("stats"),
    replacements: $("replacements"),
    replacementsCount: $("replacementsCount"),
    customRules: $("customRules"),
    allowlist: $("allowlist"),
    ruleErrors: $("ruleErrors"),
    btnSample: $("btnSample"),
    btnOpen: $("btnOpen"),
    btnClear: $("btnClear"),
    btnCopy: $("btnCopy"),
    btnDownload: $("btnDownload"),
    fileInput: $("fileInput"),
    dropOverlay: $("dropOverlay"),
  };

  let lastResult = null;
  let fileName = null;
  let timer = null;

  // ---------- Ajustes (solo preferencias, nunca el texto) ----------

  function loadSettings() {
    try {
      return JSON.parse(localStorage.getItem(SETTINGS_KEY)) || {};
    } catch {
      return {};
    }
  }

  function saveSettings() {
    try {
      localStorage.setItem(SETTINGS_KEY, JSON.stringify(currentOptions()));
    } catch {
      // modo privado o almacenamiento bloqueado: los ajustes no se recuerdan
    }
  }

  function currentOptions() {
    const categories = {};
    el.categories.querySelectorAll("input").forEach((cb) => {
      categories[cb.value] = cb.checked;
    });
    return {
      categories,
      keepPrivate: el.keepPrivate.checked,
      keepSpecial: el.keepSpecial.checked,
      customRules: el.customRules.value,
      allowlist: el.allowlist.value,
    };
  }

  function renderCategories(saved) {
    for (const [id, cat] of Object.entries(CATEGORIES)) {
      const label = document.createElement("label");
      label.className = "chip";
      const cb = document.createElement("input");
      cb.type = "checkbox";
      cb.value = id;
      cb.checked = !saved.categories || saved.categories[id] !== false;
      label.append(cb, " " + cat.label);
      el.categories.append(label);
    }
  }

  function applySettings(saved) {
    if (typeof saved.keepPrivate === "boolean") el.keepPrivate.checked = saved.keepPrivate;
    if (typeof saved.keepSpecial === "boolean") el.keepSpecial.checked = saved.keepSpecial;
    if (typeof saved.customRules === "string") el.customRules.value = saved.customRules;
    if (typeof saved.allowlist === "string") el.allowlist.value = saved.allowlist;
  }

  // ---------- Limpieza y renderizado ----------

  function run() {
    clearTimeout(timer);
    const text = el.input.value;
    const t0 = performance.now();
    const result = scrub(text, currentOptions());
    const ms = Math.round(performance.now() - t0);
    lastResult = text ? result : null;

    renderOutput(text, result);
    renderStats(result);
    renderReplacements(result);
    renderRuleErrors(result.errors);

    el.btnCopy.disabled = el.btnDownload.disabled = !text;
    if (!text) {
      setStatus("");
    } else if (result.findings.length === 0) {
      setStatus("No se encontraron datos sensibles. Revisa el texto de todos modos.");
    } else {
      const n = result.findings.length;
      const u = result.replacements.length;
      setStatus(`${n} ${n === 1 ? "valor reemplazado" : "valores reemplazados"} (${u} ${u === 1 ? "único" : "únicos"}) en ${ms} ms.`);
    }
  }

  function schedule() {
    clearTimeout(timer);
    timer = setTimeout(run, el.input.value.length > 200000 ? 400 : 120);
  }

  function renderOutput(text, result) {
    const out = el.output;
    out.textContent = "";
    if (!text) return;
    if (result.findings.length > MAX_HIGHLIGHTS) {
      out.textContent = result.output;
      return;
    }
    // Se construye con nodos de texto (nunca innerHTML) para que el contenido
    // del log no pueda inyectar HTML en la página.
    const frag = document.createDocumentFragment();
    let pos = 0;
    for (const f of result.findings) {
      if (f.start > pos) frag.append(text.slice(pos, f.start));
      const mark = document.createElement("mark");
      mark.textContent = f.placeholder;
      mark.title = CATEGORIES[f.category] ? CATEGORIES[f.category].label : "Regla personalizada";
      frag.append(mark);
      pos = f.end;
    }
    if (pos < text.length) frag.append(text.slice(pos));
    out.append(frag);
  }

  function renderStats(result) {
    el.stats.textContent = "";
    for (const [cat, count] of Object.entries(result.stats)) {
      const chip = document.createElement("span");
      chip.className = "chip";
      const strong = document.createElement("strong");
      strong.textContent = count;
      const name = CATEGORIES[cat] ? CATEGORIES[cat].label : "Personalizadas";
      chip.append(strong, " " + name);
      el.stats.append(chip);
    }
  }

  function renderReplacements(result) {
    el.replacements.textContent = "";
    const rows = result.replacements;
    el.replacementsCount.textContent = rows.length ? `(${rows.length})` : "";
    const frag = document.createDocumentFragment();
    for (const r of rows.slice(0, MAX_TABLE_ROWS)) {
      const tr = document.createElement("tr");
      const label = CATEGORIES[r.category] ? CATEGORIES[r.category].label : "Personalizada";
      for (const value of [r.placeholder, r.original, label, r.count]) {
        const td = document.createElement("td");
        td.textContent = value;
        tr.append(td);
      }
      frag.append(tr);
    }
    if (rows.length > MAX_TABLE_ROWS) {
      const tr = document.createElement("tr");
      const td = document.createElement("td");
      td.colSpan = 4;
      td.className = "muted";
      td.textContent = `… y ${rows.length - MAX_TABLE_ROWS} más.`;
      tr.append(td);
      frag.append(tr);
    }
    el.replacements.append(frag);
  }

  function renderRuleErrors(errors) {
    el.ruleErrors.textContent = "";
    for (const e of errors) {
      const li = document.createElement("li");
      li.textContent = `Línea ${e.line}: ${e.message}`;
      el.ruleErrors.append(li);
    }
  }

  function setStatus(msg) {
    el.status.textContent = msg;
  }

  // ---------- Acciones ----------

  async function copyOutput() {
    if (!lastResult) return;
    const text = lastResult.output;
    try {
      await navigator.clipboard.writeText(text);
    } catch {
      const ta = document.createElement("textarea");
      ta.value = text;
      ta.style.position = "fixed";
      ta.style.opacity = "0";
      document.body.append(ta);
      ta.select();
      document.execCommand("copy");
      ta.remove();
    }
    flash(el.btnCopy, "¡Copiado!");
  }

  function downloadOutput() {
    if (!lastResult) return;
    const base = fileName ? fileName.replace(/\.[^.]+$/, "") : "logscrub";
    const ext = fileName && /\.[^.]+$/.test(fileName) ? fileName.match(/\.[^.]+$/)[0] : ".txt";
    const blob = new Blob([lastResult.output], { type: "text/plain;charset=utf-8" });
    const url = URL.createObjectURL(blob);
    const a = document.createElement("a");
    a.href = url;
    a.download = `${base}.scrubbed${ext}`;
    document.body.append(a);
    a.click();
    a.remove();
    setTimeout(() => URL.revokeObjectURL(url), 1000);
  }

  function flash(button, text) {
    const original = button.textContent;
    button.textContent = text;
    setTimeout(() => (button.textContent = original), 1500);
  }

  function loadFile(file) {
    if (!file) return;
    if (file.size > MAX_FILE_MB * 1024 * 1024) {
      setStatus(`El archivo pesa más de ${MAX_FILE_MB} MB. Divídelo en partes más pequeñas.`);
      return;
    }
    const reader = new FileReader();
    reader.onload = () => {
      fileName = file.name;
      el.input.value = reader.result;
      run();
    };
    reader.onerror = () => setStatus("No se pudo leer el archivo.");
    reader.readAsText(file);
  }

  function clearAll() {
    el.input.value = "";
    fileName = null;
    run();
    el.input.focus();
  }

  // Valores de ejemplo: IPs de documentación (RFC 5737/3849), dominios example.com
  // y tokens falsos armados por partes para no disparar escáneres de secretos.
  function sampleText() {
    const jwt = "eyJ" + "hbGciOiJIUzI1NiJ9.eyJ" + "zdWIiOiIxMjM0NTY3ODkwIn0.dBjftJeZ4CVPmB92K27uhbUJU1p1r_wW1gFWFOEjXk";
    const gh = "gh" + "p_" + "R4nd0mT0k3nV4lu3F0rD3m0Purp0s3s0nly1";
    return [
      "# --- syslog / sshd ---",
      "Oct  5 10:21:33 web-prod-01 sshd[2211]: Failed password for invalid user admin from 203.0.113.45 port 52144 ssh2",
      "Oct  5 10:21:40 web-prod-01 sshd[2211]: Accepted publickey for jperez from 198.51.100.23 port 50122 ssh2",
      "",
      "# --- nginx ---",
      '203.0.113.45 - - [05/Oct/2026:10:22:01 +0000] "GET /api/v1/users?token=9f8e7d6c5b4a3210 HTTP/1.1" 401 512 "-" "curl/8.4.0"',
      "",
      "# --- aplicación ---",
      "2026-10-05T10:22:05Z ERROR db connection failed: postgres://app_user:S3cr3tP4ss@db01.internal.example.com:5432/orders",
      "2026-10-05T10:22:06Z WARN  notify failed for maria.lopez@example.com via smtp.example.com",
      `Authorization: Bearer ${jwt}`,
      `GITHUB_TOKEN=${gh}`,
      "aws_access_key_id = AKIAIOSFODNN7EXAMPLE",
      "",
      "# --- MikroTik ---",
      "/system identity set name=MK-Oficina-Central",
      "/ip address add address=192.168.88.1/24 interface=bridge",
      '/interface wireless security-profiles set default authentication-types=wpa2-psk wpa2-pre-shared-key="ClaveWifi2026!"',
      "/interface ethernet set [ find default-name=ether1 ] mac-address=4C:5E:0C:12:AB:CD",
      "",
      "# --- Cisco IOS ---",
      "hostname R1-Sucursal",
      "enable secret 5 $1$mERr$hx5rVt7rPNoS4wqbXKX7m0",
      "username soporte privilege 15 secret 0 Cisco#2026",
      "interface GigabitEthernet0/0",
      " ip address 198.51.100.2 255.255.255.252",
      " mac-address 001a.2b3c.4d5e",
      "snmp-server community empresa-ro RO",
      "access-list 10 permit 10.10.0.0 0.0.255.255",
      "",
      "# --- FortiGate ---",
      "config vpn ipsec phase1-interface",
      '    edit "vpn-sucursal"',
      "        set remote-gw 203.0.113.200",
      "        set psksecret ENC kP9vR2xT6yL0bM4nQ8sW",
      "    next",
      "end",
      "",
      "# --- IPv6 ---",
      "neighbor 2001:db8:85a3::8a2e:370:7334 reachable via fe80::1%eth0",
    ].join("\n");
  }

  // ---------- Eventos ----------

  function init() {
    const saved = loadSettings();
    renderCategories(saved);
    applySettings(saved);

    el.input.addEventListener("input", () => {
      fileName = null;
      schedule();
    });

    const onOptionsChange = () => {
      saveSettings();
      schedule();
    };
    el.categories.addEventListener("change", onOptionsChange);
    el.keepPrivate.addEventListener("change", onOptionsChange);
    el.keepSpecial.addEventListener("change", onOptionsChange);
    el.customRules.addEventListener("input", onOptionsChange);
    el.allowlist.addEventListener("input", onOptionsChange);

    el.btnSample.addEventListener("click", () => {
      el.input.value = sampleText();
      fileName = null;
      run();
    });
    el.btnOpen.addEventListener("click", () => el.fileInput.click());
    el.fileInput.addEventListener("change", () => {
      loadFile(el.fileInput.files[0]);
      el.fileInput.value = "";
    });
    el.btnClear.addEventListener("click", clearAll);
    el.btnCopy.addEventListener("click", copyOutput);
    el.btnDownload.addEventListener("click", downloadOutput);

    // Arrastrar y soltar en cualquier parte de la página
    let dragDepth = 0;
    const hasFiles = (e) => e.dataTransfer && [...e.dataTransfer.types].includes("Files");
    document.addEventListener("dragenter", (e) => {
      if (!hasFiles(e)) return;
      dragDepth++;
      el.dropOverlay.hidden = false;
    });
    document.addEventListener("dragleave", () => {
      dragDepth = Math.max(0, dragDepth - 1);
      if (dragDepth === 0) el.dropOverlay.hidden = true;
    });
    document.addEventListener("dragover", (e) => {
      if (hasFiles(e)) e.preventDefault();
    });
    document.addEventListener("drop", (e) => {
      if (!hasFiles(e)) return;
      e.preventDefault();
      dragDepth = 0;
      el.dropOverlay.hidden = true;
      loadFile(e.dataTransfer.files[0]);
    });

    // Ctrl+Enter: limpiar y copiar
    el.input.addEventListener("keydown", (e) => {
      if (e.key === "Enter" && (e.ctrlKey || e.metaKey)) {
        e.preventDefault();
        run();
        copyOutput();
      }
    });

    run();
  }

  init();
})();
