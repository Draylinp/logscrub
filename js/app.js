// LogScrub · lógica de la interfaz
// Nada de lo que se pega aquí sale del navegador: no hay peticiones de red
// (la CSP de index.html las bloquea) y el texto no se guarda en ningún sitio.
(function () {
  "use strict";

  const { scrub, restore, CATEGORIES } = window.LogScrub;
  const I18N = window.LogScrubI18n;

  const SETTINGS_KEY = "logscrub.settings.v1";
  const LANG_KEY = "logscrub.lang";
  const THEME_KEY = "logscrub.theme";
  const THEMES = ["auto", "light", "dark"];
  const THEME_ICONS = { auto: "🖥️", light: "☀️", dark: "🌙" };
  const MAX_HIGHLIGHTS = 5000; // por encima se muestra texto plano para no frenar el navegador
  const MAX_TABLE_ROWS = 1000;
  const MAX_FILE_MB = 50;

  const $ = (id) => document.getElementById(id);
  const el = {
    categories: $("categories"),
    keepPrivate: $("keepPrivate"),
    keepSpecial: $("keepSpecial"),
    format: $("format"),
    input: $("input"),
    output: $("output"),
    status: $("status"),
    stats: $("stats"),
    replacements: $("replacements"),
    replacementsCount: $("replacementsCount"),
    customRules: $("customRules"),
    allowlist: $("allowlist"),
    ruleErrors: $("ruleErrors"),
    restoreInput: $("restoreInput"),
    restoreOutput: $("restoreOutput"),
    btnSample: $("btnSample"),
    btnOpen: $("btnOpen"),
    btnClear: $("btnClear"),
    btnCopy: $("btnCopy"),
    btnDownload: $("btnDownload"),
    btnCsv: $("btnCsv"),
    btnCopyRestored: $("btnCopyRestored"),
    btnLang: $("btnLang"),
    btnTheme: $("btnTheme"),
    themeIcon: $("themeIcon"),
    fileInput: $("fileInput"),
    dropOverlay: $("dropOverlay"),
  };

  let lang = "es";
  let lastResult = null;
  let lastStatus = null; // [clave, ...args] para poder retraducir el estado
  let fileName = null;
  let timer = null;

  const t = (key, ...args) => {
    const v = I18N[lang][key];
    return typeof v === "function" ? v(...args) : v;
  };
  const categoryLabel = (cat) => t(`cat_${cat}`) || cat;

  // ---------- Almacenamiento (solo preferencias, nunca el texto) ----------

  function storageGet(key) {
    try {
      return localStorage.getItem(key);
    } catch {
      return null;
    }
  }

  function storageSet(key, value) {
    try {
      if (value === null) localStorage.removeItem(key);
      else localStorage.setItem(key, value);
    } catch {
      // modo privado o almacenamiento bloqueado: no se recuerda
    }
  }

  function loadSettings() {
    try {
      return JSON.parse(storageGet(SETTINGS_KEY)) || {};
    } catch {
      return {};
    }
  }

  function saveSettings() {
    storageSet(SETTINGS_KEY, JSON.stringify(currentOptions()));
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
      format: el.format.value,
      customRules: el.customRules.value,
      allowlist: el.allowlist.value,
    };
  }

  function renderCategories(saved) {
    for (const id of Object.keys(CATEGORIES)) {
      const label = document.createElement("label");
      label.className = "chip";
      const cb = document.createElement("input");
      cb.type = "checkbox";
      cb.value = id;
      cb.checked = !saved.categories || saved.categories[id] !== false;
      const span = document.createElement("span");
      span.dataset.i18n = `cat_${id}`;
      label.append(cb, " ", span);
      el.categories.append(label);
    }
  }

  function applySettings(saved) {
    if (typeof saved.keepPrivate === "boolean") el.keepPrivate.checked = saved.keepPrivate;
    if (typeof saved.keepSpecial === "boolean") el.keepSpecial.checked = saved.keepSpecial;
    if (saved.format && el.format.querySelector(`option[value="${saved.format}"]`)) el.format.value = saved.format;
    if (typeof saved.customRules === "string") el.customRules.value = saved.customRules;
    if (typeof saved.allowlist === "string") el.allowlist.value = saved.allowlist;
  }

  // ---------- Idioma ----------

  function detectLang() {
    const fromUrl = new URLSearchParams(location.search).get("lang");
    if (fromUrl === "es" || fromUrl === "en") return fromUrl;
    const saved = storageGet(LANG_KEY);
    if (saved === "es" || saved === "en") return saved;
    return (navigator.language || "en").toLowerCase().startsWith("es") ? "es" : "en";
  }

  function applyLang(next) {
    lang = next;
    document.documentElement.lang = lang;
    document.title = t("pageTitle");
    document.querySelector('meta[name="description"]').content = t("pageDescription");
    document.querySelectorAll("[data-i18n]").forEach((n) => (n.textContent = t(n.dataset.i18n)));
    // Solo textos fijos del diccionario, nunca contenido del usuario.
    document.querySelectorAll("[data-i18n-html]").forEach((n) => (n.innerHTML = t(n.dataset.i18nHtml)));
    document.querySelectorAll("[data-i18n-placeholder]").forEach((n) => (n.placeholder = t(n.dataset.i18nPlaceholder)));
    document.querySelectorAll("[data-i18n-title]").forEach((n) => (n.title = t(n.dataset.i18nTitle)));
    document.querySelectorAll("[data-i18n-data-empty]").forEach((n) => (n.dataset.empty = t(n.dataset.i18nDataEmpty)));
    applyTheme(currentTheme(), false);
    if (lastStatus) setStatus(...lastStatus);
    renderAll();
  }

  // ---------- Tema ----------

  function currentTheme() {
    return document.documentElement.dataset.theme || "auto";
  }

  function applyTheme(theme, persist = true) {
    if (theme === "auto") delete document.documentElement.dataset.theme;
    else document.documentElement.dataset.theme = theme;
    el.themeIcon.textContent = THEME_ICONS[theme];
    const label = t(`theme${theme[0].toUpperCase()}${theme.slice(1)}`);
    el.btnTheme.title = label;
    el.btnTheme.setAttribute("aria-label", label);
    if (persist) storageSet(THEME_KEY, theme === "auto" ? null : theme);
  }

  // ---------- Limpieza y renderizado ----------

  function run() {
    clearTimeout(timer);
    const text = el.input.value;
    const t0 = performance.now();
    const result = scrub(text, currentOptions());
    const ms = Math.round(performance.now() - t0);
    lastResult = text ? result : null;

    el.btnCopy.disabled = el.btnDownload.disabled = !text;
    el.btnCsv.disabled = !result.replacements.length;
    if (!text) {
      setStatus(null);
    } else if (result.findings.length === 0) {
      setStatus("statusNone");
    } else {
      const lines = text.split("\n").length;
      setStatus("statusDone", result.findings.length, result.replacements.length, lines, ms);
    }
    renderAll();
  }

  function renderAll() {
    const result = lastResult || { findings: [], replacements: [], stats: {}, errors: [], output: "" };
    renderOutput(el.input.value, result);
    renderStats(result);
    renderReplacements(result);
    renderRuleErrors(lastResult ? lastResult.errors : []);
    renderRestore();
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
      mark.title = categoryLabel(f.category);
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
      chip.append(strong, " " + categoryLabel(cat));
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
      for (const value of [r.placeholder, r.original, categoryLabel(r.category), r.count]) {
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
      td.textContent = t("moreRows", rows.length - MAX_TABLE_ROWS);
      tr.append(td);
      frag.append(tr);
    }
    el.replacements.append(frag);
  }

  function renderRuleErrors(errors) {
    el.ruleErrors.textContent = "";
    for (const e of errors) {
      const li = document.createElement("li");
      li.textContent = t("ruleError", e.line, e.message);
      el.ruleErrors.append(li);
    }
  }

  function renderRestore() {
    const text = el.restoreInput.value;
    const replacements = lastResult ? lastResult.replacements : [];
    el.restoreOutput.textContent = text && replacements.length ? restore(text, replacements) : "";
    el.restoreOutput.dataset.empty = replacements.length ? "" : t("restoreEmpty");
    el.btnCopyRestored.disabled = !el.restoreOutput.textContent;
  }

  function setStatus(key, ...args) {
    lastStatus = key ? [key, ...args] : null;
    el.status.textContent = key ? t(key, ...args) : "";
  }

  // ---------- Acciones ----------

  async function copyText(text, button) {
    if (!text) return;
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
    const original = button.textContent;
    button.textContent = t("copied");
    setTimeout(() => (button.textContent = original), 1500);
  }

  function saveFile(content, name, type) {
    const blob = new Blob([content], { type });
    const url = URL.createObjectURL(blob);
    const a = document.createElement("a");
    a.href = url;
    a.download = name;
    document.body.append(a);
    a.click();
    a.remove();
    setTimeout(() => URL.revokeObjectURL(url), 1000);
  }

  function downloadOutput() {
    if (!lastResult) return;
    const match = fileName && fileName.match(/^(.+?)(\.[^.]+)?$/);
    const base = match ? match[1] : "logscrub";
    const ext = (match && match[2]) || ".txt";
    saveFile(lastResult.output, `${base}.scrubbed${ext}`, "text/plain;charset=utf-8");
  }

  function downloadCsv() {
    if (!lastResult) return;
    const cell = (v) => `"${String(v).replace(/"/g, '""')}"`;
    const header = [t("thPlaceholder"), t("thOriginal"), t("thType"), t("thCount")];
    const rows = lastResult.replacements.map((r) => [r.placeholder, r.original, categoryLabel(r.category), r.count]);
    const csv = [header, ...rows].map((row) => row.map(cell).join(",")).join("\r\n");
    // BOM para que Excel abra bien los acentos
    saveFile("﻿" + csv, "logscrub-replacements.csv", "text/csv;charset=utf-8");
  }

  function loadFile(file) {
    if (!file) return;
    if (file.size > MAX_FILE_MB * 1024 * 1024) {
      setStatus("fileTooBig", MAX_FILE_MB);
      return;
    }
    const reader = new FileReader();
    reader.onload = () => {
      fileName = file.name;
      el.input.value = reader.result;
      run();
    };
    reader.onerror = () => setStatus("fileError");
    reader.readAsText(file);
  }

  function clearAll() {
    el.input.value = "";
    fileName = null;
    run();
    el.input.focus();
  }

  // Desplazamiento sincronizado entre el original y el resultado
  function syncScroll(from, to) {
    let lock = false;
    from.addEventListener("scroll", () => {
      if (lock) return;
      const max = from.scrollHeight - from.clientHeight;
      const ratio = max > 0 ? from.scrollTop / max : 0;
      lock = true;
      to.scrollTop = ratio * (to.scrollHeight - to.clientHeight);
      requestAnimationFrame(() => (lock = false));
    });
  }

  // Valores de ejemplo: IPs de documentación (RFC 5737/3849), dominios example.com
  // y tokens falsos armados por partes para no disparar escáneres de secretos.
  function sampleText() {
    const c = t("sampleComments");
    const jwt = "eyJ" + "hbGciOiJIUzI1NiJ9.eyJ" + "zdWIiOiIxMjM0NTY3ODkwIn0.dBjftJeZ4CVPmB92K27uhbUJU1p1r_wW1gFWFOEjXk";
    const gh = "gh" + "p_" + "R4nd0mT0k3nV4lu3F0rD3m0Purp0s3s0nly1";
    return [
      c.syslog,
      "Oct  5 10:21:33 web-prod-01 sshd[2211]: Failed password for invalid user admin from 203.0.113.45 port 52144 ssh2",
      "Oct  5 10:21:40 web-prod-01 sshd[2211]: Accepted publickey for jperez from 198.51.100.23 port 50122 ssh2",
      "",
      c.nginx,
      '203.0.113.45 - - [05/Oct/2026:10:22:01 +0000] "GET /api/v1/users?token=9f8e7d6c5b4a3210 HTTP/1.1" 401 512 "-" "curl/8.4.0"',
      "",
      c.app,
      "2026-10-05T10:22:05Z ERROR db connection failed: postgres://app_user:S3cr3tP4ss@db01.internal.example.com:5432/orders",
      "2026-10-05T10:22:06Z WARN  notify failed for maria.lopez@example.com via smtp.example.com",
      `Authorization: Bearer ${jwt}`,
      `GITHUB_TOKEN=${gh}`,
      "aws_access_key_id = AKIAIOSFODNN7EXAMPLE",
      "",
      c.mikrotik,
      "/system identity set name=MK-Oficina-Central",
      "/ip address add address=192.168.88.1/24 interface=bridge",
      '/interface wireless security-profiles set default authentication-types=wpa2-psk wpa2-pre-shared-key="ClaveWifi2026!"',
      "/interface ethernet set [ find default-name=ether1 ] mac-address=4C:5E:0C:12:AB:CD",
      "",
      c.cisco,
      "hostname R1-Sucursal",
      "enable secret 5 $1$mERr$hx5rVt7rPNoS4wqbXKX7m0",
      "username soporte privilege 15 secret 0 Cisco#2026",
      "interface GigabitEthernet0/0",
      " ip address 198.51.100.2 255.255.255.252",
      " mac-address 001a.2b3c.4d5e",
      "snmp-server community empresa-ro RO",
      "access-list 10 permit 10.10.0.0 0.0.255.255",
      "",
      c.fortigate,
      "config vpn ipsec phase1-interface",
      '    edit "vpn-sucursal"',
      "        set remote-gw 203.0.113.200",
      "        set psksecret ENC kP9vR2xT6yL0bM4nQ8sW",
      "    next",
      "end",
      "",
      c.ipv6,
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
    el.format.addEventListener("change", onOptionsChange);
    el.customRules.addEventListener("input", onOptionsChange);
    el.allowlist.addEventListener("input", onOptionsChange);
    el.restoreInput.addEventListener("input", renderRestore);

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
    el.btnCopy.addEventListener("click", () => lastResult && copyText(lastResult.output, el.btnCopy));
    el.btnDownload.addEventListener("click", downloadOutput);
    el.btnCsv.addEventListener("click", downloadCsv);
    el.btnCopyRestored.addEventListener("click", () => copyText(el.restoreOutput.textContent, el.btnCopyRestored));

    el.btnLang.addEventListener("click", () => {
      const next = lang === "es" ? "en" : "es";
      storageSet(LANG_KEY, next);
      applyLang(next);
    });
    el.btnTheme.addEventListener("click", () => {
      const next = THEMES[(THEMES.indexOf(currentTheme()) + 1) % THEMES.length];
      applyTheme(next);
    });

    syncScroll(el.input, el.output);
    syncScroll(el.output, el.input);

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
        if (lastResult) copyText(lastResult.output, el.btnCopy);
      }
    });

    applyLang(detectLang());
    run();
  }

  init();
})();
