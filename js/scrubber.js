// LogScrub · motor de limpieza
// Aplica los detectores sobre el texto y reemplaza cada valor sensible por un
// marcador consistente: el mismo valor siempre recibe el mismo marcador (IP_1, HOST_2...).
(function (root) {
  "use strict";

  const { CATEGORIES, DETECTORS } =
    typeof module === "object" && module.exports ? require("./detectors.js") : root.LogScrubDetectors;

  const DEFAULT_OPTIONS = {
    categories: {}, // { ipv4: false } desactiva una categoría; las ausentes quedan activas
    keepPrivate: false, // conservar IPs privadas (10.x, 192.168.x, fe80::...)
    keepSpecial: true, // conservar máscaras, 0.0.0.0, loopback, broadcast
    customRules: "", // texto con una regla por línea (ver parseCustomRules)
    allowlist: "", // valores que nunca se reemplazan, uno por línea
  };

  function escapeRegExp(s) {
    return s.replace(/[.*+?^${}()|[\]\\]/g, "\\$&");
  }

  function sanitizeLabel(label) {
    const clean = label.toUpperCase().replace(/[^A-Z0-9_]/g, "_").replace(/^_+|_+$/g, "");
    return clean || "CUSTOM";
  }

  // Una regla por línea:
  //   Acme Corp                → texto literal (sin distinguir mayúsculas)
  //   /PRJ-\d{4}/              → expresión regular
  //   /id=(?<v>\d+)/ => CLIENTE → solo reemplaza el grupo "v" y usa el marcador CLIENTE_1
  // Las líneas vacías y las que empiezan con # se ignoran.
  function parseCustomRules(text) {
    const rules = [];
    const errors = [];
    const lines = String(text || "").split(/\r?\n/);
    lines.forEach((line, i) => {
      const trimmed = line.trim();
      if (!trimmed || trimmed.startsWith("#")) return;
      let body = trimmed;
      let label = "CUSTOM";
      const arrow = trimmed.lastIndexOf("=>");
      if (arrow > 0) {
        body = trimmed.slice(0, arrow).trim();
        label = sanitizeLabel(trimmed.slice(arrow + 2).trim());
      }
      if (!body) return;
      const rx = /^\/(.+)\/([a-z]*)$/.exec(body);
      try {
        let pattern;
        if (rx) {
          const flags = new Set(rx[2].split("").concat(["g", "d"]));
          flags.delete("y");
          pattern = new RegExp(rx[1], [...flags].join(""));
        } else {
          pattern = new RegExp(escapeRegExp(body), "gid");
        }
        rules.push({
          id: `custom-${i + 1}`,
          category: "custom",
          prefix: label,
          pattern,
          group: pattern.source.includes("(?<v>") ? "v" : undefined,
        });
      } catch (e) {
        errors.push({ line: i + 1, text: trimmed, message: e.message });
      }
    });
    return { rules, errors };
  }

  function parseAllowlist(text) {
    return new Set(
      String(text || "")
        .split(/\r?\n/)
        .map((s) => s.trim().toLowerCase())
        .filter(Boolean)
    );
  }

  // Clave para decidir si dos apariciones son "el mismo valor".
  function normalize(category, value, ignoreCase) {
    if (ignoreCase) return value.toLowerCase();
    switch (category) {
      case "mac":
        return value.replace(/[^0-9a-f]/gi, "").toLowerCase();
      case "email":
      case "hostname":
      case "ipv6":
        return value.toLowerCase();
      default:
        return value;
    }
  }

  function spanFor(match, group) {
    if (group) {
      const span = match.indices && match.indices.groups && match.indices.groups[group];
      return span ? [span[0], span[1]] : null;
    }
    return [match.index, match.index + match[0].length];
  }

  function scrub(text, options) {
    const input = String(text || "");
    const opts = Object.assign({}, DEFAULT_OPTIONS, options);
    const { rules: customRules, errors } = parseCustomRules(opts.customRules);
    const allow = parseAllowlist(opts.allowlist);

    const detectors = customRules.concat(
      DETECTORS.filter((d) => opts.categories[d.category] !== false).map((d) => ({
        ...d,
        group: d.pattern.source.includes("(?<v>") ? "v" : undefined,
      }))
    );

    // Cada carácter solo puede pertenecer a una coincidencia: la del detector
    // con más prioridad (el primero de la lista).
    const taken = new Uint8Array(input.length);
    const found = [];

    for (const det of detectors) {
      det.pattern.lastIndex = 0;
      for (const m of input.matchAll(det.pattern)) {
        const span = spanFor(m, det.group);
        if (!span) continue;
        let [start, end] = span;
        const first = input[start];
        if (end - start >= 2 && (first === '"' || first === "'") && input[end - 1] === first) {
          start++;
          end--;
        }
        if (end <= start) continue;
        const value = input.slice(start, end);
        if (det.validate && !det.validate(value)) continue;
        if (det.keep && det.keep(value, opts)) continue;
        if (allow.has(value.toLowerCase())) continue;
        if (taken.subarray(start, end).some((x) => x)) continue;
        taken.fill(1, start, end);
        found.push({
          start,
          end,
          value,
          category: det.category,
          prefix: det.prefix || CATEGORIES[det.category].prefix,
          detector: det.id,
          ignoreCase: det.category === "custom" && det.pattern.flags.includes("i"),
        });
      }
    }

    found.sort((a, b) => a.start - b.start);

    // Marcadores numerados por orden de aparición.
    const counters = {};
    const byKey = new Map();
    const parts = [];
    let pos = 0;
    for (const f of found) {
      const key = `${f.prefix}\u0000${normalize(f.category, f.value, f.ignoreCase)}`;
      let entry = byKey.get(key);
      if (!entry) {
        counters[f.prefix] = (counters[f.prefix] || 0) + 1;
        entry = {
          category: f.category,
          original: f.value,
          placeholder: `${f.prefix}_${counters[f.prefix]}`,
          count: 0,
        };
        byKey.set(key, entry);
      }
      entry.count++;
      f.placeholder = entry.placeholder;
      parts.push(input.slice(pos, f.start), entry.placeholder);
      pos = f.end;
    }
    parts.push(input.slice(pos));

    const stats = {};
    for (const f of found) stats[f.category] = (stats[f.category] || 0) + 1;

    return {
      output: parts.join(""),
      findings: found,
      replacements: [...byKey.values()],
      stats,
      errors,
    };
  }

  const api = { scrub, parseCustomRules, CATEGORIES, DETECTORS, DEFAULT_OPTIONS };

  if (typeof module === "object" && module.exports) module.exports = api;
  else root.LogScrub = api;
})(typeof globalThis !== "undefined" ? globalThis : this);
