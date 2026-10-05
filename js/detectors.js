// LogScrub · reglas de detección
// Cada detector busca un tipo de dato sensible. El orden importa: cuando dos
// detectores encuentran texto superpuesto, gana el que aparece primero en la lista.
//
// Forma de un detector:
//   id        identificador único
//   category  clave de CATEGORIES (define el prefijo del marcador, p. ej. IP_1)
//   pattern   RegExp con flag "g". Si usa un grupo con nombre "v", solo se
//             reemplaza ese grupo (requiere también el flag "d").
//   validate  (opcional) fn(valor) → false descarta la coincidencia
//   keep      (opcional) fn(valor, opciones) → true conserva el valor original
(function (root) {
  "use strict";

  const CATEGORIES = {
    privateKey: { label: "Claves privadas", prefix: "PRIVATE_KEY" },
    token: { label: "Tokens y claves API", prefix: "TOKEN" },
    secret: { label: "Contraseñas y secretos", prefix: "SECRET" },
    user: { label: "Usuarios", prefix: "USER" },
    email: { label: "Correos", prefix: "EMAIL" },
    mac: { label: "Direcciones MAC", prefix: "MAC" },
    ipv6: { label: "IPv6", prefix: "IPV6" },
    ipv4: { label: "IPv4", prefix: "IP" },
    hostname: { label: "Hostnames y dominios", prefix: "HOST" },
  };

  // ---------- Utilidades de validación ----------

  function ipv4ToInt(ip) {
    const parts = ip.split(".");
    if (parts.length !== 4) return null;
    let n = 0;
    for (const p of parts) {
      if (!/^\d{1,3}$/.test(p)) return null;
      const v = Number(p);
      if (v > 255) return null;
      n = n * 256 + v;
    }
    return n;
  }

  function isValidIPv4(ip) {
    return ipv4ToInt(ip) !== null;
  }

  // Máscaras de red (255.255.255.0), wildcards de Cisco (0.0.0.255),
  // 0.0.0.0, broadcast y loopback: no identifican a nadie y cambiarlas rompe configs.
  function isSpecialIPv4(ip) {
    const n = ipv4ToInt(ip);
    if (n === null) return false;
    if (ip.startsWith("127.")) return true;
    const bits = n.toString(2).padStart(32, "0");
    return /^1*0*$/.test(bits) || /^0*1*$/.test(bits);
  }

  function isPrivateIPv4(ip) {
    const n = ipv4ToInt(ip);
    if (n === null) return false;
    const inRange = (base, maskBits) => {
      const b = ipv4ToInt(base);
      const size = 2 ** (32 - maskBits);
      return n >= b && n < b + size;
    };
    return (
      inRange("10.0.0.0", 8) ||
      inRange("172.16.0.0", 12) ||
      inRange("192.168.0.0", 16) ||
      inRange("169.254.0.0", 16) ||
      inRange("100.64.0.0", 10)
    );
  }

  function isValidIPv6(raw) {
    const s = raw.replace(/%.*$/, "");
    const halves = s.split("::");
    if (halves.length > 2) return false;
    const split = (str) => (str === "" ? [] : str.split(":"));
    let groups = split(halves[0]).concat(halves.length === 2 ? split(halves[1]) : []);
    let count = groups.length;
    const last = groups[groups.length - 1];
    if (last && last.includes(".")) {
      if (!s.endsWith(last) || !isValidIPv4(last)) return false;
      groups = groups.slice(0, -1);
      count += 1;
    }
    if (!groups.every((g) => /^[0-9a-f]{1,4}$/i.test(g))) return false;
    return halves.length === 2 ? count < 8 : count === 8;
  }

  function isSpecialIPv6(raw) {
    const s = raw.replace(/%.*$/, "").toLowerCase();
    return s === "::" || s === "::1";
  }

  function isPrivateIPv6(raw) {
    const first = raw.toLowerCase().split(":")[0];
    if (!first) return false;
    const n = parseInt(first, 16);
    return (n & 0xffc0) === 0xfe80 || (n & 0xfe00) === 0xfc00; // link-local, ULA
  }

  function isSpecialMac(mac) {
    const hex = mac.replace(/[^0-9a-f]/gi, "").toLowerCase();
    return hex === "000000000000" || hex === "ffffffffffff";
  }

  // TLD aceptados para hostnames. Cualquier TLD de 2 letras cuenta como país,
  // salvo los que suelen ser extensiones de archivo.
  const TLDS = new Set(
    (
      "com net org edu gov mil int info biz name pro aero coop museum mobi asia tel travel jobs " +
      "app dev cloud tech online site xyz top club shop store blog website space live news email " +
      "network systems solutions services company digital agency media group global world center " +
      "host hosting server link click page zone today support tools works design studio academy " +
      "lan local localdomain internal intranet intra corp home homelab arpa test example invalid " +
      "onion lab priv private office vpn mesh mail cloud"
    ).split(" ")
  );
  const FILE_EXTENSIONS_2 = new Set(
    "js py sh md rb ts cs so pl gz xz db rs kt vb ps mo po ko hs ml pm ex cc hh ui".split(" ")
  );

  function isLikelyHostname(host) {
    if (host.length > 253) return false;
    const tld = host.slice(host.lastIndexOf(".") + 1).toLowerCase();
    if (!/^[a-z]+$/.test(tld)) return false;
    if (tld.length === 2) return !FILE_EXTENSIONS_2.has(tld);
    return TLDS.has(tld);
  }

  // Valores que no son secretos aunque aparezcan tras "password=".
  const NOT_SECRET = /^(?:true|false|null|none|nil|undefined|yes|no|on|off|\*+|x+|<[^>]*>|\$\{?\w+\}?|\{\{[^}]*\}\}|%\w+%)$/i;

  function isRealSecret(value) {
    return value.length > 0 && !NOT_SECRET.test(value);
  }

  // ---------- Piezas de regex reutilizables ----------

  // Valor de una línea clave=valor: entre comillas o hasta un separador.
  const VALUE = String.raw`(?<v>"[^"\n]*"|'[^'\n]*'|[^\s,;&"'}\]]+)`;
  const SECRET_KEYS = String.raw`password|passwd|passphrase|secret|token|api[_-]?key|apikey|access[_-]?key|private[_-]?key|client[_-]?secret|auth(?:entication)?[_-]?key|pre-?shared-?key|psk`;
  const SEP = String.raw`["']?\s*(?:=>|[:=])\s*`;

  // ---------- Detectores (en orden de prioridad) ----------

  const DETECTORS = [
    // Claves privadas completas (PEM / OpenSSH)
    {
      id: "pem-private-key",
      category: "privateKey",
      pattern: /-----BEGIN [A-Z0-9 ]*PRIVATE KEY(?: BLOCK)?-----[\s\S]*?-----END [A-Z0-9 ]*PRIVATE KEY(?: BLOCK)?-----/g,
    },

    // Tokens con formato conocido
    { id: "jwt", category: "token", pattern: /\beyJ[A-Za-z0-9_-]{5,}\.[A-Za-z0-9_-]{5,}\.[A-Za-z0-9_-]{5,}/g },
    { id: "aws-access-key", category: "token", pattern: /\b(?:AKIA|ASIA|AGPA|AIDA|AROA|ANPA|ANVA|AIPA)[A-Z0-9]{16}\b/g },
    { id: "github-token", category: "token", pattern: /\b(?:gh[pousr]_[A-Za-z0-9]{36,255}|github_pat_[A-Za-z0-9_]{22,255})\b/g },
    { id: "gitlab-token", category: "token", pattern: /\bglpat-[A-Za-z0-9_-]{20,}/g },
    { id: "slack-token", category: "token", pattern: /\bxox[abposr]-[A-Za-z0-9-]{10,}/g },
    { id: "slack-webhook", category: "token", pattern: /https:\/\/hooks\.slack\.com\/services\/[A-Za-z0-9/_-]+/g },
    { id: "google-api-key", category: "token", pattern: /\bAIza[0-9A-Za-z_-]{35}(?![\w-])/g },
    { id: "stripe-key", category: "token", pattern: /\b(?:sk|rk|pk)_(?:live|test)_[A-Za-z0-9]{10,}/g },
    { id: "sk-api-key", category: "token", pattern: /\bsk-[A-Za-z0-9_-]{20,}/g },
    { id: "npm-token", category: "token", pattern: /\bnpm_[A-Za-z0-9]{36}\b/g },
    { id: "telegram-bot-token", category: "token", pattern: /\b\d{8,10}:AA[A-Za-z0-9_-]{33}(?![\w-])/g },
    {
      id: "authorization-header",
      category: "token",
      pattern: /\bAuthorization["']?\s*[:=]\s*["']?(?:(?:Basic|Bearer|Token|Digest)[ \t]+)?(?<v>[A-Za-z0-9._~+/-]{8,}=*)/gid,
    },
    { id: "bearer-token", category: "token", pattern: /\bBearer[ \t]+(?<v>[A-Za-z0-9._~+/-]{8,}=*)/gd },

    // Credenciales dentro de URLs: esquema://usuario:clave@host
    {
      id: "url-password",
      category: "secret",
      pattern: /\b[a-z][a-z0-9+.-]{1,15}:\/\/[^\s:/@]{1,128}:(?<v>[^\s@/]{1,256})@/gid,
    },
    {
      id: "url-user",
      category: "user",
      pattern: /\b[a-z][a-z0-9+.-]{1,15}:\/\/(?<v>[^\s:/@]{1,128}):[^\s@/]{1,256}@/gid,
    },

    // Cisco IOS
    {
      id: "cisco-enable-secret",
      category: "secret",
      pattern: /^[ \t]*(?:enable[ \t]+)?(?:secret|password)[ \t]+(?:\d[ \t]+)?(?<v>\S+)/gimd,
    },
    {
      id: "cisco-username-secret",
      category: "secret",
      pattern: /^[ \t]*username[ \t]+\S+(?:[ \t]+\S+){0,8}?[ \t]+(?:secret|password)[ \t]+(?:\d[ \t]+)?(?<v>\S+)/gimd,
    },
    {
      id: "cisco-keys",
      category: "secret",
      pattern: /\b(?:snmp-server[ \t]+community|key-string|ntp[ \t]+authentication-key[ \t]+\d+[ \t]+md5|message-digest-key[ \t]+\d+[ \t]+md5|authentication-key|(?:tacacs|radius)-server[ \t]+key|isakmp[ \t]+key|pre-shared-key(?:[ \t]+(?:local|remote))?|wpa-psk[ \t]+ascii|chap[ \t]+password|pap[ \t]+sent-username[ \t]+\S+[ \t]+password)[ \t]+(?:\d[ \t]+)?(?<v>\S+)/gid,
    },
    { id: "cisco-username", category: "user", pattern: /^[ \t]*username[ \t]+(?<v>\S+)/gimd },

    // FortiGate: set password ENC xxx / set psksecret xxx
    {
      id: "fortigate-secret",
      category: "secret",
      pattern: /^[ \t]*set[ \t]+(?:\w+-){0,3}(?:password|passwd|pwd|secret|psksecret|passphrase|key|psk)[ \t]+(?:ENC[ \t]+)?(?<v>"[^"\n]*"|\S+)/gimd,
    },

    // Genérico clave=valor / clave: valor (MikroTik, .env, JSON, YAML, INI, query strings)
    {
      id: "key-value-secret",
      category: "secret",
      pattern: new RegExp(String.raw`(?<![\w-])(?:[\w-]{0,40}?[_.-])?(?:${SECRET_KEYS})${SEP}${VALUE}`, "gid"),
      validate: isRealSecret,
    },
    {
      id: "key-value-user",
      category: "user",
      pattern: new RegExp(String.raw`(?<![\w-])(?:[\w-]{0,40}?[_.-])?(?:user(?:name)?|login|usuario)${SEP}${VALUE}`, "gid"),
      validate: isRealSecret,
    },

    // sshd: "Failed password for invalid user bob from ..."
    {
      id: "sshd-user",
      category: "user",
      pattern: /\b(?:(?:Failed|Accepted)[ \t]+\S+[ \t]+for(?:[ \t]+invalid[ \t]+user)?|Invalid[ \t]+user|session (?:opened|closed) for user)[ \t]+(?<v>[^\s(]+)/gd,
    },

    // Correos
    {
      id: "email",
      category: "email",
      pattern: /(?<![\w.+-])[A-Za-z0-9._%+-]{1,64}@(?:[A-Za-z0-9-]{1,63}\.)+[A-Za-z]{2,24}(?![\w-])/g,
    },

    // MAC: 00:1A:2B:3C:4D:5E, 00-1A-..., 001a.2b3c.4d5e (Cisco)
    {
      id: "mac",
      category: "mac",
      pattern: /(?<![\w:-])[0-9A-Fa-f]{2}([:-])(?:[0-9A-Fa-f]{2}\1){4}[0-9A-Fa-f]{2}(?![\w:-])/g,
      keep: (v, o) => o.keepSpecial && isSpecialMac(v),
    },
    {
      id: "mac-cisco",
      category: "mac",
      pattern: /(?<![\w.])[0-9A-Fa-f]{4}\.[0-9A-Fa-f]{4}\.[0-9A-Fa-f]{4}(?![\w.])/g,
      keep: (v, o) => o.keepSpecial && isSpecialMac(v),
    },

    // IPv6
    {
      id: "ipv6",
      category: "ipv6",
      pattern: /(?<![\w:.])(?:[0-9A-Fa-f]{0,4}:){2,7}(?:[0-9A-Fa-f]{1,4}|\d{1,3}(?:\.\d{1,3}){3})?(?:%[\w.]+)?(?![\w:])/g,
      validate: isValidIPv6,
      keep: (v, o) => (o.keepSpecial && isSpecialIPv6(v)) || (o.keepPrivate && isPrivateIPv6(v)),
    },

    // IPv4
    {
      id: "ipv4",
      category: "ipv4",
      pattern: /(?<![\w.])(?:\d{1,3}\.){3}\d{1,3}(?!\w|\.\d)/g,
      validate: isValidIPv4,
      keep: (v, o) => (o.keepSpecial && isSpecialIPv4(v)) || (o.keepPrivate && isPrivateIPv4(v)),
    },

    // Nombres de equipo en configs y syslog
    { id: "cisco-hostname", category: "hostname", pattern: /^[ \t]*hostname[ \t]+(?<v>\S+)/gimd },
    { id: "fortigate-hostname", category: "hostname", pattern: /^[ \t]*set[ \t]+hostname[ \t]+(?<v>"[^"\n]*"|\S+)/gimd },
    { id: "mikrotik-identity", category: "hostname", pattern: /\/system[ \t]+identity\s+set[ \t]+name=(?<v>"[^"\n]*"|\S+)/gid },
    {
      id: "syslog-host",
      category: "hostname",
      pattern: /^(?:[A-Z][a-z]{2}[ \t]+\d{1,2}[ \t]+\d{2}:\d{2}:\d{2}|\d{4}-\d{2}-\d{2}T[\d:.]+(?:Z|[+-]\d{2}:?\d{2})?)[ \t]+(?<v>[A-Za-z][\w.-]*)[ \t]+[\w./-]+(?:\[\d+\])?:/gmd,
    },

    // FQDN: servidor.empresa.com
    {
      id: "hostname",
      category: "hostname",
      pattern: /(?<![\w.-])(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z][a-z0-9-]{0,62}(?![\w-]|\.[a-z0-9])/gi,
      validate: isLikelyHostname,
    },
  ];

  const api = {
    CATEGORIES,
    DETECTORS,
    isValidIPv4,
    isSpecialIPv4,
    isPrivateIPv4,
    isValidIPv6,
    isPrivateIPv6,
    isLikelyHostname,
  };

  if (typeof module === "object" && module.exports) module.exports = api;
  else root.LogScrubDetectors = api;
})(typeof globalThis !== "undefined" ? globalThis : this);
