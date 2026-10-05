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
    privateKey: { label: "Private keys", prefix: "PRIVATE_KEY" },
    token: { label: "Tokens & API keys", prefix: "TOKEN" },
    secret: { label: "Passwords & secrets", prefix: "SECRET" },
    user: { label: "Usernames", prefix: "USER" },
    email: { label: "Emails", prefix: "EMAIL" },
    mac: { label: "MAC addresses", prefix: "MAC" },
    ipv6: { label: "IPv6", prefix: "IPV6" },
    ipv4: { label: "IPv4", prefix: "IP" },
    hostname: { label: "Hostnames & domains", prefix: "HOST" },
    phone: { label: "Phone numbers", prefix: "PHONE" },
    financial: { label: "Cards & IBAN", prefix: "CARD" },
    nationalId: { label: "ID numbers", prefix: "ID" },
    serial: { label: "Serial numbers", prefix: "SERIAL" },
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
      "com net org edu gov mil int info biz pro aero coop museum mobi asia tel travel jobs " +
      "app dev cloud tech online site xyz top club shop store blog website space live news email " +
      "network systems solutions services company digital agency media group global world center " +
      "host hosting server link click page zone today support tools works design studio academy " +
      "lan local localdomain internal intranet intra corp home homelab arpa test example invalid " +
      "onion lab priv private office vpn mesh mail cloud"
    ).split(" ")
  );
  const FILE_EXTENSIONS_2 = new Set(
    "js py sh md rb ts cs so pl gz xz db rs kt vb ps mo po ko hs ml pm ex cc hh ui id".split(" ")
  );

  function isLikelyHostname(host) {
    if (host.length > 253) return false;
    const labels = host.split(".");
    if (labels.length === 2 && labels[0].length === 1) return false; // alias tipo p.id, u.name
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

  function luhn(digits) {
    let sum = 0;
    let double = false;
    for (let i = digits.length - 1; i >= 0; i--) {
      let n = digits.charCodeAt(i) - 48;
      if (double) {
        n *= 2;
        if (n > 9) n -= 9;
      }
      sum += n;
      double = !double;
    }
    return sum % 10 === 0;
  }

  // Visa, Mastercard, Amex, Discover y JCB con dígito de control válido.
  function isCardNumber(value) {
    const d = value.replace(/[ -]/g, "");
    if (d.length < 13 || d.length > 19) return false;
    if (!/^(?:4|5[1-5]|2[2-7]|3[47]|6(?:011|5)|35)/.test(d)) return false;
    return luhn(d);
  }

  function isIban(value) {
    const s = value.replace(/ /g, "").toUpperCase();
    if (s.length < 15 || s.length > 34) return false;
    let rem = 0;
    for (const ch of s.slice(4) + s.slice(0, 4)) {
      const n = /\d/.test(ch) ? ch : String(ch.charCodeAt(0) - 55);
      for (const c of n) rem = (rem * 10 + (c.charCodeAt(0) - 48)) % 97;
    }
    return rem === 1;
  }

  // DNI español: 8 dígitos + letra de control.
  function isSpanishDni(value) {
    const m = /^(\d{8})-?([A-Z])$/i.exec(value);
    return !!m && "TRWAGMYFPDXBNJZSQVHLCKE"[Number(m[1]) % 23] === m[2].toUpperCase();
  }

  function isPhone(value) {
    const digits = value.replace(/\D/g, "").length;
    return digits >= 8 && digits <= 15;
  }

  const hasDigit = (v) => /\d/.test(v);

  const GENERIC_PROFILE_DIRS = new Set(["public", "default", "default user", "all users", "shared", "guest"]);
  const isPersonalDir = (v) => !GENERIC_PROFILE_DIRS.has(v.toLowerCase());

  // Valores dentro de data:/stringData: de los manifiestos "kind: Secret" de Kubernetes.
  function findK8sSecretValues(text) {
    const spans = [];
    if (!/^kind:[ \t]*Secret[ \t]*\r?$/m.test(text)) return spans;

    const collect = (doc) => {
      if (!doc.some((l) => /^kind:[ \t]*Secret[ \t]*$/.test(l.text))) return;
      let inData = false;
      let blockIndent = -1;
      for (const { text: line, start } of doc) {
        if (!line.trim()) continue;
        const indent = line.length - line.trimStart().length;
        if (indent === 0) {
          inData = /^(?:data|stringData):[ \t]*$/.test(line);
          blockIndent = -1;
          continue;
        }
        if (!inData) continue;
        if (blockIndent >= 0 && indent > blockIndent) {
          spans.push([start + indent, start + line.length]); // línea de un bloque "|"
          continue;
        }
        blockIndent = -1;
        const m = /^[ \t]+[^\s:#][^:]*:[ \t]*(.*)$/.exec(line);
        if (!m || !m[1]) continue;
        if (/^[|>][-+]?$/.test(m[1])) {
          blockIndent = indent;
          continue;
        }
        spans.push([start + line.length - m[1].length, start + line.length]);
      }
    };

    let doc = [];
    let pos = 0;
    for (const raw of text.split("\n")) {
      const line = raw.replace(/\r$/, "");
      if (/^---/.test(line)) {
        collect(doc);
        doc = [];
      } else {
        doc.push({ text: line, start: pos });
      }
      pos += raw.length + 1;
    }
    collect(doc);
    return spans;
  }

  // ---------- Piezas de regex reutilizables ----------

  // Valor de una línea clave=valor: entre comillas o hasta un separador.
  const VALUE = String.raw`(?<v>"[^"\n]*"|'[^'\n]*'|[^\s,;&"'}\]]+)`;
  const SECRET_KEYS = String.raw`password|passwd|passphrase|secret|token|api[_-]?key|apikey|access[_-]?key|private[_-]?key|client[_-]?secret|auth(?:entication)?[_-]?key|pre-?shared-?key|psk|account[_-]?key|shared[_-]?access[_-]?key|private[_-]?key[_-]?id|client[_-]?key[_-]?data|sas[_-]?token`;
  const SEP = String.raw`["']?\s*(?:=>|[:=])\s*`;

  // ---------- Detectores (en orden de prioridad) ----------

  const DETECTORS = [
    // Claves privadas completas (PEM / OpenSSH)
    {
      id: "pem-private-key",
      category: "privateKey",
      pattern: /-----BEGIN [A-Z0-9 ]*PRIVATE KEY(?: BLOCK)?-----[\s\S]*?-----END [A-Z0-9 ]*PRIVATE KEY(?: BLOCK)?-----/g,
    },
    {
      id: "openvpn-static-key",
      category: "privateKey",
      pattern: /-----BEGIN OpenVPN Static key V\d-----[\s\S]*?-----END OpenVPN Static key V\d-----/g,
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
    { id: "google-oauth-secret", category: "token", pattern: /\bGOCSPX-[A-Za-z0-9_-]{28}(?![\w-])/g },
    { id: "google-oauth-token", category: "token", pattern: /\bya29\.[A-Za-z0-9_-]{20,}/g },
    { id: "azure-client-secret", category: "token", pattern: /(?<![\w~.-])[A-Za-z0-9_~.-]{3}\dQ~[A-Za-z0-9_~.-]{31,34}(?![\w~.-])/g },
    { id: "azure-sas-signature", category: "token", pattern: /[?&]sig=(?<v>[A-Za-z0-9%+/=]{20,})/gd },
    { id: "docker-hub-token", category: "token", pattern: /\bdckr_pat_[A-Za-z0-9_-]{20,}/g },
    { id: "digitalocean-token", category: "token", pattern: /\bdo[opr]_v1_[a-f0-9]{64}\b/g },
    { id: "vault-token", category: "token", pattern: /\bhv[sbr]\.[A-Za-z0-9_-]{24,}/g },
    { id: "sendgrid-key", category: "token", pattern: /\bSG\.[A-Za-z0-9_-]{22}\.[A-Za-z0-9_-]{43}\b/g },
    { id: "shopify-token", category: "token", pattern: /\bshp(?:at|ss|ca|pa)_[a-fA-F0-9]{32}\b/g },
    { id: "huggingface-token", category: "token", pattern: /\bhf_[A-Za-z0-9]{34,}\b/g },
    { id: "pypi-token", category: "token", pattern: /\bpypi-AgEIcHlwaS5vcmc[A-Za-z0-9_-]{50,}/g },
    { id: "discord-webhook", category: "token", pattern: /https:\/\/(?:canary\.|ptb\.)?discord(?:app)?\.com\/api\/webhooks\/\d+\/[A-Za-z0-9_-]+/g },
    { id: "docker-config-auth", category: "token", pattern: /"auth"\s*:\s*"(?<v>[A-Za-z0-9+/=]{8,})"/gd },
    { id: "telegram-bot-token", category: "token", pattern: /\b\d{8,10}:AA[A-Za-z0-9_-]{33}(?![\w-])/g },
    {
      id: "authorization-header",
      category: "token",
      pattern: /\bAuthorization["']?\s*[:=]\s*["']?(?:(?:Basic|Bearer|Token|Digest)[ \t]+)?(?<v>[A-Za-z0-9._~+/-]{8,}=*)/gid,
    },
    { id: "bearer-token", category: "token", pattern: /\bBearer[ \t]+(?<v>[A-Za-z0-9._~+/-]{8,}=*)/gd },

    // Kubernetes: valores de data:/stringData: en manifiestos kind: Secret
    { id: "k8s-secret-data", category: "secret", find: findK8sSecretValues },

    // Credenciales dentro de URLs: esquema://usuario:clave@host
    {
      id: "url-password",
      category: "secret",
      pattern: /\b[a-z][a-z0-9+.-]{1,15}:\/\/[^\s:/@]{0,128}:(?<v>[^\s@/]{1,256})@/gid,
    },
    {
      id: "url-user",
      category: "user",
      pattern: /\b[a-z][a-z0-9+.-]{1,15}:\/\/(?<v>[^\s:/@]{1,128}):[^\s@/]{1,256}@/gid,
    },

    // Juniper Junos
    { id: "juniper-type9", category: "secret", pattern: /"(?<v>\$9\$[^"\n]+)"/gd },
    { id: "juniper-secret-data", category: "secret", pattern: /(?<v>"[^"\n]*"|[^\s;"]+)[ \t]*;[ \t]*## SECRET-DATA/gd },
    { id: "juniper-snmp-community", category: "secret", pattern: /\bsnmp[ \t]+community[ \t]+(?<v>"[^"\n]*"|[^\s;{]+)/gd },
    { id: "juniper-community-block", category: "secret", pattern: /^[ \t]*community[ \t]+(?<v>"[^"\n]*"|[^\s;{]+)[ \t]*\{/gmd },

    // Huawei VRP: password cipher xxx / local-user admin / sysname
    {
      id: "huawei-cipher",
      category: "secret",
      pattern: /\b(?:password|pre-shared-key|community(?:[ \t]+(?:read|write))?|authentication-mode[ \t]+\S+|key)[ \t]+(?:cipher|irreversible-cipher|simple)[ \t]+(?<v>\S+)/gid,
    },
    { id: "huawei-snmp-community", category: "secret", pattern: /\bsnmp-agent[ \t]+community[ \t]+(?:read|write)[ \t]+(?:cipher[ \t]+)?(?<v>\S+)/gid },
    { id: "huawei-local-user", category: "user", pattern: /^[ \t]*local-user[ \t]+(?<v>\S+)/gimd },

    // VyOS / EdgeOS (Ubiquiti)
    {
      id: "vyos-secret",
      category: "secret",
      pattern: /\b(?:plaintext-password|encrypted-password|pre-shared-secret|shared-secret-key|ppk-secret)[ \t]+(?<v>'[^'\n]*'|"[^"\n]*"|[^\s;]+)/gid,
    },
    { id: "login-user", category: "user", pattern: /\blogin[ \t]+user[ \t]+(?<v>[^\s;{]+)/gd },
    { id: "user-block", category: "user", pattern: /^[ \t]*user[ \t]+(?<v>[^\s;{]+)[ \t]*\{/gmd },

    // pfSense / OPNsense (config.xml)
    {
      id: "xml-secret",
      category: "secret",
      pattern: /<(?<t>(?:[\w-]*[_-])?(?:password|passwd|secret|psk|ipsecpsk|pre-shared-key|apikey|api_key|api_secret|bcrypt-hash|sha512-hash|md5-hash|nt-hash|prv|bindpw|authkey|token|privatekey|passphrase|shared_key|tls|community|rocommunity))>(?<v>[^<]+)<\/\k<t>>/gid,
    },
    { id: "xml-user", category: "user", pattern: /<user>\s*<name>(?<v>[^<]+)<\/name>/gd },

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
      pattern: /\b(?:snmp-server[ \t]+community|key-string|ntp[ \t]+authentication-key[ \t]+\d+[ \t]+md5|message-digest-key[ \t]+\d+[ \t]+md5|authentication-key|(?:tacacs|radius)-server[ \t]+key|isakmp[ \t]+key|pre-shared-key(?:[ \t]+(?:local|remote))?|wpa-psk[ \t]+ascii|chap[ \t]+password|pap[ \t]+sent-username[ \t]+\S+[ \t]+password)[ \t]+(?:\d[ \t]+)?(?!(?:cipher|irreversible-cipher|simple)[ \t])(?<v>\S+)/gid,
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
      pattern: new RegExp(String.raw`(?<![\w-])(?:[\w-]{0,40}?[_.-])?(?:user(?:name)?|user[ _]?id|login|usuario)${SEP}${VALUE}`, "gid"),
      validate: isRealSecret,
    },

    // Línea de comandos: --password xxx / --token=xxx
    {
      id: "cli-flag-secret",
      category: "secret",
      pattern: /(?<![\w-])--(?:password|passwd|token|secret|api-key|client-secret|access-key|secret-key)(?:=|[ \t]+)(?<v>"[^"\n]*"|'[^'\n]*'|[^\s"']+)/gd,
      validate: isRealSecret,
    },

    // Rutas con el nombre del usuario: C:\Users\nombre, /home/nombre, /Users/nombre
    {
      id: "windows-profile-path",
      category: "user",
      pattern: /\b[A-Za-z]:(?:\\{1,2}|\/)(?:Users|Documents and Settings)(?:\\{1,2}|\/)(?<v>[^\\/:*?"<>|\r\n\s](?:[^\\/:*?"<>|\r\n]*?[^\\/:*?"<>|\r\n\s])?)(?=\\|\/)/gd,
      validate: isPersonalDir,
    },
    {
      id: "windows-profile-path-end",
      category: "user",
      pattern: /\b[A-Za-z]:(?:\\{1,2}|\/)(?:Users|Documents and Settings)(?:\\{1,2}|\/)(?<v>[^\\/:*?"<>|\s]+)/gd,
      validate: isPersonalDir,
    },
    {
      id: "unix-home-path",
      category: "user",
      pattern: /(?<![\w.~-])\/(?:home|Users)\/(?<v>[^/\s:'"]+)/gd,
      validate: isPersonalDir,
    },
    { id: "windows-sid", category: "user", prefix: "SID", pattern: /\bS-1-5-21-\d{1,10}-\d{1,10}-\d{1,10}(?:-\d{1,10})?\b/g },

    // Números de serie (Cisco show version/inventory, MikroTik routerboard, FortiGate...)
    {
      id: "serial-number",
      category: "serial",
      pattern: /\b(?:serial[ _-]?(?:number|no\.?|num)?|s\/n|sn|processor board id|n[uú]mero de serie)[ \t]*[:=#]?[ \t]*(?<v>"[^"\n]*"|[A-Z0-9][A-Z0-9-]{4,39})(?![\w-])/gid,
      validate: hasDigit,
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

    // Financieros: IBAN y tarjetas (validados con mod 97 y Luhn)
    {
      id: "iban",
      category: "financial",
      prefix: "IBAN",
      pattern: /\b[A-Z]{2}\d{2}(?: ?[A-Z0-9]{4}){2,7}(?: ?[A-Z0-9]{1,3})?\b/g,
      validate: isIban,
    },
    { id: "card", category: "financial", pattern: /(?<![\w-])\d(?:[ -]?\d){12,18}(?![\w-])/g, validate: isCardNumber },

    // Documentos de identidad
    {
      id: "id-context",
      category: "nationalId",
      pattern: /\b(?:RNC|C[ée]dula|DNI|NIF|NIE|CURP|RFC|RUT|CUIT|CUIL|SSN|NSS|passport|pasaporte)\b[ \t]*(?:No\.?|N[º°o]\.?|#)?[ \t]*[:=]?[ \t]*(?<v>[A-Z0-9](?:[A-Z0-9.-]{4,20}[A-Z0-9])?)/gid,
      validate: hasDigit,
    },
    { id: "do-cedula", category: "nationalId", pattern: /(?<![\w-])\d{3}-\d{7}-\d(?![\w-])/g },
    { id: "do-rnc", category: "nationalId", pattern: /(?<![\w-])\d-\d{2}-\d{5}-\d(?![\w-])/g },
    { id: "es-dni", category: "nationalId", pattern: /(?<![\w-])\d{8}-?[A-Za-z](?![\w-])/g, validate: isSpanishDni },
    { id: "mx-curp", category: "nationalId", pattern: /\b[A-Z]{4}\d{6}[HM][A-Z]{5}[0-9A-Z]\d\b/g },
    { id: "us-ssn", category: "nationalId", pattern: /(?<![\w-])(?!000|666|9\d\d)\d{3}-(?!00)\d{2}-(?!0000)\d{4}(?![\w-])/g },

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

    // Teléfonos: +1 809-555-0123, (809) 555-0123, +34 612 345 678
    {
      id: "phone-nanp",
      category: "phone",
      pattern: /(?<![\w+.-])(?:\+?1[ .-]?)?(?:\([2-9]\d{2}\)[ .-]?|[2-9]\d{2}[ .-])\d{3}[ .-]\d{4}(?![\w-]|\.\d)/g,
    },
    {
      id: "phone-international",
      category: "phone",
      pattern: /(?<![\w+])\+\d{1,3}[ .-]?(?:\(\d{1,4}\)[ .-]?)?\d{1,4}(?:[ .-]?\d{2,4}){1,4}(?![\w-]|\.\d)/g,
      validate: isPhone,
    },

    // Nombres de equipo en configs y syslog
    { id: "junos-hostname", category: "hostname", pattern: /\bhost-name[ \t]+(?<v>"[^"\n]*"|[^\s;]+)/gd },
    { id: "huawei-sysname", category: "hostname", pattern: /^[ \t]*sysname[ \t]+(?<v>\S+)/gimd },
    { id: "xml-hostname", category: "hostname", pattern: /<hostname>(?<v>[^<]+)<\/hostname>/gd },
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
      pattern: /(?<![\w.-])(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z][a-z0-9-]{0,62}(?![\w-]|\.[a-z0-9]|\()/gi,
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
    isCardNumber,
    isIban,
    isSpanishDni,
    findK8sSecretValues,
  };

  if (typeof module === "object" && module.exports) module.exports = api;
  else root.LogScrubDetectors = api;
})(typeof globalThis !== "undefined" ? globalThis : this);
