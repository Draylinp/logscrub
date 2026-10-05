// LogScrub · pruebas del motor
// Ejecutar con: npm test   (o: npm test)
"use strict";

const test = require("node:test");
const assert = require("node:assert/strict");
const { scrub, restore, parseCustomRules } = require("../js/scrubber.js");

// Los tokens falsos se arman por partes para que los escáneres de secretos
// (p. ej. la protección de push de GitHub) no los confundan con reales.
const FAKE = {
  github: "gh" + "p_" + "A".repeat(36),
  slack: "xo" + "xb-" + "1234567890-abcdefghij",
  stripe: "sk" + "_live_" + "a1b2c3d4e5f6g7h8",
  google: "AI" + "za" + "B".repeat(35),
  openai: "sk" + "-proj-" + "c".repeat(30),
  jwt: "eyJ" + "hbGciOiJIUzI1NiJ9" + ".eyJ" + "zdWIiOiIxIn0" + ".abcdefghijk",
};

const out = (text, opts) => scrub(text, opts).output;

test("IPv4: reemplaza y mantiene el mismo marcador para la misma IP", () => {
  assert.equal(out("from 203.0.113.5 to 198.51.100.7 and 203.0.113.5"), "from IP_1 to IP_2 and IP_1");
});

test("IPv4: conserva máscaras, wildcards, 0.0.0.0 y loopback", () => {
  const t = "ip address 203.0.113.1 255.255.255.0\npermit 0.0.0.0 0.0.0.255\nlisten 127.0.0.1";
  assert.equal(out(t), "ip address IP_1 255.255.255.0\npermit 0.0.0.0 0.0.0.255\nlisten 127.0.0.1");
});

test("IPv4: keepSpecial=false también reemplaza máscaras", () => {
  assert.equal(out("mask 255.255.255.0", { keepSpecial: false }), "mask IP_1");
});

test("IPv4: keepPrivate conserva rangos privados", () => {
  const t = "lan 192.168.1.10 10.0.0.1 172.16.5.4 wan 203.0.113.9";
  assert.equal(out(t, { keepPrivate: true }), "lan 192.168.1.10 10.0.0.1 172.16.5.4 wan IP_1");
});

test("IPv4: conserva el sufijo CIDR y el puerto", () => {
  assert.equal(out("net 203.0.113.0/24 host 198.51.100.1:8080"), "net IP_1/24 host IP_2:8080");
});

test("IPv4: ignora octetos inválidos y versiones", () => {
  assert.equal(out("999.1.1.1 v1.2.3.4 1.2.3 1.2.3.4.5"), "999.1.1.1 v1.2.3.4 1.2.3 1.2.3.4.5");
});

test("IPv6: reemplaza direcciones válidas y conserva ::1", () => {
  assert.equal(out("a 2001:db8::1 b ::1 c 2001:DB8::1"), "a IPV6_1 b ::1 c IPV6_1");
});

test("IPv6: no confunde horas, C++ ni MACs", () => {
  const t = "12:30:45 std::string 4C:5E:0C:12:AB:CD";
  assert.equal(out(t), "12:30:45 std::string MAC_1");
});

test("IPv6: keepPrivate conserva link-local y ULA", () => {
  assert.equal(out("fe80::1%eth0 fd00::5 2001:db8::9", { keepPrivate: true }), "fe80::1%eth0 fd00::5 IPV6_1");
});

test("MAC: los tres formatos de la misma MAC reciben el mismo marcador", () => {
  const t = "00:1A:2B:3C:4D:5E 00-1a-2b-3c-4d-5e 001a.2b3c.4d5e ff:ff:ff:ff:ff:ff";
  assert.equal(out(t), "MAC_1 MAC_1 MAC_1 ff:ff:ff:ff:ff:ff");
});

test("Correo y hostname", () => {
  assert.equal(
    out("send to Maria.Lopez@example.com via smtp.example.com and maria.lopez@EXAMPLE.com"),
    "send to EMAIL_1 via HOST_1 and EMAIL_1"
  );
});

test("Hostname: no confunde archivos ni paquetes de código", () => {
  const t = "app.js config.yaml readme.md java.io.IOException console.log(x) archivo.txt";
  assert.equal(out(t), t);
});

test("URL con credenciales: usuario, clave y host", () => {
  assert.equal(
    out("postgres://app:S3cr3t@db01.internal.example.com:5432/x"),
    "postgres://USER_1:SECRET_1@HOST_1:5432/x"
  );
});

test("Secretos clave=valor (env, JSON, YAML, query string)", () => {
  assert.equal(out("DB_PASSWORD=hunter2"), "DB_PASSWORD=SECRET_1");
  assert.equal(out('{"api_key": "abc123xyz"}'), '{"api_key": "SECRET_1"}');
  assert.equal(out("password: 'mi clave'"), "password: 'SECRET_1'");
  assert.equal(out("/x?token=abc123&page=2"), "/x?token=SECRET_1&page=2");
});

test("Secretos: ignora valores que no son secretos", () => {
  const t = "password=true\nsecret: ${DB_SECRET}\ntoken=****\nautocomplete-password=off";
  assert.equal(out(t), t);
});

test("MikroTik", () => {
  const t = [
    "/system identity set name=MK-Central",
    'set default wpa2-pre-shared-key="Clave Wifi!" authentication-types=wpa2-psk',
    "add name=vpn1 password=Vpn#2026 service=l2tp",
  ].join("\n");
  assert.equal(
    out(t),
    [
      "/system identity set name=HOST_1",
      'set default wpa2-pre-shared-key="SECRET_1" authentication-types=wpa2-psk',
      "add name=vpn1 password=SECRET_2 service=l2tp",
    ].join("\n")
  );
});

test("Cisco IOS", () => {
  const t = [
    "hostname R1",
    "enable secret 5 $1$mERr$hx5rVt7rPNoS4wqbXKX7m0",
    "username soporte privilege 15 secret 0 Cisco#2026",
    "snmp-server community empresa-ro RO",
    " key-string 7 0822455D0A16",
    "crypto isakmp key MiPSK address 203.0.113.1",
  ].join("\n");
  assert.equal(
    out(t),
    [
      "hostname HOST_1",
      "enable secret 5 SECRET_1",
      "username USER_1 privilege 15 secret 0 SECRET_2",
      "snmp-server community SECRET_3 RO",
      " key-string 7 SECRET_4",
      "crypto isakmp key SECRET_5 address IP_1",
    ].join("\n")
  );
});

test("FortiGate", () => {
  const t = [
    '    set hostname "FGT-Oficina"',
    "    set password ENC SH2xGfE3pQ1q0v8mL1wq9K",
    '    set psksecret "otra clave"',
    "    set keylife 28800",
  ].join("\n");
  assert.equal(
    out(t),
    ['    set hostname "HOST_1"', "    set password ENC SECRET_1", '    set psksecret "SECRET_2"', "    set keylife 28800"].join(
      "\n"
    )
  );
});

test("sshd y syslog", () => {
  const t =
    "Oct  5 10:21:33 web01 sshd[22]: Failed password for invalid user admin from 203.0.113.4 port 1 ssh2\n" +
    "Oct  5 10:21:40 web01 sshd[22]: Accepted publickey for jperez from 203.0.113.4 port 2 ssh2";
  assert.equal(
    out(t),
    "Oct  5 10:21:33 HOST_1 sshd[22]: Failed password for invalid user USER_1 from IP_1 port 1 ssh2\n" +
      "Oct  5 10:21:40 HOST_1 sshd[22]: Accepted publickey for USER_2 from IP_1 port 2 ssh2"
  );
});

test("Tokens con formato conocido", () => {
  for (const [name, tok] of Object.entries(FAKE)) {
    assert.equal(out(`value ${tok} end`), "value TOKEN_1 end", name);
  }
  assert.equal(out("aws_access_key_id = AKIAIOSFODNN7EXAMPLE"), "aws_access_key_id = TOKEN_1");
  assert.equal(out("Authorization: Basic dXNlcjpwYXNzd29yZA=="), "Authorization: Basic TOKEN_1");
});

test("Clave privada PEM completa", () => {
  const t = "a\n-----BEGIN RSA PRIVATE KEY-----\nMIIEow\nIBAAK\n-----END RSA PRIVATE KEY-----\nb";
  assert.equal(out(t), "a\nPRIVATE_KEY_1\nb");
});

test("Categorías desactivadas no se reemplazan", () => {
  const t = "203.0.113.1 user@example.com";
  assert.equal(out(t, { categories: { ipv4: false } }), "203.0.113.1 EMAIL_1");
});

test("Lista de permitidos", () => {
  const t = "dns 8.8.8.8 host 203.0.113.1 smtp.example.com";
  assert.equal(out(t, { allowlist: "8.8.8.8\nSMTP.example.com" }), "dns 8.8.8.8 host IP_1 smtp.example.com");
});

test("Reglas personalizadas: literal, regex y grupo v con etiqueta", () => {
  const rules = "Acme Corp => EMPRESA\n/PRJ-\\d{4}/\n/cliente=(?<v>\\d+)/ => CLIENTE\n# comentario";
  assert.equal(
    out("acme corp PRJ-1234 cliente=998 ACME CORP", { customRules: rules }),
    "EMPRESA_1 CUSTOM_1 cliente=CLIENTE_1 EMPRESA_1"
  );
});

test("Reglas personalizadas: informa regex inválidas sin romper", () => {
  const { rules, errors } = parseCustomRules("/[abc/\nok");
  assert.equal(rules.length, 1);
  assert.equal(errors.length, 1);
  assert.equal(errors[0].line, 1);
});

test("Resultado: tabla de reemplazos y estadísticas", () => {
  const r = scrub("203.0.113.1 203.0.113.1 a@example.com");
  assert.deepEqual(r.stats, { ipv4: 2, email: 1 });
  assert.deepEqual(
    r.replacements.map((x) => [x.placeholder, x.original, x.count]),
    [
      ["IP_1", "203.0.113.1", 2],
      ["EMAIL_1", "a@example.com", 1],
    ]
  );
});

test("Texto vacío y texto sin datos sensibles", () => {
  assert.equal(out(""), "");
  assert.equal(out("hola mundo\nsin nada que ocultar"), "hola mundo\nsin nada que ocultar");
});

test("Rendimiento: 1 MB de log en menos de 3 s", () => {
  const line =
    "Oct  5 10:21:33 web01 sshd[22]: Failed password for root from 203.0.113.4 port 52144 ssh2 user=a@example.com\n";
  const big = line.repeat(Math.ceil(1e6 / line.length));
  const t0 = Date.now();
  const r = scrub(big);
  assert.ok(Date.now() - t0 < 3000, `tardó ${Date.now() - t0} ms`);
  assert.ok(!r.output.includes("203.0.113.4"));
});

test("Formatos de marcador", () => {
  const t = "203.0.113.1 a@example.com";
  assert.equal(out(t, { format: "brackets" }), "[IP_1] [EMAIL_1]");
  assert.equal(out(t, { format: "angle" }), "<IP_1> <EMAIL_1>");
  assert.equal(out(t, { format: "braces" }), "{{IP_1}} {{EMAIL_1}}");
  assert.equal(out(t, { format: "desconocido" }), "IP_1 EMAIL_1");
});

test("restore: devuelve los originales sin confundir IP_1 con IP_10", () => {
  const ips = Array.from({ length: 10 }, (_, i) => `203.0.113.${i + 1}`).join(" ");
  const r = scrub(ips);
  assert.equal(restore(r.output, r.replacements), ips);
  assert.equal(restore("Revisa IP_10 e IP_1, no IP_100 ni MY_IP_1.", r.replacements), "Revisa 203.0.113.10 e 203.0.113.1, no IP_100 ni MY_IP_1.");
});

test("restore: funciona con todos los formatos", () => {
  const t = "user=admin from 203.0.113.1";
  for (const format of ["plain", "brackets", "angle", "braces"]) {
    const r = scrub(t, { format });
    assert.equal(restore(r.output, r.replacements), t, format);
  }
});

test("restore: sin reemplazos devuelve el texto tal cual", () => {
  assert.equal(restore("IP_1", []), "IP_1");
  assert.equal(restore("", null), "");
});
