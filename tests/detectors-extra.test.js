// LogScrub · pruebas de los detectores de v0.6
// Equipos de red, nube/DevOps, datos personales, rutas y números de serie.
"use strict";

const test = require("node:test");
const assert = require("node:assert/strict");
const { scrub, createState } = require("../js/scrubber.js");

const out = (text, opts) => scrub(text, opts).output;
const lines = (...l) => l.join("\n");

// ---------- Equipos de red ----------

test("Juniper Junos (formato set y llaves)", () => {
  const t = lines(
    'set system host-name EX-Core-01',
    'set system root-authentication encrypted-password "$6$abc$defghijk"',
    'set snmp community Pr1vada authorization read-only',
    "user soporte {",
    '    authentication {',
    '        encrypted-password "$6$xyz$1234567"; ## SECRET-DATA',
    "    }",
    "}",
    'authentication-key "$9$AbCdEfGhIjK"; ## SECRET-DATA'
  );
  assert.equal(
    out(t),
    lines(
      "set system host-name HOST_1",
      'set system root-authentication encrypted-password "SECRET_1"',
      "set snmp community SECRET_2 authorization read-only",
      "user USER_1 {",
      "    authentication {",
      '        encrypted-password "SECRET_3"; ## SECRET-DATA',
      "    }",
      "}",
      'authentication-key "SECRET_4"; ## SECRET-DATA'
    )
  );
});

test("Huawei VRP", () => {
  const t = lines(
    "sysname HW-Agg-01",
    "local-user admin password irreversible-cipher $1a$AbCd$EfGh$",
    "snmp-agent community read cipher %^%#xYz%^%#",
    "ike peer sucursal",
    " pre-shared-key cipher %@%@AbC%@%@"
  );
  assert.equal(
    out(t),
    lines(
      "sysname HOST_1",
      "local-user USER_1 password irreversible-cipher SECRET_1",
      "snmp-agent community read cipher SECRET_2",
      "ike peer sucursal",
      " pre-shared-key cipher SECRET_3"
    )
  );
});

test("VyOS / EdgeOS (Ubiquiti)", () => {
  const t = lines(
    "set system login user admin authentication plaintext-password 'Cl4ve!'",
    "set vpn ipsec site-to-site peer 203.0.113.1 authentication pre-shared-secret S3cr3tPSK",
    "host-name edge-router"
  );
  assert.equal(
    out(t),
    lines(
      "set system login user USER_1 authentication plaintext-password 'SECRET_1'",
      "set vpn ipsec site-to-site peer IP_1 authentication pre-shared-secret SECRET_2",
      "host-name HOST_1"
    )
  );
});

test("pfSense / OPNsense config.xml", () => {
  const t = lines(
    "<hostname>fw-oficina</hostname>",
    "<user>",
    "  <name>admin</name>",
    "  <bcrypt-hash>$2y$10$abcdefghijk</bcrypt-hash>",
    "</user>",
    "<pre-shared-key>MiPSK2026</pre-shared-key>",
    "<keylength>2048</keylength>"
  );
  assert.equal(
    out(t),
    lines(
      "<hostname>HOST_1</hostname>",
      "<user>",
      "  <name>USER_1</name>",
      "  <bcrypt-hash>SECRET_1</bcrypt-hash>",
      "</user>",
      "<pre-shared-key>SECRET_2</pre-shared-key>",
      "<keylength>2048</keylength>"
    )
  );
});

test("WireGuard y OpenVPN", () => {
  const t = lines(
    "[Interface]",
    "PrivateKey = yAnz5TF+lXXJte14tji3zlMNq+hd2rYUIgJBgB3fBmk=",
    "[Peer]",
    "PresharedKey = /UwcSPg38hW/D9Y3tcS1FOV0K1wuURMbS0sesJEP5ak=",
    "Endpoint = 203.0.113.5:51820",
    "<tls-auth>",
    "-----BEGIN OpenVPN Static key V1-----",
    "e5a6b7c8d9",
    "-----END OpenVPN Static key V1-----",
    "</tls-auth>"
  );
  assert.equal(
    out(t),
    lines(
      "[Interface]",
      "PrivateKey = SECRET_1",
      "[Peer]",
      "PresharedKey = SECRET_2",
      "Endpoint = IP_1:51820",
      "<tls-auth>",
      "PRIVATE_KEY_1",
      "</tls-auth>"
    )
  );
});

test("Cisco: pre-shared-key de Huawei no rompe el de Cisco", () => {
  assert.equal(out("pre-shared-key local cisco123"), "pre-shared-key local SECRET_1");
});

// ---------- Nube y DevOps ----------

test("Kubernetes Secret: data, stringData y bloques |", () => {
  const t = lines(
    "apiVersion: v1",
    "kind: Secret",
    "metadata:",
    "  name: db-credentials",
    "data:",
    "  username: YWRtaW4=",
    "  password: UzNjcjN0",
    "stringData:",
    "  config.yaml: |",
    "    apiKey: abc123",
    "    region: us-east",
    "---",
    "kind: ConfigMap",
    "data:",
    "  LOG_LEVEL: debug"
  );
  assert.equal(
    out(t),
    lines(
      "apiVersion: v1",
      "kind: Secret",
      "metadata:",
      "  name: db-credentials",
      "data:",
      "  username: SECRET_1",
      "  password: SECRET_2",
      "stringData:",
      "  config.yaml: |",
      "    SECRET_3",
      "    SECRET_4",
      "---",
      "kind: ConfigMap",
      "data:",
      "  LOG_LEVEL: debug"
    )
  );
});

test("Tokens de nube y DevOps", () => {
  const fakes = [
    "GOCSPX" + "-" + "a".repeat(28),
    "ya29" + "." + "b".repeat(30),
    "abc" + "8Q~" + "c".repeat(32),
    "dckr" + "_pat_" + "d".repeat(27),
    "dop" + "_v1_" + "e".repeat(64),
    "hvs" + "." + "F".repeat(30),
    "SG" + "." + "g".repeat(22) + "." + "h".repeat(43),
    "shpat" + "_" + "a".repeat(32),
    "hf" + "_" + "I".repeat(34),
  ];
  for (const tok of fakes) assert.equal(out(`x ${tok} y`), "x TOKEN_1 y", tok.slice(0, 8));
});

test("Azure: cadena de conexión y firma SAS", () => {
  assert.equal(
    out("DefaultEndpointsProtocol=https;AccountName=demo;AccountKey=" + "k".repeat(40) + "==;EndpointSuffix=core.windows.net"),
    "DefaultEndpointsProtocol=https;AccountName=demo;AccountKey=SECRET_1;EndpointSuffix=HOST_1"
  );
  assert.equal(
    out("https://demo.blob.core.windows.net/c?sv=2022-11-02&sig=" + "AbC%2Bd".repeat(5) + "&se=2026"),
    "https://HOST_1/c?sv=2022-11-02&sig=TOKEN_1&se=2026"
  );
});

test("Docker config.json y cuenta de servicio de Google", () => {
  assert.equal(out('{"auths":{"registry.example.com":{"auth":"dXNlcjpwYXNz"}}}'), '{"auths":{"HOST_1":{"auth":"TOKEN_1"}}}');
  assert.equal(
    out('"private_key_id": "a1b2c3d4e5f6", "client_email": "bot@proj.iam.gserviceaccount.com"'),
    '"private_key_id": "SECRET_1", "client_email": "EMAIL_1"'
  );
});

test("Flags de línea de comandos y URL sin usuario", () => {
  assert.equal(out("docker login --password Hunter2 --username bob"), "docker login --password SECRET_1 --username bob");
  assert.equal(out("cli --token=abc123def"), "cli --token=SECRET_1");
  assert.equal(out("redis://:S3cr3t@cache.example.com:6379"), "redis://:SECRET_1@HOST_1:6379");
  assert.equal(out("mkdir -p /tmp/x && rm --force y"), "mkdir -p /tmp/x && rm --force y");
});

test("Cadena de conexión SQL Server", () => {
  assert.equal(
    out("Server=db01.example.com;Database=app;User Id=sa;Password=P4ss!;"),
    "Server=HOST_1;Database=app;User Id=USER_1;Password=SECRET_1;"
  );
});

// ---------- Datos personales ----------

test("Tarjetas: válidas con Luhn, ignora números que no lo son", () => {
  assert.equal(out("visa 4111 1111 1111 1111 amex 3782-822463-10005"), "visa CARD_1 amex CARD_2");
  assert.equal(out("pedido 4111111111111112 ts 1696500000000"), "pedido 4111111111111112 ts 1696500000000");
});

test("IBAN válido e inválido", () => {
  assert.equal(out("cuenta DE89 3704 0044 0532 0130 00 y ES9121000418450200051332"), "cuenta IBAN_1 y IBAN_2");
  assert.equal(out("ref DE00 3704 0044 0532 0130 00"), "ref DE00 3704 0044 0532 0130 00");
});

test("Documentos de identidad", () => {
  assert.equal(out("Cédula: 001-1234567-8"), "Cédula: ID_1");
  assert.equal(out("cliente 402-1234567-1 RNC 1-01-12345-6"), "cliente ID_1 RNC ID_2");
  assert.equal(out("RNC: 101123456"), "RNC: ID_1");
  assert.equal(out("DNI 12345678Z, otro 12345678A"), "DNI ID_1, otro 12345678A");
  assert.equal(out("CURP GODE561231HDFRRN09"), "CURP ID_1");
  assert.equal(out("SSN 123-45-6789"), "SSN ID_1");
});

test("Teléfonos", () => {
  assert.equal(out("llamar al (809) 555-0123 o +1 829-555-0199"), "llamar al PHONE_1 o PHONE_2");
  assert.equal(out("móvil +34 612 345 678"), "móvil PHONE_1");
});

test("Teléfonos: sin falsos positivos en fechas, horas, zonas horarias ni versiones", () => {
  const t = "[05/Oct/2026:10:22:01 +0000] 2026-10-05 10:22:05 v2.10.3 pid 12345 port 443 +5 retries";
  assert.equal(out(t), t);
});

// ---------- Rutas y números de serie ----------

test("Rutas con el nombre del usuario", () => {
  assert.equal(
    out("C:\\Users\\Juan Perez\\AppData\\x.log y C:\\Users\\Public\\x y /home/maria/.ssh y /Users/bob"),
    "C:\\Users\\USER_1\\AppData\\x.log y C:\\Users\\Public\\x y /home/USER_2/.ssh y /Users/USER_3"
  );
  assert.equal(out('"path": "C:\\\\Users\\\\digim\\\\Documents"'), '"path": "C:\\\\Users\\\\USER_1\\\\Documents"');
});

test("SID de Windows", () => {
  assert.equal(out("owner S-1-5-21-3623811015-3361044348-30300820-1013 y S-1-5-18"), "owner SID_1 y S-1-5-18");
});

test("Números de serie", () => {
  const t = lines(
    "Processor board ID FTX1234A5BC",
    "serial-number: HG709ABC123",
    "SN: FOC12345678",
    "Serial-Number: FGT60FTK21000000",
    "interface Serial0/1/0",
    "serial console enabled"
  );
  assert.equal(
    out(t),
    lines("Processor board ID SERIAL_1", "serial-number: SERIAL_2", "SN: SERIAL_3", "Serial-Number: SERIAL_4", "interface Serial0/1/0", "serial console enabled")
  );
});

// ---------- Motor ----------

test("Estado compartido: numeración consistente entre varios textos", () => {
  const state = createState();
  const a = scrub("from 203.0.113.1", { state });
  const b = scrub("to 203.0.113.2 and 203.0.113.1", { state });
  assert.equal(a.output, "from IP_1");
  assert.equal(b.output, "to IP_2 and IP_1");
  assert.deepEqual(b.replacements.map((r) => r.placeholder), ["IP_2", "IP_1"]);
});

test("Rendimiento con todos los detectores: 1 MB variado en menos de 3 s", () => {
  const block = lines(
    "Oct  5 10:21:33 web01 sshd[22]: Failed password for root from 203.0.113.4 port 52144 ssh2",
    "2026-10-05T10:22:05Z ERROR user=a@example.com path=C:\\Users\\bob\\x card 4111 1111 1111 1111",
    "set system host-name R1; <password>x</password> serial-number: HG709ABC123 +34 612 345 678",
    ""
  );
  const big = block.repeat(Math.ceil(1e6 / block.length));
  const t0 = Date.now();
  scrub(big);
  assert.ok(Date.now() - t0 < 3000, `tardó ${Date.now() - t0} ms`);
});

test("Hostnames: sin falsos positivos en SQL ni llamadas a funciones", () => {
  const t = "SELECT p.id, u.name FROM t; user.id = 5; logger.info(msg); console.log(x)";
  assert.equal(out(t), t);
  assert.equal(out("conectar a smtp.gmail.com:587 y x.example.com"), "conectar a HOST_1:587 y HOST_2");
});
