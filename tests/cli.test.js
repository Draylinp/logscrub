// LogScrub · pruebas de la línea de comandos (ejecuta bin/logscrub.js como proceso)
"use strict";

const test = require("node:test");
const assert = require("node:assert/strict");
const fs = require("fs");
const os = require("os");
const path = require("path");
const { spawnSync } = require("child_process");

const BIN = path.join(__dirname, "..", "bin", "logscrub.js");
const tmp = fs.mkdtempSync(path.join(os.tmpdir(), "logscrub-test-"));
test.after(() => fs.rmSync(tmp, { recursive: true, force: true }));

function run(args, input) {
  const r = spawnSync(process.execPath, [BIN, ...args], { input: input ?? "", encoding: "utf8" });
  return { code: r.status, stdout: r.stdout, stderr: r.stderr };
}

function file(name, content) {
  const p = path.join(tmp, name);
  fs.writeFileSync(p, content);
  return p;
}

test("stdin → stdout", () => {
  const r = run([], "from 203.0.113.1 user=admin\n");
  assert.equal(r.code, 0);
  assert.equal(r.stdout, "from IP_1 user=USER_1\n");
});

test("Varios archivos comparten la numeración", () => {
  const a = file("a.log", "203.0.113.1\n");
  const b = file("b.log", "203.0.113.2 203.0.113.1\n");
  assert.equal(run([a, b]).stdout, "IP_1\nIP_2 IP_1\n");
});

test("--out-dir escribe un archivo limpio por entrada", () => {
  const a = file("router.rsc", "/system identity set name=MK1\n");
  const dir = path.join(tmp, "out");
  assert.equal(run(["-d", dir, a]).code, 0);
  assert.equal(fs.readFileSync(path.join(dir, "router.scrubbed.rsc"), "utf8"), "/system identity set name=HOST_1\n");
});

test("--map y --restore hacen el viaje de ida y vuelta", () => {
  const original = "db postgres://app:S3cr3t@db01.example.com/x from 203.0.113.9\n";
  const map = path.join(tmp, "map.json");
  const scrubbed = run(["-m", map], original);
  assert.equal(scrubbed.code, 0);
  assert.ok(!scrubbed.stdout.includes("S3cr3t"));
  const saved = JSON.parse(fs.readFileSync(map, "utf8"));
  assert.equal(saved.tool, "logscrub");
  const restored = run(["--restore", "-m", map], scrubbed.stdout);
  assert.equal(restored.stdout, original);
});

test("--check: código 1 y ubicación sin revelar el valor", () => {
  const f = file("conf.yaml", "name: app\npassword: hunter2\n");
  const r = run(["--check", f]);
  assert.equal(r.code, 1);
  assert.equal(r.stdout, "");
  assert.match(r.stderr, /conf\.yaml:2:11 {2}secret/);
  assert.ok(!r.stderr.includes("hunter2"));
  assert.equal(run(["--check"], "nada sensible\n").code, 0);
});

test("--only, --disable, --format y --keep-private", () => {
  const t = "203.0.113.1 192.168.1.1 a@example.com";
  assert.equal(run(["--only", "email"], t).stdout, "203.0.113.1 192.168.1.1 EMAIL_1");
  assert.equal(run(["--disable", "ipv4"], t).stdout, "203.0.113.1 192.168.1.1 EMAIL_1");
  assert.equal(run(["-f", "brackets", "--keep-private"], t).stdout, "[IP_1] 192.168.1.1 [EMAIL_1]");
});

test("--rules y --allow desde archivos", () => {
  const rules = file("rules.txt", "Acme Corp => EMPRESA\n");
  const allow = file("allow.txt", "8.8.8.8\n");
  assert.equal(run(["--rules", rules, "--allow", allow], "Acme Corp usa 8.8.8.8 y 203.0.113.1").stdout, "EMPRESA_1 usa 8.8.8.8 y IP_1");
});

test("--json y --stats", () => {
  const r = run(["--json"], "203.0.113.1 203.0.113.1");
  const data = JSON.parse(r.stdout);
  assert.equal(data.output, "IP_1 IP_1");
  assert.deepEqual(data.stats, { ipv4: 2 });
  const s = run(["--stats"], "203.0.113.1");
  assert.match(s.stderr, /1 value\(s\) replaced, 1 unique \(ipv4: 1\)/);
});

test("Errores de uso devuelven código 2", () => {
  assert.equal(run(["--only", "nada"], "x").code, 2);
  assert.equal(run(["--format", "raro"], "x").code, 2);
  assert.equal(run(["--restore"], "x").code, 2);
  assert.equal(run(["--opcion-inexistente"], "x").code, 2);
  assert.equal(run([path.join(tmp, "no-existe.log")]).code, 2);
});

test("--help, --version y --list", () => {
  assert.match(run(["--help"]).stdout, /Usage:/);
  assert.match(run(["-v"]).stdout, /^\d+\.\d+\.\d+\n$/);
  assert.match(run(["--list"]).stdout, /ipv4 +IP/);
});
