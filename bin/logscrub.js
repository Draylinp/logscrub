#!/usr/bin/env node
// LogScrub · versión de línea de comandos
// Usa el mismo motor que la web (js/scrubber.js). Nada sale de tu equipo.
"use strict";

const fs = require("fs");
const path = require("path");
const { parseArgs } = require("util");
const { scrub, restore, createState, CATEGORIES } = require("../js/scrubber.js");
const { version } = require("../package.json");

const HELP = `LogScrub ${version} · Sanitize logs and configs before sharing them.

Usage:
  logscrub [options] [file ...]        scrub files (or stdin) to stdout
  logscrub --restore -m map.json [file] put the original values back

Options:
  -o, --output <file>      write the result to a file instead of stdout
  -d, --out-dir <dir>      write each input to <dir>/<name>.scrubbed<ext>
  -m, --map <file.json>    save the replacements table (needed for --restore)
  -r, --restore            replace placeholders with the originals from --map
  -c, --check              print nothing but findings; exit 1 if sensitive data is found
  -s, --stats              print a summary to stderr
  -f, --format <style>     placeholder style: plain (IP_1), brackets ([IP_1]),
                           angle (<IP_1>), braces ({{IP_1}})
      --only <list>        only these categories (comma-separated, see --list)
      --disable <list>     skip these categories
      --keep-private       keep private IPs (10.x, 192.168.x, fe80::...)
      --no-keep-special    also replace netmasks, wildcards, 0.0.0.0 and loopback
      --rules <file>       custom rules, one per line (text, /regex/, "=> NAME")
      --allow <file>       values that are never replaced, one per line
      --json               print JSON: { output, replacements, stats }
      --list               list the categories
  -h, --help               show this help
  -v, --version            show the version

Examples:
  logscrub router.rsc > router.clean.rsc
  journalctl -u nginx | logscrub --stats | pbcopy
  logscrub -m map.json app.log -o app.clean.log
  logscrub --restore -m map.json reply.txt
  logscrub --check config/*.yaml          # CI / pre-commit
`;

const EXIT_OK = 0;
const EXIT_FOUND = 1;
const EXIT_USAGE = 2;

class UsageError extends Error {}

function parse(argv) {
  const { values, positionals } = parseArgs({
    args: argv,
    allowPositionals: true,
    options: {
      output: { type: "string", short: "o" },
      "out-dir": { type: "string", short: "d" },
      map: { type: "string", short: "m" },
      restore: { type: "boolean", short: "r" },
      check: { type: "boolean", short: "c" },
      stats: { type: "boolean", short: "s" },
      format: { type: "string", short: "f" },
      only: { type: "string" },
      disable: { type: "string" },
      "keep-private": { type: "boolean" },
      "no-keep-special": { type: "boolean" },
      rules: { type: "string" },
      allow: { type: "string" },
      json: { type: "boolean" },
      list: { type: "boolean" },
      help: { type: "boolean", short: "h" },
      version: { type: "boolean", short: "v" },
    },
  });
  return { opts: values, files: positionals };
}

function categoryList(value, flag) {
  const list = value.split(",").map((s) => s.trim()).filter(Boolean);
  for (const c of list) {
    if (!CATEGORIES[c]) throw new UsageError(`${flag}: unknown category "${c}". Run logscrub --list.`);
  }
  return list;
}

function buildOptions(opts) {
  const categories = {};
  if (opts.only) {
    const only = new Set(categoryList(opts.only, "--only"));
    for (const c of Object.keys(CATEGORIES)) categories[c] = only.has(c);
  }
  if (opts.disable) for (const c of categoryList(opts.disable, "--disable")) categories[c] = false;
  if (opts.format && !["plain", "brackets", "angle", "braces"].includes(opts.format)) {
    throw new UsageError(`--format: use plain, brackets, angle or braces.`);
  }
  return {
    categories,
    keepPrivate: !!opts["keep-private"],
    keepSpecial: !opts["no-keep-special"],
    format: opts.format || "plain",
    customRules: opts.rules ? readText(opts.rules) : "",
    allowlist: opts.allow ? readText(opts.allow) : "",
  };
}

function readText(file) {
  try {
    return fs.readFileSync(file, "utf8").replace(/^﻿/, "");
  } catch (e) {
    throw new UsageError(`cannot read ${file}: ${e.code || e.message}`);
  }
}

function readStdin() {
  return fs.readFileSync(0, "utf8").replace(/^﻿/, "");
}

function readInputs(files) {
  if (files.length === 0) {
    if (process.stdin.isTTY) throw new UsageError("no input. Pass a file or pipe text into logscrub (see --help).");
    return [{ name: "<stdin>", text: readStdin() }];
  }
  return files.map((f) => ({ name: f, text: f === "-" ? readStdin() : readText(f) }));
}

function lineCol(text, index) {
  let line = 1;
  let last = -1;
  for (let i = text.indexOf("\n"); i !== -1 && i < index; i = text.indexOf("\n", i + 1)) {
    line++;
    last = i;
  }
  return [line, index - last];
}

function writeOut(file, content) {
  fs.mkdirSync(path.dirname(path.resolve(file)), { recursive: true });
  fs.writeFileSync(file, content);
}

function runRestore(opts, files) {
  if (!opts.map) throw new UsageError("--restore needs --map <file.json> (created with -m when scrubbing).");
  let map;
  try {
    map = JSON.parse(readText(opts.map));
  } catch (e) {
    if (e instanceof UsageError) throw e;
    throw new UsageError(`${opts.map} is not a valid LogScrub map.`);
  }
  if (!map || !Array.isArray(map.replacements)) throw new UsageError(`${opts.map} is not a valid LogScrub map.`);
  const text = readInputs(files)
    .map((i) => restore(i.text, map.replacements))
    .join("");
  if (opts.output) writeOut(opts.output, text);
  else process.stdout.write(text);
  return EXIT_OK;
}

function runScrub(opts, files) {
  if (opts.output && opts["out-dir"]) throw new UsageError("use either --output or --out-dir, not both.");
  const options = buildOptions(opts);
  options.state = createState(); // misma numeración en todos los archivos
  const inputs = readInputs(files);
  const results = inputs.map((input) => ({ input, result: scrub(input.text, options) }));

  for (const { result } of results) {
    for (const e of result.errors) process.stderr.write(`logscrub: rule line ${e.line}: ${e.message}\n`);
  }

  const replacements = [...options.state.byKey.values()];
  const total = results.reduce((n, r) => n + r.result.findings.length, 0);

  if (opts.check) {
    // Solo ubicación y tipo: nunca se imprime el valor sensible.
    for (const { input, result } of results) {
      for (const f of result.findings) {
        const [line, col] = lineCol(input.text, f.start);
        process.stderr.write(`${input.name}:${line}:${col}  ${f.category}  (${f.detector})\n`);
      }
    }
    process.stderr.write(total ? `logscrub: ${total} sensitive value(s) found.\n` : "logscrub: clean.\n");
    return total ? EXIT_FOUND : EXIT_OK;
  }

  if (opts.map) {
    const data = { tool: "logscrub", version, format: options.format, replacements };
    writeOut(opts.map, JSON.stringify(data, null, 2) + "\n");
  }

  if (opts.json) {
    const stats = {};
    for (const { result } of results) {
      for (const [k, v] of Object.entries(result.stats)) stats[k] = (stats[k] || 0) + v;
    }
    const json = { output: results.map((r) => r.result.output).join(""), replacements, stats };
    const text = JSON.stringify(json, null, 2) + "\n";
    if (opts.output) writeOut(opts.output, text);
    else process.stdout.write(text);
  } else if (opts["out-dir"]) {
    for (const { input, result } of results) {
      const base = input.name === "<stdin>" || input.name === "-" ? "stdin.txt" : path.basename(input.name);
      const ext = path.extname(base);
      const target = path.join(opts["out-dir"], `${base.slice(0, base.length - ext.length)}.scrubbed${ext || ".txt"}`);
      writeOut(target, result.output);
    }
  } else {
    const text = results.map((r) => r.result.output).join("");
    if (opts.output) writeOut(opts.output, text);
    else process.stdout.write(text);
  }

  if (opts.stats) {
    const byCat = {};
    for (const { result } of results) {
      for (const [k, v] of Object.entries(result.stats)) byCat[k] = (byCat[k] || 0) + v;
    }
    const detail = Object.entries(byCat)
      .map(([k, v]) => `${k}: ${v}`)
      .join(", ");
    process.stderr.write(`logscrub: ${total} value(s) replaced, ${replacements.length} unique${detail ? ` (${detail})` : ""}.\n`);
  }
  return EXIT_OK;
}

function main(argv) {
  let parsed;
  try {
    parsed = parse(argv);
  } catch (e) {
    process.stderr.write(`logscrub: ${e.message}\nRun logscrub --help for usage.\n`);
    return EXIT_USAGE;
  }
  const { opts, files } = parsed;
  if (opts.help) {
    process.stdout.write(HELP);
    return EXIT_OK;
  }
  if (opts.version) {
    process.stdout.write(`${version}\n`);
    return EXIT_OK;
  }
  if (opts.list) {
    for (const [id, c] of Object.entries(CATEGORIES)) process.stdout.write(`${id.padEnd(12)} ${c.prefix.padEnd(12)} ${c.label}\n`);
    return EXIT_OK;
  }
  try {
    return opts.restore ? runRestore(opts, files) : runScrub(opts, files);
  } catch (e) {
    if (e instanceof UsageError) {
      process.stderr.write(`logscrub: ${e.message}\n`);
      return EXIT_USAGE;
    }
    throw e;
  }
}

if (require.main === module) {
  process.exitCode = main(process.argv.slice(2));
}

module.exports = { main };
