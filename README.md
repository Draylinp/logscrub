# 🧽 LogScrub

[![Tests](https://github.com/Draylinp/logscrub/actions/workflows/test.yml/badge.svg)](https://github.com/Draylinp/logscrub/actions/workflows/test.yml)
[![npm](https://img.shields.io/npm/v/@draylinp/logscrub.svg)](https://www.npmjs.com/package/@draylinp/logscrub)
[![License: MIT](https://img.shields.io/badge/license-MIT-blue.svg)](LICENSE)

**Sanitize logs and configs before sharing them. 100% local, in your browser or your terminal. Nothing is uploaded.**

🔗 **Try it:** https://draylinp.github.io/logscrub/ · 🇪🇸 [Leer en español](README.es.md)

<p align="center"><img src="assets/demo.gif" alt="LogScrub replacing IPs, users, passwords and tokens in a log as it is typed" width="860"></p>

Paste a log, a router config or command output. LogScrub replaces IPs, MAC addresses, emails, hostnames, passwords and tokens with **consistent placeholders** (`IP_1`, `HOST_2`), so the text stays useful for troubleshooting with support, a forum or an AI assistant.

```diff
- Oct  5 10:21:33 web-prod-01 sshd[2211]: Failed password for invalid user admin from 203.0.113.45 port 52144
+ Oct  5 10:21:33 HOST_1 sshd[2211]: Failed password for invalid user USER_1 from IP_1 port 52144
- username support privilege 15 secret 0 Cisco#2026
+ username USER_2 privilege 15 secret 0 SECRET_1
- ip address 198.51.100.2 255.255.255.252
+ ip address IP_2 255.255.255.252
```

## Features

- **Consistent placeholders:** the same value always gets the same placeholder, so you can still follow what talks to what.
- **Config-aware:** netmasks, Cisco wildcards, `0.0.0.0` and loopback are kept, so configs still make sense.
- **Restore a reply:** paste the answer you got back and LogScrub puts the original values in place of the placeholders.
- **Custom rules and allowlist:** hide your company or project names, and never hide things like public DNS servers.
- **Choose the placeholder style:** `IP_1`, `[IP_1]`, `<IP_1>` or `{{IP_1}}`.
- Open files or drag & drop them, copy or download the result, and export the replacements table as CSV.
- English and Spanish interface, with light, dark and auto themes.

## What it detects

| Category | Examples |
|---|---|
| IPv4 / IPv6 | `203.0.113.45`, `2001:db8::1` (optionally keep private ranges) |
| MAC addresses | `00:1A:2B:3C:4D:5E`, `00-1a-2b-…`, `001a.2b3c.4d5e` (all three formats → same placeholder) |
| Emails and hostnames | `user@example.com`, `db01.internal.example.com`, the syslog host field |
| Passwords and secrets | `password=`, `"api_key":`, `?token=`, `postgres://user:pass@host` |
| Network devices | **MikroTik**, **Cisco IOS**, **FortiGate**, **Juniper Junos** (`$9$`, `## SECRET-DATA`, `host-name`), **Huawei VRP** (`cipher`, `local-user`, `sysname`), **VyOS / EdgeOS** (`plaintext-password`, `pre-shared-secret`), **pfSense / OPNsense** `config.xml`, **WireGuard**, **OpenVPN** static keys |
| Cloud and DevOps | Kubernetes `Secret` manifests, Azure connection strings, SAS signatures and client secrets, Google service-account JSON and OAuth, Docker `config.json`, `--password` / `--token` flags, SQL Server connection strings |
| Tokens | JWT, AWS, GitHub, GitLab, Slack, Google, Stripe, `sk-…` API keys, npm, Docker Hub, DigitalOcean, Vault, SendGrid, Shopify, Hugging Face, PyPI, Discord and Slack webhooks, Telegram, `Authorization:` headers |
| Private keys | Full PEM / OpenSSH `PRIVATE KEY` blocks |
| Usernames | `username …`, `user=`, sshd `for invalid user …`, `C:\Users\name`, `/home/name`, `/Users/name`, Windows SIDs |
| Personal data | Phone numbers, credit cards (Luhn-checked), IBAN (checksum-validated), Dominican cédula and RNC, Spanish DNI, Mexican CURP, US SSN |
| Serial numbers | Cisco `Processor board ID`, `SN:`, MikroTik `serial-number`, FortiGate `Serial-Number` |

## Command line

The same engine runs in your terminal (Node.js 18.3+). Nothing is installed globally and nothing leaves your machine.

```bash
npx @draylinp/logscrub router.rsc > router.clean.rsc   # no install
npm install -g @draylinp/logscrub                      # or install the logscrub command
```

```bash
logscrub app.log                         # scrub to stdout
journalctl -u nginx | logscrub --stats   # from a pipe, summary on stderr
logscrub -m map.json *.log -d clean/     # one clean file per input, shared numbering
logscrub --restore -m map.json reply.txt # put the original values back
logscrub --check config/*.yaml           # CI / pre-commit: exit 1 if secrets are found
```

Useful options: `--only ipv4,secret`, `--disable hostname`, `--keep-private`, `-f brackets`, `--rules rules.txt`, `--allow allow.txt`, `--json`. Run `logscrub --help` for all of them and `logscrub --list` for the categories.

`--check` reports only the file, line, column and type of each finding. It never prints the sensitive value.

## Privacy

- Everything runs locally in JavaScript, in the browser or in Node.js. The page's Content-Security-Policy sets `connect-src 'none'`, so **the browser itself blocks any network request**.
- Your text is never stored. Only your preferences are saved in `localStorage`: categories, options, custom rules, language and theme.
- The replacements table contains the original values. It's for you, so don't share it.

> ⚠️ LogScrub reduces risk, but no tool catches 100% of sensitive data. Always review the output before sharing it.

## Development

There's no build step and there are no dependencies. Serve the folder with any static server, for example the VS Code *Live Server* extension, and open `index.html`.

```bash
npm test   # engine tests with Node's built-in test runner (Node 18+)
```

```
index.html          page
bin/logscrub.js     command line
css/styles.css      styles (light/dark tokens)
js/detectors.js     detection rules: order = priority
js/scrubber.js      engine: overlaps, consistent placeholders, custom rules, restore
js/i18n.js          English / Spanish texts
js/theme.js         applies the saved theme before first paint
js/app.js           UI
tests/              engine, detector and CLI tests
```

Want to add a detector? Add it to `js/detectors.js` in the right priority position, add a test in `tests/scrubber.test.js` and run `npm test`.

## Roadmap

- [x] v0.1 · UI + IPv4/IPv6, MAC, email, hostname
- [x] v0.2 · Consistent placeholders
- [x] v0.3 · Secrets in MikroTik, Cisco and FortiGate configs, JWT, cloud keys
- [x] v0.4 · Custom rules
- [x] v0.5 · English version, theme toggle, restore replies, CSV export
- [x] v0.6 · Juniper, Huawei, VyOS/EdgeOS, pfSense/OPNsense; cloud & DevOps secrets; personal data; user paths; serial numbers; CLI
- [x] v0.6.1 · Published on npm as `@draylinp/logscrub`
- [ ] v0.7 · Pre-commit hook, more devices
- [ ] v1.0 · Stable API

See [CHANGELOG.md](CHANGELOG.md) for details.

## Support and suggestions

- 🐛 **Found a bug, or something that wasn't detected?** [Open a bug report](https://github.com/Draylinp/logscrub/issues/new?template=bug_report.yml).
- 💡 **Have an idea or need support for another device?** [Send a suggestion](https://github.com/Draylinp/logscrub/issues/new?template=feature_request.yml).
- 🔒 **Security issue?** [Report it privately](https://github.com/Draylinp/logscrub/security/advisories/new). Please don't use a public issue.

> **Never paste real logs, passwords or tokens in an issue.** Use fake values with the same format, such as the `203.0.113.x` documentation IPs and `example.com`.

Pull requests are welcome.

## License

[MIT](LICENSE) © Draylin
