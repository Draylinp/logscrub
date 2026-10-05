# Changelog

## 0.6.1 · 2026-10-05

- Published on npm as [`@draylinp/logscrub`](https://www.npmjs.com/package/@draylinp/logscrub): `npx @draylinp/logscrub file.log`
- Demo GIF and social preview image
- The restored reply now wraps long lines

## 0.6.0 · 2026-10-05

- **Command line:** `npx github:Draylinp/logscrub`, with stdin/stdout, multiple files with shared numbering, `--out-dir`, `--map` / `--restore`, `--check` for CI (never prints the values), `--json`, `--stats`
- **Network devices:** Juniper Junos, Huawei VRP, VyOS / EdgeOS, pfSense / OPNsense `config.xml`, WireGuard, OpenVPN static keys
- **Cloud and DevOps:** Kubernetes Secrets, Azure (connection strings, SAS, client secrets), Google service accounts and OAuth, Docker, Docker Hub, DigitalOcean, Vault, SendGrid, Shopify, Hugging Face, PyPI, Discord webhooks, CLI `--password`/`--token` flags
- **Personal data:** phone numbers, credit cards (Luhn), IBAN (mod 97), Dominican cédula and RNC, Spanish DNI, Mexican CURP, US SSN
- **Users and devices:** usernames in Windows/Linux/macOS paths, Windows SIDs, serial numbers
- Fewer false positives for hostnames (`p.id`, `u.name`, `logger.info(`)

## 0.5.0 · 2026-10-05

- English / Spanish interface (auto-detected, switchable, `?lang=en` / `?lang=es`)
- Light / dark / auto theme toggle
- Placeholder formats: `IP_1`, `[IP_1]`, `<IP_1>`, `{{IP_1}}`
- **Restore a reply**: put the original values back into a text that uses the placeholders
- Export the replacements table as CSV
- Synchronized scrolling between original and result

## 0.4.0 · 2026-10-05

- Detectors: IPv4/IPv6, MAC, emails, hostnames, usernames, secrets (MikroTik, Cisco IOS, FortiGate, key=value, URLs), API tokens, PEM private keys
- Consistent placeholders, custom rules and allowlist
- Highlighted output, stats, replacements table, file open and drag & drop
- Content-Security-Policy with `connect-src 'none'`
