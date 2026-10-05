# Changelog

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
