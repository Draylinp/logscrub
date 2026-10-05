# 🧽 LogScrub

**Sanitize logs and configs before sharing them. 100% in your browser.**
**Limpia logs y configuraciones antes de compartirlos. 100 % en tu navegador.**

🔗 **Demo:** https://draylinp.github.io/logscrub/

## What is it? · ¿Qué es?

**EN:** Paste logs, router configs or command output and LogScrub replaces IPs, MAC addresses, emails, hostnames, passwords and tokens with consistent placeholders (`IP_1`, `HOST_2`), so the text stays useful for troubleshooting. Nothing leaves your browser.

**ES:** Pega logs, configuraciones de routers o salidas de comandos y LogScrub reemplaza IPs, MACs, correos, hostnames, contraseñas y tokens por marcadores consistentes (`IP_1`, `HOST_2`), para que el texto siga sirviendo para diagnosticar. Nada sale de tu navegador.

```diff
- Oct  5 10:21:33 web-prod-01 sshd[2211]: Failed password for invalid user admin from 203.0.113.45 port 52144
+ Oct  5 10:21:33 HOST_1 sshd[2211]: Failed password for invalid user USER_1 from IP_1 port 52144
- username soporte privilege 15 secret 0 Cisco#2026
+ username USER_2 privilege 15 secret 0 SECRET_1
```

## What it detects · Qué detecta

| Category | Examples |
|---|---|
| IPv4 / IPv6 | `203.0.113.45`, `2001:db8::1` (keeps netmasks, wildcards, `0.0.0.0`, loopback) |
| MAC | `00:1A:2B:3C:4D:5E`, `00-1a-…`, `001a.2b3c.4d5e` (same MAC → same placeholder) |
| Emails, hostnames | `user@example.com`, `db01.internal.example.com`, syslog host field |
| Passwords & secrets | `password=`, `"api_key":`, `?token=`, `postgres://user:pass@host` |
| Network configs | MikroTik (`wpa2-pre-shared-key`, `/system identity`), Cisco IOS (`enable secret`, `username … secret`, `snmp-server community`, `key-string`), FortiGate (`set password ENC`, `set psksecret`) |
| Tokens | JWT, AWS, GitHub, GitLab, Slack, Google, Stripe, OpenAI/Anthropic-style `sk-…`, npm, Telegram, `Authorization:` headers |
| Private keys | Full PEM / OpenSSH `PRIVATE KEY` blocks |
| Users | `username …`, `user=`, sshd `for invalid user …` |

Plus **custom rules** (literal text or `/regex/`, with your own placeholder name) and an **allowlist** of values that must never be replaced.

## Privacy · Privacidad

- Everything runs locally in JavaScript. The page's Content-Security-Policy sets `connect-src 'none'`, so the browser itself blocks any network request.
- Your text is never stored. Only your preferences (enabled categories, custom rules) are saved in `localStorage`.
- The replacements table shows the original values so you can interpret answers. Don't share it.

> ⚠️ LogScrub reduces risk but no tool catches 100% of sensitive data. Always review the output before sharing.

## Development · Desarrollo

No build step and no dependencies. Open `index.html` with any static server (e.g. VS Code Live Server).

```bash
npm test      # runs the engine tests with Node's built-in test runner (Node 18+)
```

```
js/detectors.js   detection rules (order = priority)
js/scrubber.js    engine: overlaps, consistent placeholders, custom rules
js/app.js         UI
tests/            engine tests
```

## Roadmap

- [x] v0.1 · UI + IPv4/IPv6, MAC, email, hostname
- [x] v0.2 · Consistent placeholders
- [x] v0.3 · Secrets in MikroTik, Cisco and FortiGate configs, JWT, cloud keys
- [x] v0.4 · Custom rules
- [ ] v1.0 · CLI version

## License · Licencia

MIT © Draylin
