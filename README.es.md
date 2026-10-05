# 🧽 LogScrub

[![Tests](https://github.com/Draylinp/logscrub/actions/workflows/test.yml/badge.svg)](https://github.com/Draylinp/logscrub/actions/workflows/test.yml)
[![Licencia: MIT](https://img.shields.io/badge/licencia-MIT-blue.svg)](LICENSE)

**Limpia logs y configuraciones antes de compartirlos. 100 % en tu navegador, nada se sube.**

🔗 **Pruébalo:** https://draylinp.github.io/logscrub/?lang=es · 🇬🇧 [Read in English](README.md)

Pega un log, la configuración de un router o la salida de un comando. LogScrub reemplaza IPs, MACs, correos, hostnames, contraseñas y tokens por **marcadores consistentes** (`IP_1`, `HOST_2`), para que el texto siga sirviendo para diagnosticar con soporte, en un foro o con un asistente de IA.

```diff
- Oct  5 10:21:33 web-prod-01 sshd[2211]: Failed password for invalid user admin from 203.0.113.45 port 52144
+ Oct  5 10:21:33 HOST_1 sshd[2211]: Failed password for invalid user USER_1 from IP_1 port 52144
- username soporte privilege 15 secret 0 Cisco#2026
+ username USER_2 privilege 15 secret 0 SECRET_1
- ip address 198.51.100.2 255.255.255.252
+ ip address IP_2 255.255.255.252
```

## Funciones

- **Marcadores consistentes:** el mismo valor siempre recibe el mismo marcador, así se puede seguir qué se comunica con qué.
- **Pensado para configuraciones:** conserva máscaras, wildcards de Cisco, `0.0.0.0` y loopback, para que la configuración siga teniendo sentido.
- **Restaurar una respuesta:** pega la respuesta que te dieron y LogScrub pone los valores originales en lugar de los marcadores.
- **Reglas personalizadas y lista de permitidos:** oculta nombres de tu empresa o proyecto, y nunca ocultes cosas como los DNS públicos.
- **Formato del marcador a elegir:** `IP_1`, `[IP_1]`, `<IP_1>` o `{{IP_1}}`.
- Abre archivos o arrástralos, copia o descarga el resultado y exporta la tabla de reemplazos en CSV.
- Interfaz en español e inglés, con tema claro, oscuro y automático.

## Qué detecta

| Categoría | Ejemplos |
|---|---|
| IPv4 / IPv6 | `203.0.113.45`, `2001:db8::1` (opcionalmente conserva los rangos privados) |
| Direcciones MAC | `00:1A:2B:3C:4D:5E`, `00-1a-2b-…`, `001a.2b3c.4d5e` (los tres formatos → mismo marcador) |
| Correos y hostnames | `usuario@example.com`, `db01.internal.example.com`, el campo host de syslog |
| Contraseñas y secretos | `password=`, `"api_key":`, `?token=`, `postgres://usuario:clave@host` |
| Equipos de red | **MikroTik** (`wpa2-pre-shared-key`, `/system identity`), **Cisco IOS** (`enable secret`, `username … secret`, `snmp-server community`, `key-string`, `isakmp key`), **FortiGate** (`set password ENC`, `set psksecret`, `set hostname`) |
| Tokens | JWT, AWS, GitHub, GitLab, Slack, Google, Stripe, claves API `sk-…`, npm, Telegram, cabeceras `Authorization:` |
| Claves privadas | Bloques PEM / OpenSSH `PRIVATE KEY` completos |
| Usuarios | `username …`, `user=`, sshd `for invalid user …` |

## Privacidad

- Todo se ejecuta localmente en JavaScript. La Content-Security-Policy de la página define `connect-src 'none'`, así que **el propio navegador bloquea cualquier petición de red**.
- El texto nunca se guarda. Solo se guardan tus preferencias en `localStorage`: categorías, opciones, reglas, idioma y tema.
- La tabla de reemplazos contiene los valores originales. Es para ti, no la compartas.

> ⚠️ LogScrub reduce el riesgo, pero ninguna herramienta detecta el 100 % de los datos sensibles. Revisa siempre el resultado antes de compartirlo.

## Desarrollo

No hay paso de compilación ni dependencias. Sirve la carpeta con cualquier servidor estático, por ejemplo la extensión *Live Server* de VS Code, y abre `index.html`.

```bash
npm test   # pruebas del motor con el test runner de Node (Node 18+)
```

```
index.html          página
css/styles.css      estilos (tokens claro/oscuro)
js/detectors.js     reglas de detección: el orden marca la prioridad
js/scrubber.js      motor: solapamientos, marcadores, reglas, restaurar
js/i18n.js          textos en español e inglés
js/theme.js         aplica el tema guardado antes de pintar
js/app.js           interfaz
tests/              pruebas del motor
```

¿Quieres añadir un detector? Agrégalo en `js/detectors.js` en la posición de prioridad adecuada, añade una prueba en `tests/scrubber.test.js` y ejecuta `npm test`.

## Roadmap

- [x] v0.1 · Interfaz + IPv4/IPv6, MAC, correo, hostname
- [x] v0.2 · Marcadores consistentes
- [x] v0.3 · Secretos en configuraciones MikroTik, Cisco y FortiGate, JWT, claves cloud
- [x] v0.4 · Reglas personalizadas
- [x] v0.5 · Versión en inglés, selector de tema, restaurar respuestas, exportar CSV
- [ ] v0.6 · Más equipos (Juniper, Ubiquiti, pfSense / OPNsense)
- [ ] v1.0 · Versión CLI

Detalles en [CHANGELOG.md](CHANGELOG.md).

## Soporte y sugerencias

- 🐛 **¿Encontraste un error o algo que no se detectó?** [Abre un reporte](https://github.com/Draylinp/logscrub/issues/new?template=bug_report.yml).
- 💡 **¿Tienes una idea o necesitas soporte para otro equipo?** [Envía una sugerencia](https://github.com/Draylinp/logscrub/issues/new?template=feature_request.yml).
- 🔒 **¿Un problema de seguridad?** [Repórtalo en privado](https://github.com/Draylinp/logscrub/security/advisories/new). Por favor, no uses un issue público.

> **Nunca pegues logs, contraseñas ni tokens reales en un issue.** Usa valores falsos con el mismo formato, como las IPs de documentación `203.0.113.x` y `example.com`.

Los pull requests son bienvenidos.

## Licencia

[MIT](LICENSE) © Draylin
