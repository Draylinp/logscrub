# 🧽 LogScrub

[![Tests](https://github.com/Draylinp/logscrub/actions/workflows/test.yml/badge.svg)](https://github.com/Draylinp/logscrub/actions/workflows/test.yml)
[![Licencia: MIT](https://img.shields.io/badge/licencia-MIT-blue.svg)](LICENSE)

**Limpia logs y configuraciones antes de compartirlos. 100 % local, en tu navegador o en tu terminal. Nada se sube.**

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
| Equipos de red | **MikroTik**, **Cisco IOS**, **FortiGate**, **Juniper Junos** (`$9$`, `## SECRET-DATA`, `host-name`), **Huawei VRP** (`cipher`, `local-user`, `sysname`), **VyOS / EdgeOS** (`plaintext-password`, `pre-shared-secret`), **pfSense / OPNsense** `config.xml`, **WireGuard**, claves estáticas de **OpenVPN** |
| Nube y DevOps | Manifiestos `Secret` de Kubernetes, cadenas de conexión, firmas SAS y client secrets de Azure, JSON de cuentas de servicio y OAuth de Google, `config.json` de Docker, flags `--password` / `--token`, cadenas de conexión de SQL Server |
| Tokens | JWT, AWS, GitHub, GitLab, Slack, Google, Stripe, claves API `sk-…`, npm, Docker Hub, DigitalOcean, Vault, SendGrid, Shopify, Hugging Face, PyPI, webhooks de Discord y Slack, Telegram, cabeceras `Authorization:` |
| Claves privadas | Bloques PEM / OpenSSH `PRIVATE KEY` completos |
| Usuarios | `username …`, `user=`, sshd `for invalid user …`, `C:\Users\nombre`, `/home/nombre`, `/Users/nombre`, SIDs de Windows |
| Datos personales | Teléfonos, tarjetas de crédito (validadas con Luhn), IBAN (con dígito de control), cédula y RNC dominicanos, DNI español, CURP mexicano, SSN de EE. UU. |
| Números de serie | Cisco `Processor board ID`, `SN:`, MikroTik `serial-number`, FortiGate `Serial-Number` |

## Línea de comandos

El mismo motor funciona en tu terminal (Node.js 18.3+). No se instala nada de forma global y nada sale de tu equipo.

```bash
npx github:Draylinp/logscrub router.rsc > router.limpio.rsc
```

```bash
logscrub app.log                         # limpia y escribe en stdout
journalctl -u nginx | logscrub --stats   # desde una tubería, resumen en stderr
logscrub -m mapa.json *.log -d limpios/  # un archivo limpio por entrada, misma numeración
logscrub --restore -m mapa.json resp.txt # devuelve los valores originales
logscrub --check config/*.yaml           # CI / pre-commit: código 1 si hay secretos
```

Opciones útiles: `--only ipv4,secret`, `--disable hostname`, `--keep-private`, `-f brackets`, `--rules reglas.txt`, `--allow permitidos.txt`, `--json`. Usa `logscrub --help` para verlas todas y `logscrub --list` para las categorías.

`--check` solo informa el archivo, la línea, la columna y el tipo de cada hallazgo. Nunca imprime el valor sensible.

## Privacidad

- Todo se ejecuta localmente en JavaScript, en el navegador o en Node.js. La Content-Security-Policy de la página define `connect-src 'none'`, así que **el propio navegador bloquea cualquier petición de red**.
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
bin/logscrub.js     línea de comandos
css/styles.css      estilos (tokens claro/oscuro)
js/detectors.js     reglas de detección: el orden marca la prioridad
js/scrubber.js      motor: solapamientos, marcadores, reglas, restaurar
js/i18n.js          textos en español e inglés
js/theme.js         aplica el tema guardado antes de pintar
js/app.js           interfaz
tests/              pruebas del motor, los detectores y la CLI
```

¿Quieres añadir un detector? Agrégalo en `js/detectors.js` en la posición de prioridad adecuada, añade una prueba en `tests/scrubber.test.js` y ejecuta `npm test`.

## Roadmap

- [x] v0.1 · Interfaz + IPv4/IPv6, MAC, correo, hostname
- [x] v0.2 · Marcadores consistentes
- [x] v0.3 · Secretos en configuraciones MikroTik, Cisco y FortiGate, JWT, claves cloud
- [x] v0.4 · Reglas personalizadas
- [x] v0.5 · Versión en inglés, selector de tema, restaurar respuestas, exportar CSV
- [x] v0.6 · Juniper, Huawei, VyOS/EdgeOS, pfSense/OPNsense; secretos de nube y DevOps; datos personales; rutas de usuario; números de serie; CLI
- [ ] v0.7 · Publicar en npm, hook de pre-commit
- [ ] v1.0 · API estable

Detalles en [CHANGELOG.md](CHANGELOG.md).

## Soporte y sugerencias

- 🐛 **¿Encontraste un error o algo que no se detectó?** [Abre un reporte](https://github.com/Draylinp/logscrub/issues/new?template=bug_report.yml).
- 💡 **¿Tienes una idea o necesitas soporte para otro equipo?** [Envía una sugerencia](https://github.com/Draylinp/logscrub/issues/new?template=feature_request.yml).
- 🔒 **¿Un problema de seguridad?** [Repórtalo en privado](https://github.com/Draylinp/logscrub/security/advisories/new). Por favor, no uses un issue público.

> **Nunca pegues logs, contraseñas ni tokens reales en un issue.** Usa valores falsos con el mismo formato, como las IPs de documentación `203.0.113.x` y `example.com`.

Los pull requests son bienvenidos.

## Licencia

[MIT](LICENSE) © Draylin
