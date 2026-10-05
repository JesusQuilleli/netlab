# netlab

Consola unificada de diagnóstico de **red, DNS, IP y correo**. Siete
herramientas en una sola interfaz web, con historial, informes exportables,
auditoría y control de acceso por usuarios.

Cada herramienta es un módulo autónomo en `src/tools/`, y la interfaz se genera
a partir de la descripción que publica cada uno. Añadir una herramienta es
dejar el fichero: no hay que tocar ni el servidor ni la interfaz.

| Herramienta | Qué hace |
|---|---|
| `ip-audit` | Auditoría completa de una IP: geolocalización, ASN, uso de AbuseIPDB, zonas de pago de Spamhaus |
| `ip-abuse` | Consulta de AbuseIPDB y de las listas de abuso |
| `subnet-analyzer` | Divide una red, calcula VLSM y solapamientos |
| `dns-checker` | Registros, resolución inversa, comparación entre resolvers, SPF/DMARC/DKIM |
| `mail-checker` | Revisa un `.eml` o un texto pegado y explica por qué es spam o no |
| `smtp-validator` | Diagnóstico de un servidor SMTP: TLS, STARTTLS, EHLO, certificados y entrega |
| `web-checker` | Disponibilidad, cabeceras, TLS y redirecciones de un sitio |

---

## Requisitos

- **Node.js 24 o superior.** Es obligatorio: el servidor usa `node:sqlite`, que
  es experimental en versiones anteriores. En Ubuntu instalarlo con el
  repositorio de Node, no con `apt install nodejs`, que suele ir muy atras.
- Linux, macOS o Windows. No necesita Docker ni base de datos externa.

## Puesta en marcha en local

```bash
git clone https://github.com/JesusQuilleli/netlab.git
cd netlab
npm install
npm --prefix web install
npm run build          # genera web/dist
cp .env.example .env   # en local puedes dejar AUTH_ENABLED=false
npm start              # http://127.0.0.1:4310
```

Con `AUTH_ENABLED=false` se entra sin contraseña, que es lo cómodo para trabajar
en local. **En la VPS es obligatorio `AUTH_ENABLED=true`.**

### Desarrollo

```bash
npm run dev:api        # servidor con recarga
npm run dev:web        # Vite en el 5173, con /api apuntando al 4310
npm run test:all       # 697 tests de servidor + 76 de interfaz
```

---

## Despliegue en una VPS

Ubuntu o Debian, con un dominio apuntando a la IP del servidor. La guía
completa está en **[docs/DESPLIEGUE.md](docs/DESPLIEGUE.md)**; el resumen es:

```bash
# 1. Instalar Node.js 24, el usuario de servicio y el sistema.
sudo bash deploy/instalar.sh

# 2. Crear el administrador principal.
#    Todavía no hay ninguna cuenta. Hágalo por túnel SSH para no exponer
#    el puerto antes de que exista:
ssh -L 4310:127.0.0.1:4310 usuario@TU_VPS
#   y abra http://127.0.0.1:4310 en el navegador

# 3. Poner nginx con HTTPS delante.
sudo cp /opt/netlab/deploy/nginx.conf /etc/nginx/sites-available/netlab
sudo nano /etc/nginx/sites-available/netlab      # sustituir DOMINIO.TLD
sudo ln -s /etc/nginx/sites-available/netlab /etc/nginx/sites-enabled/netlab
sudo nginx -t && sudo systemctl reload nginx
sudo certbot --nginx -d TU_DOMINIO

# 4. Comprobar el estado de seguridad.
cd /opt/netlab && npm run manual
```

### Cómo está montado

```
Internet ──HTTPS──> nginx ──http loopback──> netlab (127.0.0.1:4310)
                                                 │
                                                 └── data/netlab.db
                                                     usuarios, historial,
                                                     auditoría, informes
```

El servidor **no gestiona TLS** y por eso debe quedar en `127.0.0.1`, con el
proxy delante. Con `HOST=0.0.0.0` el puerto de diagnóstico queda expuesto y la
contraseña viaja en claro.

`TRUST_PROXY=loopback` (el valor por defecto) hace que netlab lea la IP real del
cliente de `X-Forwarded-For`, pero solo si quien conecta es la propia máquina.
Sin esto, el límite de intentos por IP sería global y la auditoría registraría
siempre `127.0.0.1`.

### Actualizar

```bash
cd /opt/netlab && git pull --ff-only
sudo -u netlab npm ci --omit=dev
sudo -u netlab npm ci --prefix web && sudo -u netlab npm run build
sudo systemctl restart netlab
```

---

## Cuentas

Las cuentas **no están en el `.env`**. Viven en la tabla `usuarios` de
`data/netlab.db`, con la contraseña derivada con scrypt.

Al abrir el sistema por primera vez sin ningún usuario, la interfaz pide crear
el **administrador principal**. Ese endpoint queda cerrado para siempre en
cuanto existe un usuario, de modo que nadie más puede crear su propia cuenta de
admin desde fuera. A partir de ahí, el administrador da de alta al resto de
usuarios desde `/admin`.

## Seguridad

- Contraseñas con **scrypt** y sal por usuario; nunca en texto plano ni en el
  historial.
- Sesiones en cookie `HttpOnly` + `SameSite=Strict` (+ `Secure` con HTTPS) y
  **token CSRF** en cada operación que modifica estado.
- **Límite de intentos** por IP real: 8 en 15 minutos.
- Cabeceras `Content-Security-Policy`, `X-Content-Type-Options` y
  `X-Frame-Options` en cada respuesta.
- Las claves de API se **enmascaran** en los informes y en el historial.
- Servicio systemd con `NoNewPrivileges`, `ProtectSystem=strict` y usuario
  dedicado sin shell.
- `npm run manual` genera un PDF con el estado de la revisión de seguridad por
  área, y dice si es desplegable.

### Credenciales expuestas: rotar

Hay claves de AbuseIPDB en claro en el historial del proyecto y en ficheros
antiguos de `legacy/`. **Da por hecho que están comprometidas y rótalas antes de
desplegar.** Una clave filtrada en `legacy/` también sirve para que alguien te
cobre las consultas.

## Estructura

```
src/
  core/        red, correo, formats, errores, config, redacción de secretos
  tools/       las siete herramientas (cada una, autocontenida)
  server/      app.js (rutas), auth, usuarios, historial, auditoría, métricas
  formats/     json, md, html, txt, pdf
  docs/        generador del manual PDF
web/           interfaz React (Vite), se compila a web/dist
deploy/        systemd, nginx, script de instalación
data/          netlab.db, informes, logs — NO se versiona
legacy/        proyectos antiguos congelados — NO se versiona
```

## Documentación

- [Manual de la aplicación (PDF)](docs/manual-netlab.pdf) — qué hace cada módulo,
  para qué sirve y cómo se usa. Se regenera con `npm run manual`.
- [Guía de despliegue](docs/DESPLIEGUE.md)