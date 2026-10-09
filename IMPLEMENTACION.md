# netlab - Resumen de Implementación

## 1. Enlace Público Temporal para Justificación (`/r/:token`)

### Qué se implementó
Sistema completo de enlaces compartibles públicos para informes de **web-checker** (y cualquier herramienta).

### Flujo
1. Usuario ejecuta comprobación → recibe `executionId`
2. Marca "Crear enlace público temporal" + días (1-90, default 7)
3. Frontend: `POST /api/compartir { ejecucionId, ttlDias }`
4. Backend: crea token opaco en tabla `compartidos` (8-9 chars base64url)
5. Devuelve `{ shareUrl: "/r/abc123", expiraEn: "2026-10-09T..." }`
6. Tercero abre `/r/abc123` → HTML standalone sin autenticación
7. Expiración automática (410) o revocación manual (`DELETE /api/compartir/:token`)

### Archivos modificados
| Archivo | Cambios |
|---------|---------|
| `src/server/historial.js` | Tabla `compartidos` + métodos `crearCompartido/obtenerCompartido/revocarCompartido` |
| `src/server/app.js` | Rutas `GET /r/:token` (público), `POST/DELETE /api/compartir` (auth) |
| `src/tools/web-checker.js` | Campos `compartir` (checkbox) + `ttlDiasCompartir` (number, shownWhen: compartir) |
| `src/formats/html.js` | Render standalone ya compatible |
| `web/src/components/informe/Informe.tsx` | Componente `CompartirBtn` con copy-to-clipboard |
| `web/src/styles.css` | Estilos `.compartido`, `.fila` |

### Seguridad
- Token opaco (no revela UUID interno ni owner)
- `Result` ya pasa por `redactDeep` → sin secretos en HTML
- Solo owner puede crear/revocar; cualquiera puede leer
- TTL configurable (`SHARE_TTL_DIAS=7`, `SHARE_TTL_MAX_DIAS=90`)
- Rate-limit global ya protege `POST /api/compartir`

---

## 2. Multi-Usuario (Autenticación Mejorada)

### Qué se implementó
Sistema de usuarios con roles (`admin`/`user`) en SQLite, reemplaza el single-user de `.env`.

### Nuevos módulos
| Archivo | Descripción |
|---------|-------------|
| `src/server/password.js` | `hashPassword`, `verificarPassword`, `igual` (scrypt, timing-safe) |
| `src/server/usuarios.js` | Clase `Usuarios` (CRUD usuarios, autenticación) |

### Auth actualizado (`src/server/auth.js`)
- Constructor recibe `opciones.usuarios` (instancia de `Usuarios`)
- Sesiones guardan `{ usuario, role, expira }`
- `identidad()` devuelve `{ usuario, role, local }`
- `entrar()` usa `usuarios.autenticar(username, password)`

### API de administración (`/api/usuarios`)
| Método | Ruta | Auth | Descripción |
|--------|------|------|-------------|
| GET | `/api/usuarios` | admin | Lista usuarios |
| POST | `/api/usuarios` | admin | Crea usuario (username, password ≥8, role) |
| PATCH | `/api/usuarios/:id` | admin | Actualiza password/role/activo |
| DELETE | `/api/usuarios/:id` | admin | Borra usuario (no auto-borrado) |

### Sesión y Login
- `/api/sesion` devuelve `{ autenticado, usuario, role, csrf, ... }`
- Login devuelve `{ autenticado, usuario, role, csrf }`
- Middleware `exigeAdmin` protege rutas de gestión

### Configuración (`.env`)
```bash
AUTH_ENABLED=true
# AUTH_USER y AUTH_PASSWORD_HASH ya no se usan
# Usuarios se crean via API o script
```

### Scripts útiles
```bash
# Generar hash para seed inicial
npm run hash-password -- "mi-password-seguro"

# Crear usuario admin inicial (una vez en VPS)
node -e "
const { Usuarios } = require('./src/server/usuarios');
const u = new Usuarios();
u.crear({ username: 'admin', password: 'cambia-esto-ya', role: 'admin' });
console.log('Admin creado');
"
```

---

## 3. Despliegue en VPS (Ubuntu 22.04)

### Requisitos
- Node.js ≥ 24 (SQLite sync incluido)
- npm
- 512 MB RAM mínimo, 1 GB recomendado
- Puerto 4310 (configurable `PORT`)

### Pasos

```bash
# 1. Instalar Node 24 (via nvm recomendado)
curl -o- https://raw.githubusercontent.com/nvm-sh/nvm/v0.39.7/install.sh | bash
source ~/.bashrc
nvm install 24
nvm use 24

# 2. Clonar y compilar
git clone <tu-repo> netlab
cd netlab
npm ci
npm run build

# 3. Configurar variables de entorno
cp .env.example .env
# Editar .env:
# AUTH_ENABLED=true
# PUBLIC_URL=https://tu-dominio.com
# HOST=0.0.0.0
# PORT=4310
# SHARE_TTL_DIAS=7
# SHARE_TTL_MAX_DIAS=90

# 4. Crear usuario admin inicial
node -e "
const { Usuarios } = require('./src/server/usuarios');
const u = new Usuarios();
try {
  u.crear({ username: 'admin', password: 'password-super-seguro', role: 'admin' });
  console.log('Admin creado');
} catch(e) {
  console.log('Ya existe:', e.message);
}
u.cerrar();
"

# 5. Servicio systemd
sudo tee /etc/systemd/system/netlab.service <<'EOF'
[Unit]
Description=netlab - Network diagnostics
After=network.target

[Service]
Type=simple
User=www-data
WorkingDirectory=/home/www-data/netlab
ExecStart=/usr/bin/node src/index.js
Restart=on-failure
RestartSec=5
Environment=NODE_ENV=production
EnvironmentFile=/home/www-data/netlab/.env
# Hardening
NoNewPrivileges=true
PrivateTmp=true
ProtectSystem=strict
ProtectHome=true
ReadWritePaths=/home/www-data/netlab/data

[Install]
WantedBy=multi-user.target
EOF

# 6. Permisos y datos
sudo useradd -r -s /bin/false -d /home/www-data www-data 2>/dev/null || true
sudo mkdir -p /home/www-data/netlab/data
sudo chown -R www-data:www-data /home/www-data/netlab

# 7. Iniciar
sudo systemctl daemon-reload
sudo systemctl enable --now netlab
sudo systemctl status netlab

# 8. Nginx reverse proxy (opcional, para HTTPS)
sudo apt install nginx certbot python3-certbot-nginx
sudo certbot --nginx -d tu-dominio.com
# Configurar proxy_pass http://127.0.0.1:4310 en /etc/nginx/sites-available/tu-dominio.com
```

### Verificación
```bash
# Health check
curl https://tu-dominio.com/api/sesion

# Login
curl -X POST https://tu-dominio.com/api/sesion \
  -H "Content-Type: application/json" \
  -d '{"usuario":"admin","password":"password-super-seguro"}' \
  -c cookies.txt

# Ejecutar web-checker con enlace compartido
curl -X POST https://tu-dominio.com/api/run \
  -H "Content-Type: application/json" \
  -H "X-CSRF-Token: <token-de-sesion>" \
  -b cookies.txt \
  -d '{"tool":"web-checker","params":{"url":"ejemplo.com","compartir":true,"ttlDiasCompartir":7}}'

# Ver informe público
curl https://tu-dominio.com/r/abc123
```

---

## 4. Herramientas Incluidas (Resumen)

| Herramienta | ID | Qué hace | Qué resuelve |
|-------------|-----|----------|--------------|
| **Comprobador de sitios web** | `web-checker` | Sondea HTTP(S), DNS, TLS, RDAP, redirecciones | ¿Está este sitio arriba? ¿Por qué no carga? |
| **Analizador de IP** | `ip-audit` | AbuseIPDB, DNSBL, RDAP, geolocalización | ¿Esta IP es mala? ¿Está en listas negras? |
| **Comprobador DNS** | `dns-checker` | Consulta A/AAAA/MX/TXT/SPF/DMARC/DKIM, compara resolvers | ¿Resuelve bien el dominio? ¿Coincide 1.1.1.1? |
| **Analizador de correo** | `mail-checker` | SPF, DKIM, DMARC, MTA-STS, TLS-RPT, BIMI, contenido | ¿Mi correo está bien autenticado? |
| **Analizador de subredes** | `subnet-analyzer` | VLSM, división igual, listado hosts, CIDR ↔ máscara | Planear redes, calcular subredes |
| **Analizador WHOIS/RDAP** | `rdap-client` | Caducidad, registrador, retenciones, contactos abuse | ¿Cuándo caduca el dominio? ¿Quién es el abuse? |

### Formatos de salida (todos)
- **HTML** - Standalone, embebido CSS, imprimible, evidencia
- **PDF** - Igual contenido, para adjuntar/archivar
- **JSON** - Canónico, para automatización
- **Markdown** - Para wikis, issues, docs
- **TXT** - Terminal, logs, legible humano

---

## 5. Arquitectura Clave

```
src/
├── core/           # Contratos, errores, tiempo, red, redact, result
├── formats/        # html, json, md, pdf, txt (render desde Result)
├── server/
│   ├── app.js      # Express + rutas + middlewares
│   ├── auth.js     # Sesiones, CSRF, rate-limit, multi-user
│   ├── usuarios.js # CRUD usuarios SQLite
│   ├── password.js # scrypt hash/verify
│   ├── historial.js# SQLite ejecuciones + deduplicación por huella
│   ├── herramientas.js # Registro dinámico de tools
│   └── validar.js  # Validación de params contra campos
└── tools/          # Cada tool: campos + ejecutar() → Result
```

### Principios
- **Servidor agnóstico**: no hay `if (tool === 'x')` en `app.js`
- **Result inmutable**: formatos renderizan desde `Result` guardado, no cache
- **Deduplicación por huella**: hash del `Result` sin reloj → misma ejecución = mismo registro
- **Redact antes de guardar**: secretos nunca tocan disco ni logs

---

## 6. Pruebas

```bash
npm test          # 691 tests unitarios/integración
npm run build     # TypeScript + Vite build
```

### Tests nuevos añadidos
- `test/historial-compartir.test.js` — compartir crear/obtener/revocar/expirar
- Tests en `web-checker.test.js` — campos compartir/ttl, opciones por defecto
- Tests en `server.test.js` — auth multi-user, login, CSRF, admin endpoints

---

## 7. Configuración Clave (`.env`)

```bash
# Servidor
HOST=0.0.0.0
PORT=4310
NODE_ENV=production

# Auth
AUTH_ENABLED=true
# Usuarios via API, no .env

# Compartir
PUBLIC_URL=https://tu-dominio.com
SHARE_TTL_DIAS=7
SHARE_TTL_MAX_DIAS=90

# APIs externas (opcionales)
ABUSEIPDB_API_KEY=xxx
SPAMHAUS_DQS_KEY=xxx
MAIL_PROFILES=b1,b2
MAIL_b1_HOST=smtp.tu-server.com
MAIL_b1_PORT=587
MAIL_b1_USER=alertas@tu-dominio.com
MAIL_b1_PASS=xxx
MAIL_b1_FROM=netlab@tu-dominio.com
```

---

## 8. Próximos Pasos Sugeridos

- [x] Interfaz web de administración de usuarios (página `/admin`)
- [x] Logs de auditoría (quién creó/revocó enlaces)
- [x] Métricas Prometheus (`/metrics`)
- [x] Backup automático de `data/netlab.db`
- [x] Rate-limit por usuario en `/api/run` (ya existe por IP)

### Cómo se hizo el punto 8

- **Backup**: `src/server/backup.js` snapshot `VACUUM INTO` a `data/backups/netlab-AAAAMMDD-HHMMSS.sqlite`
  con retención (por defecto 7 copias, hora de 03:00 local, copia inmediata al arrancar).
  Endpoints admin `GET/POST /api/backups`, evento de auditoría `backup_realizado`.
- **Auditoría**: la API `GET /api/auditoria` ya filtra por tipo/usuario; el admin ahora la muestra en
  `/admin` con filtro por tipo, junto con las copias de seguridad.
- **Bug de revocación corregido**: `DELETE /api/compartir/:token` leía la variable `revogado` (nunca
  definida) y respondía 500 siempre, y auditaba el tipo mal escrito `compartir_revogado`. Ahora usa
  `TIPOS.COMPARTIR_REVOCADO` y responde 404 como corresponde cuando el enlace no existe.