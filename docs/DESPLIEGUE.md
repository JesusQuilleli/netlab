# Despliegue en una VPS

Guía para dejar netlab funcionando detrás de HTTPS en una VPS Ubuntu o Debian.

**Resumen:** ejecute `sudo bash deploy/instalar.sh`, cree el administrador
principal por túnel SSH, ponga nginx delante con un certificado y compruebe el
estado con `npm run manual`. El resto son los detalles y los motivos.

Si algo falla, `journalctl -u netlab -n 50 --no-pager` es siempre el primer
punto de mira.

---

## 0. Antes de empezar

### Requisitos

- Ubuntu 22.04+ o Debian 12+.
- Un dominio apuntando a la IP de la VPS (para el certificado HTTPS).
- El grupo de puertos 80 y 443 libre.

**Node.js 24 es obligatorio.** El servidor usa `node:sqlite`, que es
experimental en versiones anteriores y falla al arrancar. `apt install nodejs`
suele instalar una versión demasiado antigua, por eso `instalar.sh` usa el
repositorio oficial de NodeSource.

### Decidir la visibilidad

Esta es la decisión de seguridad más importante del despliegue, y conviene
tomarla antes de escribir nada:

- **Correcto:** netlab escucha en `127.0.0.1` y nginx sirve el puerto 443 con
  HTTPS. Nadie alcanza el puerto 4310 desde Internet.
- **Incorrecto:** `HOST=0.0.0.0`. El puerto de diagnóstico queda abierto, sin
  TLS y sin que nadie lo haya pedido. Con `AUTH_ENABLED=false` cualquiera que
  llegue puede lanzar diagnósticos.

No hay excepción buena a la segunda. Si necesita el puerto abierto para
diagnosticar desde fuera, use un túnel SSH o una VPN, no `0.0.0.0`.

---

## 1. Instalación automática

```bash
sudo bash deploy/instalar.sh
```

Qué hace, en orden:

1. Comprueba la versión de Node y instala NodeSource 24 si hace falta.
2. Instala `git`, `build-essential`, `python3` y `nginx`.
3. Crea el usuario de servicio `netlab`, sin shell y sin permisos de `sudo`.
4. Copia el proyecto a `/opt/netlab` e instala dependencias.
5. Compila la interfaz (`web/dist`).
6. Crea `.env` desde `.env.example` con `AUTH_ENABLED=true`, permisos `600`.
7. Instala y arranca `netlab.service`.
8. Comprueba que el servicio responde.

Es **idempotente**: se puede volver a ejecutar para actualizar. Si existe
`/opt/netlab/.git` hace `git pull --ff-only`; si no, copia el árbol sin
`.git`, `node_modules`, `web/dist` ni `data`.

### Si prefiere hacerlo a mano

```bash
sudo apt update
sudo apt install -y git build-essential python3 nginx
curl -fsSL https://deb.nodesource.com/setup_24.x | sudo -E bash -
sudo apt install -y nodejs
node -v                       # debe ser v24 o superior

sudo useradd --system --home-dir /opt/netlab --shell /usr/sbin/nologin netlab
sudo mkdir -p /opt/netlab && sudo chown netlab:netlab /opt/netlab

# desde su máquina, con el repositorio ya subido
sudo git clone https://github.com/JesusQuilleli/netlab.git /opt/netlab
sudo chown -R netlab:netlab /opt/netlab

cd /opt/netlab
sudo -u netlab npm ci --omit=dev
sudo -u netlab npm ci --prefix web
sudo -u netlab npm run build
sudo -u netlab mkdir -p data

sudo cp .env.example .env
sudo sed -i 's/^AUTH_ENABLED=.*/AUTH_ENABLED=true/' .env
sudo chmod 600 .env
sudo chown netlab:netlab .env
```

---

## 2. Crear el administrador principal

**Este paso es el que cierra el sistema.** Al no existir ningún usuario, el
endpoint que crea el primero está abierto a quien llegue al puerto. En cuanto se
crea una cuenta, ese endpoint responde `403` para siempre: nadie más va a poder
registrarse como admin desde fuera.

Por eso conviene hacerlo por túnel SSH, sin abrir nada a Internet:

```bash
# en su máquina
ssh -L 4310:127.0.0.1:4310 usuario@TU_VPS
```

Abra <http://127.0.0.1:4310> en el navegador. Netlab le pedirá crear el
administrador principal (no aparece el login todavía, porque no hay cuenta).
Elija nombre de usuario y contraseña, y créelo.

Verificación:

```bash
curl -s http://127.0.0.1:4310/api/setup/status
# {"completado":true,"requiereSetup":false}
```

Ese `true` es el cierre. Desde ese momento, el paso de arriba se puede repetir
sin riesgo.

A partir de aquí, el administrador da de alta al resto de usuarios desde
`/admin`.

---

## 3. nginx y HTTPS

El servidor no gestiona TLS. Por eso existe este paso.

```bash
sudo cp /opt/netlab/deploy/nginx.conf /etc/nginx/sites-available/netlab
sudo nano /etc/nginx/sites-available/netlab      # sustituir DOMINIO.TLD
sudo ln -s /etc/nginx/sites-available/netlab /etc/nginx/sites-enabled/netlab
sudo nginx -t
sudo systemctl reload nginx
sudo certbot --nginx -d TU_DOMINIO
```

Qué aporta `nginx.conf` y por qué importa aquí:

| Ajuste | Por qué |
|---|---|
| `X-Forwarded-For` | Netlab necesita la IP real del cliente para el límite de intentos y la auditoría. |
| `X-Forwarded-Proto` | Para que netlab sepa que la conexión es segura y marque la cookie como `Secure`. |
| `proxy_read_timeout 180s` | Los diagnósticos encadenan pruebas de red; el valor por defecto de nginx (60 s) cortaría con un 504. |
| `client_max_body_size 4m` | `dns-checker` acepta un archivo de hasta 1 MB dentro del JSON. |
| `access_log off` | Un log de acceso duplicaría en texto plano el historial y la IP de quien pidió cada informe. |
| Redirección 80 → 443 | Sin ella, alguien que escriba `http://` manda su contraseña en claro. |

Si usa Caddy en lugar de nginx, es más corto: Caddy pide el certificado solo.

```caddy
TU_DOMINIO {
    reverse_proxy 127.0.0.1:4310
}
```

### Compruebe que funciona

```bash
curl -I https://TU_DOMINIO/                # 200 y Strict-Transport-Security
curl -s https://TU_DOMINIO/api/sesion | head -c 200
sudo nginx -t                             # sintaxis correcta
```

Si el certificado no valida, `certbot renew --dry-run` dice por qué.

---

## 4. Revisión de seguridad

```bash
cd /opt/netlab && sudo -u netlab npm run manual
```

Imprime una tabla por área (autenticación, sesiones, red, base de datos,
frontend, secretos, límites, cabeceras) y un veredicto. Además genera
`docs/manual-netlab.pdf`.

Debe salir sin bloqueantes. Los avisos son cosas que hay que confirmar a mano
desde fuera (por ejemplo, que el certificado responde de verdad).

**No ignore el bloqueante de autenticación.** Si `npm run manual` dice que
`AUTH_ENABLED` no está activo, significa que cualquiera que llegue al puerto
puede lanzar diagnósticos.

---

## 5. Rotar las credenciales

Da por hecho que están comprometidas:

- **AbuseIPDB.** La clave aparece en claro en ficheros antiguos del proyecto y en
  el historial de versiones. Créala de nuevo en <https://www.abuseipdb.com/account/api>
  y ponga la nueva en `ABUSEIPDB_API_KEY` dentro de `/opt/netlab/.env`.
- **SMTP de salida y buzón.** Si hay credenciales reales en el `.env` de su
  portátil, rótelas también.
- **Spamhaus.** La clave llegó en un `.txt` suelto. Si llegó a Git en algún
  momento, rótela.

```bash
sudo nano /opt/netlab/.env      # chmod 600, propiedad de netlab
sudo systemctl restart netlab
```

---

## 6. Servicio

```bash
sudo systemctl status netlab
sudo systemctl restart netlab
sudo journalctl -u netlab -f              # seguir el log
sudo journalctl -u netlab -n 200 --no-pager
```

La unidad está en `deploy/netlab.service`. Dos cosas que conviene revisar:

- `WorkingDirectory` y `ExecStart` deben apuntar a su ruta real
  (`/opt/netlab` por defecto).
- `ReadWritePaths=/opt/netlab/data` es lo que permite escribir en la base de
  datos con `ProtectSystem=strict`. Si cambia la ruta de instalación, cámbielo
  también ahí o el servicio no podrá guardar nada.

Para darle un nombre de dominio en lugar de `127.0.0.1`:

```bash
sudo ln -s /etc/systemd/system/netlab.service /etc/systemd/system/multi-user.target.wants/
```

### Copias de seguridad

Lo único irreemplazable es `data/netlab.db`: contiene las cuentas, el historial
y la auditoría.

```bash
sudo -u netlab sqlite3 /opt/netlab/data/netlab.db ".backup '/var/backups/netlab-$(date +%F).db'"
```

Si usa el servicio de copia de su distribución, conviene **apagar el servicio
antes**: SQLite va escribiendo con WAL, y copiar el fichero a mitad de escritura
puede dar una base incoherente.

---

## 7. Actualizar

```bash
cd /opt/netlab
sudo -u netlab git pull --ff-only
sudo -u netlab npm ci --omit=dev
sudo -u netlab npm ci --prefix web
sudo -u netlab npm run build
sudo systemctl restart netlab
```

O simplemente reejecute el instalador, que hace lo mismo y comprueba al final que
el servicio responde:

```bash
sudo bash deploy/instalar.sh
```

---

## Problemas frecuentes

**`Error: Cannot find module 'node:sqlite'`**
Node.js demasiado antiguo. Debe ser v24 o superior: `node -v`.

**El servicio no arranca: `EACCES` o `EROFS`**
Los permisos. `data/` debe ser de `netlab`, y si cambió la ruta, actualice
`ReadWritePaths` en la unidad.

**La interfaz sale en blanco o sale un aviso de que no hay nada que servir**
Falta compilar: `sudo -u netlab npm run build`. `web/dist` no se versiona a
propósito, para no desplegar una interfaz vieja.

**`429` al entrar, sin haber fallado la contraseña**
El límite es de 8 intentos por IP cada 15 minutos. Si accede a través de nginx y
`TRUST_PROXY` no está a `loopback`, todas las peticiones cuentan como la misma IP
y el contador no se reinicia. Revise `TRUST_PROXY` en `.env` y que nginx envíe
`X-Forwarded-For`.

**El certificado no valida**
`sudo certbot renew --dry-run` explica el motivo. Compruebe también que el
dominio apunta a esta VPS: un A sin actualizar es la causa más común.

**Sale `AUTH_ENABLED` no activo**
El `.env` de `/opt/netlab` tiene `AUTH_ENABLED=false` o no existe. Debe ser
`true` en una VPS.