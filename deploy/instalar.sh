#!/usr/bin/env bash
#
# instalar.sh - Prepara una VPS Ubuntu/Debian para ejecutar netlab.
#
#   sudo bash deploy/instalar.sh
#
# Que hace:
#   1. instala Node.js 24 (el repositorio de Node, no el del sistema, que suele
#      ir muy atras) y las dependencias basicas;
#   2. crea el usuario de servicio `netlab`, que no es root;
#   3. copia este repositorio a /opt/netlab e instala dependencias;
#   4. compila la interfaz;
#   5. crea el .env con valores de seguridad si no existe;
#   6. instala el servicio systemd y lo arranca;
#   7. comprueba que responde.
#
# Lo que NO hace, y por que: no toca nginx ni pide el certificado. Eso necesita
# saber tu dominio, y decidirlo mal deja el sistema sin HTTPS o con el puerto de
# diagnostico abierto a Internet. Los pasos estan al final de README.md.
#
# Es idempotente: se puede volver a ejecutar para actualizar.

set -euo pipefail

RAIZ="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
DESTINO="${DESTINO:-/opt/netlab}"
USUARIO="${USUARIO:-netlab}"
PUERTO="${PUERTO:-4310}"

log()  { printf '\n\033[1;36m==>\033[0m %s\n' "$*"; }
aviso(){ printf '\033[1;33maviso:\033[0m %s\n' "$*"; }
error(){ printf '\033[1;31merror:\033[0m %s\n' "$*" >&2; exit 1; }

[ "$(id -u)" -eq 0 ] || error "Este script necesita root: sudo bash deploy/instalar.sh"

# --------------------------------------------------------------- 1. Node.js 24
log "Comprobando Node.js"
ACTUAL="$(node -v 2>/dev/null || echo 'no instalado')"
echo "    version actual: $ACTUAL"
if node -e 'process.exit(Number(process.versions.node.split(".")[0]) >= 24 ? 0 : 1)' 2>/dev/null; then
    echo "    Node.js es suficientemente reciente."
else
    log "Instalando Node.js 24"
    apt-get update -qq
    apt-get install -y -qq curl ca-certificates gnupg >/dev/null
    curl -fsSL https://deb.nodesource.com/setup_24.x | bash - >/dev/null
    apt-get install -y -qq nodejs >/dev/null
    node -v
fi

apt-get install -y -qq git build-essential python3 nginx >/dev/null

# --------------------------------------------------------- 2. usuario de servicio
log "Preparando el usuario de servicio"
if ! id -u "$USUARIO" >/dev/null 2>&1; then
    useradd --system --home-dir "$DESTINO" --shell /usr/sbin/nologin "$USUARIO"
    echo "    creado $USUARIO"
else
    echo "    $USUARIO ya existe"
fi

# ------------------------------------------------------------- 3. codigo y deps
log "Instalando netlab en $DESTINO"
if [ -d "$DESTINO/.git" ]; then
    (cd "$DESTINO" && git pull --ff-only)
else
    if [ "$(cd "$RAIZ" && pwd)" = "$DESTINO" ]; then
        echo "    ya estamos en $DESTINO"
    else
        mkdir -p "$DESTINO"
        # Se copia sin .git para no arrastrar el historial del portatil; en la
        # VPS no hace falta. Si prefieres desplegar con `git pull`, sube el
        # repositorio y quita esta copia manual.
        tar --exclude=.git --exclude=node_modules --exclude='web/dist' \
            --exclude=data -C "$RAIZ" . | tar -C "$DESTINO" -x
    fi
fi

cd "$DESTINO"
log "Instalando dependencias del servidor"
npm ci --omit=dev

log "Instalando dependencias y compilando la interfaz"
npm ci --prefix web
npm run build

if [ ! -d "$DESTINO/web/dist" ]; then
    error "El build no produjo web/dist. Revisa el paso anterior."
fi

# ------------------------------------------------------------------- 5. .env
if [ ! -f "$DESTINO/.env" ]; then
    log "Creando .env con valores de seguridad"
    cp "$DESTINO/.env.example" "$DESTINO/.env"
    # AUTH_ENABLED queda en true a proposito: en una VPS sin autenticacion,
    # cualquiera que llegue al puerto puede lanzar diagnosticos.
    sed -i "s/^AUTH_ENABLED=.*/AUTH_ENABLED=true/" "$DESTINO/.env"
    chmod 600 "$DESTINO/.env"
    echo "    creado con AUTH_ENABLED=true. Revisa el resto de credenciales."
else
    log "El .env ya existe, no se toca"
    aviso "Comprueba que tenga AUTH_ENABLED=true en una VPS"
fi

chown -R "$USUARIO:$USUARIO" "$DESTINO"
mkdir -p "$DESTINO/data"
chown -R "$USUARIO:$USUARIO" "$DESTINO/data"

# ------------------------------------------------------------- 6. systemd
log "Instalando el servicio systemd"
sed -e "s#/opt/netlab#$DESTINO#g" \
    -e "s#User=netlab#User=$USUARIO#" \
    "$RAIZ/deploy/netlab.service" > /etc/systemd/system/netlab.service
systemctl daemon-reload
systemctl enable --now netlab
sleep 2

# ------------------------------------------------------------- 7. comprobacion
log "Comprobando el servicio"
if systemctl is-active --quiet netlab; then
    echo "    netlab esta activo"
else
    systemctl --no-pager --lines=30 status netlab || true
    error "netlab no arranca. Mira el log de arriba."
fi

if curl -fsS "http://127.0.0.1:$PUERTO/api/sesion" >/dev/null 2>&1; then
    echo "    responde en 127.0.0.1:$PUERTO"
else
    aviso "El puerto $PUERTO no responde. Puede que PORT en .env sea otro:"
    aviso "  journalctl -u netlab -n 50 --no-pager"
fi

log "Listo"
cat <<EOF

netlab esta instalado en $DESTINO y escuchando solo en 127.0.0.1:$PUERTO.

Falta lo importante para poder abrirlo al mundo:

  1. Abrir la interfaz por primera vez y crear el administrador principal.
     Todavia no hay ninguna cuenta. El endpoint de setup queda cerrado en
     cuanto exista un usuario, asi que hazlo tu, no lo dejes abierto:

       ssh -L 4310:127.0.0.1:$PUERTO usuario@TU_VPS
       # y abre http://127.0.0.1:4310 en el navegador

  2. Poner nginx con HTTPS delante. Sin esto la contrasena viaja en claro:

       sudo cp $DESTINO/deploy/nginx.conf /etc/nginx/sites-available/netlab
       sudo nano /etc/nginx/sites-available/netlab     # pon tu dominio
       sudo ln -s /etc/nginx/sites-available/netlab /etc/nginx/sites-enabled/
       sudo certbot --nginx -d TU_DOMINIO

  3. Comprobar el estado de seguridad:

       cd $DESTINO && npm run manual

  4. Rotar las credenciales que esten en claro. La de AbuseIPDB aparece
     historically en el repositorio: da por hecho que esta comprometida.

EOF