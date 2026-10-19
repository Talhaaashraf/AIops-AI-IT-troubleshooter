#!/bin/sh
# Starts AIops on this PC from the folder that export.sh / export.bat made: loads the images, restores the
# data in data/ (if any) into empty volumes, then runs docker compose up -d. Safe to run again.
#   sh import.sh          (Linux/macOS; on Windows run import.bat)
set -eu
cd "$(dirname "$0")"
export MSYS_NO_PATHCONV=1   # Git Bash: pass container paths to docker unchanged
HERE=$(pwd -W 2>/dev/null || pwd)

HOST=$(docker version -f '{{.Server.Os}}/{{.Server.Arch}}' 2>/dev/null) || { echo "Docker is not running (or needs sudo): start it, then run this again."; exit 1; }
WANT=$(tr -d '\r' < PLATFORM)
if [ "$HOST" != "$WANT" ]; then
  echo "These images are for $WANT but this PC is $HOST. On the old PC run: sh deploy/export.sh --platform $HOST"
  exit 1
fi

echo "[1/5] .env"
[ -f .env ] || cp .env.example .env
if grep -q '=replace_with_' .env; then
  echo "Set DASHBOARD_PASSWORD and ADMIN_API_KEY in $HERE/.env (two different long secrets), then run this again."
  exit 1
fi

echo "[2/5] Loading images"
for file in images/*.tar; do docker load -i "$file"; done

echo "[3/5] Data"
if [ -f data/sentinel.db ]; then
  # Only into an empty volume: a database already on this PC is never overwritten.
  docker compose run --rm --no-deps -T -v "$HERE/data:/backup:ro" --entrypoint sh sentinel -c \
    'if [ -e /data/sentinel.db ]; then echo "database already on this PC: kept it"; else cp /backup/sentinel.db /data/ && echo "database restored"; fi'
else
  echo "no data/sentinel.db: starting with an empty database"
fi
if [ -f data/ollama-models.tar ]; then
  docker compose run --rm --no-deps -T -v "$HERE/data:/backup:ro" --entrypoint sh ollama -c \
    'mkdir -p /root/.ollama/models && tar xf /backup/ollama-models.tar -C /root/.ollama/models && echo "AI models restored"'
fi

echo "[4/5] Starting (first start takes minutes; longer when the AI model has to be downloaded)"
docker compose up -d --wait --wait-timeout 3600 || { docker compose ps -a; echo "Start failed: see docker compose logs <service>"; exit 1; }

echo "[5/5] Check"
docker compose ps
PORT=$(docker compose port nginx 80 | sed 's/.*://')
URL="http://localhost:$PORT/login"
# The shell discards the page (not curl -o /dev/null, which Git Bash cannot pass to a Windows curl).
{ curl -fsS "$URL" || wget -q -O - "$URL"; } >/dev/null 2>&1 || { echo "nginx does not answer on $URL"; exit 1; }
echo "OK: open http://localhost:$PORT and sign in with DASHBOARD_PASSWORD from .env"
