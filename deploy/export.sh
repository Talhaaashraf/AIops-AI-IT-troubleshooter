#!/bin/sh
# Packs AIops for another PC into dist/aiops-deploy/: the Docker images (docker save), the compose file,
# nginx config, .env.example and the import scripts. No source code is needed on the other PC.
#
#   sh deploy/export.sh                          images for this PC's CPU type (Intel/AMD or ARM)
#   sh deploy/export.sh --platform linux/arm64   for an ARM PC (Apple Silicon, Snapdragon, Raspberry Pi 5)
#   sh deploy/export.sh --platform linux/amd64   for an Intel/AMD PC
#   --with-data     also the database, decisions/ and .env (private: never upload the package then)
#   --with-models   also the AI model(s) the app uses, so the other PC needs no internet (about 2.5 GB each)
#
# Linux, macOS or Git Bash on Windows (on Windows, export.bat does the same).
set -eu
cd "$(dirname "$0")/.."
export MSYS_NO_PATHCONV=1   # Git Bash: pass container paths to docker unchanged

APP_IMAGE=sentinel-troubleshooter:latest
OUT=dist/aiops-deploy
HOST=$(docker version -f '{{.Server.Os}}/{{.Server.Arch}}')
PLATFORM=$HOST
WITH_DATA=
WITH_MODELS=
while [ $# -gt 0 ]; do
  case $1 in
    --platform) PLATFORM=${2:-}; shift 2 ;;
    --with-data) WITH_DATA=1; shift ;;
    --with-models) WITH_MODELS=1; shift ;;
    *) echo "Unknown option: $1"; exit 2 ;;
  esac
done
case $PLATFORM in
  linux/amd64 | linux/arm64) ;;
  *) echo "--platform must be linux/amd64 (Intel/AMD) or linux/arm64 (ARM)"; exit 2 ;;
esac

# Empty the folder rather than delete it: a terminal open inside it would block that.
mkdir -p "$OUT" && find "$OUT" -mindepth 1 -maxdepth 1 -exec rm -rf {} +
mkdir -p "$OUT/images" "$OUT/data" "$OUT/deploy/nginx" "$OUT/models" "$OUT/decisions"
DATA=$(cd "$OUT/data" && (pwd -W 2>/dev/null || pwd))   # docker -v needs C:/... under Git Bash
IMAGES=$(docker compose config --images | sort -u)

echo "[1/4] Images for $PLATFORM:" $IMAGES
if [ "$PLATFORM" = "$HOST" ]; then
  docker compose build sentinel
  for image in $IMAGES; do
    [ "$image" = "$APP_IMAGE" ] || docker image inspect "$image" >/dev/null 2>&1 || docker pull "$image"
  done
  docker save -o "$OUT/images/images.tar" $IMAGES
else
  # Another CPU type: buildx builds (under emulation) and fetches straight into tar files, so this
  # PC's own images are left as they are.
  docker buildx inspect aiops-export >/dev/null 2>&1 || docker buildx create --name aiops-export --driver docker-container >/dev/null
  for image in $IMAGES; do
    file="$OUT/images/$(echo "$image" | tr '/:' '__').tar"
    if [ "$image" = "$APP_IMAGE" ]; then
      docker buildx build --builder aiops-export --platform "$PLATFORM" -t "$image" -o "type=docker,dest=$file" .
    else
      echo "FROM $image" | docker buildx build --builder aiops-export --platform "$PLATFORM" -t "$image" -o "type=docker,dest=$file" -
    fi
  done
fi
echo "$PLATFORM" > "$OUT/PLATFORM"

echo "[2/4] Compose file, nginx config, .env.example, agent installers"
# No "build:" (the other PC has no source). Port 8000 only for this PC itself: devices use nginx on port 80.
sed -e '/^    build: \.[[:space:]]*$/d' -e 's/"8000:8000"/"127.0.0.1:8000:8000"/' docker-compose.yml > "$OUT/docker-compose.yml"
cp .env.example "$OUT/"
cp deploy/nginx/aiops.conf "$OUT/deploy/nginx/"
cp deploy/import.sh deploy/import.bat deploy/deploy.md "$OUT/"
if [ -d agent_builds ]; then cp -R agent_builds "$OUT/"; else mkdir "$OUT/agent_builds"; fi

if [ -n "$WITH_DATA" ]; then
  echo "[3/4] Database, decisions/ and .env (private)"
  # SQLite's backup API gives a consistent copy even while the app is running.
  docker compose run --rm --no-deps -T -v "$DATA:/backup" sentinel python -c "import os, shutil, sqlite3, sys; p = '/data/sentinel.db'; os.path.exists(p) or sys.exit('No database in the sentinel_data volume yet'); t = sqlite3.connect('/tmp/s.db'); sqlite3.connect(p).backup(t); t.close(); shutil.copy('/tmp/s.db', '/backup/sentinel.db')"
  if [ -d decisions ]; then cp -R decisions/. "$OUT/decisions/"; fi
  if [ -f .env ]; then cp .env "$OUT/.env"; fi
else
  echo "[3/4] Data: skipped (add --with-data to move the database)"
fi

if [ -n "$WITH_MODELS" ]; then
  echo "[4/4] AI models"
  # The base model from .env and the one picked in the dashboard; aiops-brain is rebuilt from them on start.
  docker compose run --rm --no-deps -T -v "$DATA:/backup" sentinel python -c "import os; from backend.llm.catalog import selected_model; names = ' '.join(dict.fromkeys([os.getenv('OLLAMA_MODEL', 'qwen3:8b').strip(), selected_model()])); open('/backup/models.txt', 'w').write(names); print('Models:', names)"
  # A model is its manifest plus the blobs it lists: copy exactly those files out of the ollama volume.
  docker compose run --rm --no-deps -T -v "$DATA:/backup" --entrypoint sh ollama -c '
    cd /root/.ollama/models && rm -f /tmp/files
    for m in $(cat /backup/models.txt); do
      n=$(echo $m | cut -d: -f1); t=$(echo $m | cut -s -d: -f2)
      case $n in */*) ;; *) n=library/$n ;; esac
      p=manifests/registry.ollama.ai/$n/${t:-latest}
      if [ -f $p ]; then
        echo $p >> /tmp/files
        grep -o "sha256:[0-9a-f]*" $p | sed s,sha256:,blobs/sha256-, >> /tmp/files
        echo "packed $m"
      else
        echo "skipped $m: not downloaded on this PC"
      fi
    done
    [ -s /tmp/files ] || { echo "no model to pack" >&2; exit 1; }
    sort -u /tmp/files | tar cf /backup/ollama-models.tar -T -'
else
  echo "[4/4] AI models: skipped (the other PC downloads them on first start; add --with-models for offline)"
fi

echo
du -sh "$OUT" "$OUT"/images "$OUT"/data 2>/dev/null || true
echo "Done: copy the folder $OUT to the other PC and run .\import.bat (Windows) or sh import.sh (Linux/macOS)."
if [ -n "$WITH_DATA" ]; then echo "It holds your .env passwords and device data: copy it privately (USB), never to GitHub."; fi
