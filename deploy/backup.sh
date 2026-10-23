#!/bin/sh
# Daily backup of AIops' data on the server: the database (a consistent copy taken with SQLite's backup API, so
# it is safe while the app writes), the AI decision records and the server's settings (~/app-config/.env).
# Keeps AIOPS_BACKUP_KEEP_DAYS days (14). Each file holds the dashboard password and device data: owner-only.
#
#   install:  mkdir -p ~/bin && cp deploy/backup.sh ~/bin/aiops-backup.sh && chmod +x ~/bin/aiops-backup.sh
#             (crontab -l 2>/dev/null; echo "30 2 * * * $HOME/bin/aiops-backup.sh >> $HOME/backups/aiops/backup.log 2>&1") | crontab -
#   restore:  see docs/04-docker.md ("Backups")
set -eu
BACKUP_DIR="${AIOPS_BACKUP_DIR:-$HOME/backups/aiops}"
KEEP_DAYS="${AIOPS_BACKUP_KEEP_DAYS:-14}"
CONTAINER="${AIOPS_CONTAINER:-sentinel-sentinel-1}"
stamp=$(date +%Y%m%d-%H%M%S)
mkdir -p "$BACKUP_DIR"
work=$(mktemp -d)
trap 'rm -rf "$work"; docker exec "$CONTAINER" rm -f /tmp/aiops-backup.db >/dev/null 2>&1 || true' EXIT

docker exec "$CONTAINER" python -c "
import sqlite3
source, copy = sqlite3.connect('/data/sentinel.db'), sqlite3.connect('/tmp/aiops-backup.db')
source.backup(copy)
check = copy.execute('pragma integrity_check').fetchone()[0]
copy.close()
raise SystemExit(0 if check == 'ok' else 'database copy failed its integrity check: ' + check)
"
docker cp "$CONTAINER:/tmp/aiops-backup.db" "$work/sentinel.db"
docker cp "$CONTAINER:/app/decisions" "$work/decisions"
if [ -f "$HOME/app-config/.env" ]; then cp "$HOME/app-config/.env" "$work/app-config.env"; fi

umask 077
tar czf "$BACKUP_DIR/aiops-$stamp.tar.gz" -C "$work" .
find "$BACKUP_DIR" -maxdepth 1 -name 'aiops-*.tar.gz' -mtime +"$KEEP_DAYS" -delete
echo "$(date -Is) $BACKUP_DIR/aiops-$stamp.tar.gz $(du -h "$BACKUP_DIR/aiops-$stamp.tar.gz" | cut -f1)"
