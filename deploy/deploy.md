# Deploy AIops on another laptop (Docker only, no source code)

The old PC (the one with the source code) builds a folder, `dist/aiops-deploy/`. Copy that folder to the new laptop and run one script there.

| In the folder | What it is |
| --- | --- |
| `images/*.tar` | The 4 Docker images (`docker save`): app, ollama, nginx, ngrok |
| `docker-compose.yml`, `deploy/nginx/aiops.conf` | The stack and the reverse proxy |
| `.env.example` | Settings template. `.env` too, if exported `--with-data` |
| `data/sentinel.db`, `decisions/` | Database and AI decision log (`--with-data` only) |
| `data/ollama-models.tar` | AI model files (`--with-models` only, about 2.5 GB for qwen3:4b) |
| `agent_builds/` | The agent installer that devices download |
| `PLATFORM` | CPU type the images were built for |
| `import.bat`, `import.sh` | Start everything on the new laptop |

## 1. Check the new laptop's CPU type

Docker must be installed on it (step 3). Run there:

```
docker version -f "{{.Server.Arch}}"
```

`amd64` means Intel or AMD. `arm64` means ARM: Apple M-series, Snapdragon, Raspberry Pi. Images only run on the type they were built for.

## 2. Old PC: build the folder

Run in the project folder:

| New laptop | Windows (cmd or PowerShell) | Linux / macOS |
| --- | --- | --- |
| Same CPU type as this PC | `deploy\export.bat --with-data --with-models` | `sh deploy/export.sh --with-data --with-models` |
| ARM | `deploy\export.bat --platform linux/arm64 --with-data --with-models` | `sh deploy/export.sh --platform linux/arm64 --with-data --with-models` |
| Intel/AMD | `deploy\export.bat --platform linux/amd64 --with-data --with-models` | `sh deploy/export.sh --platform linux/amd64 --with-data --with-models` |

- `--with-data` moves the database, `decisions/` and `.env`. Leave it out for a fresh install.
- `--with-models` packs the AI model, so the new laptop needs no internet. Leave it out and the new laptop downloads it on first start.
- A different CPU type is built under emulation (Docker Desktop has it built in; on Linux run `docker run --privileged --rm tonistiigi/binfmt --install all` once). That build takes longer.

**Test:** these show the CPU type and the image files:

```
type dist\aiops-deploy\PLATFORM & dir dist\aiops-deploy\images      (Windows cmd)
cat dist/aiops-deploy/PLATFORM; ls -lh dist/aiops-deploy/images     (Linux/macOS)
```

## 3. Copy the folder

Copy it to the new laptop by USB drive or over the local network. With `--with-data`, it holds your passwords and device data. Never upload it to GitHub or a public share, and delete the copies once the new laptop works.

**Test:** the folder size on the new laptop matches the old PC (Explorer > Properties, or `du -sh aiops-deploy`).

## 4. New laptop: install Docker

- **Windows:** Docker Desktop with the WSL 2 backend. In Settings, turn on *Start Docker Desktop when you sign in*.
- **macOS:** Docker Desktop. Pick the Apple-chip build on M-series Macs.
- **Linux:** `curl -fsSL https://get.docker.com | sh`, then `sudo systemctl enable --now docker`. Then `sudo usermod -aG docker $USER`, and log out and back in.

Give Docker at least 6 GB of RAM (Docker Desktop: Settings > Resources). qwen3:4b needs about 4 GB of that.

**Test:** both commands print a version. Compose must be 2.24 or newer:

```
docker version
docker compose version
```

## 5. New laptop: start it

Open a terminal in the copied folder:

```
.\import.bat        (Windows, cmd or PowerShell)
sh import.sh        (Linux/macOS)
```

The script does five things. Running it again is safe.

1. It checks `.env`. If there is no `.env` (exported without `--with-data`), it creates one from `.env.example` and stops. Set `DASHBOARD_PASSWORD` and `ADMIN_API_KEY` to two different long secrets, then run the script again.
2. It loads the images (`docker load`).
3. It restores `data/sentinel.db` and the AI models, only into empty volumes. A database already on the new laptop is never overwritten.
4. It runs `docker compose up -d --wait`.
5. It checks that `http://localhost/login` answers.

**Test:**

```
docker compose ps
curl -I http://localhost/login
```

- In `docker compose ps`, ollama, sentinel and nginx show `healthy` and ngrok shows `Up`. `model-init` is a one-time job, so `docker compose ps -a` shows it as `Exited (0)`.
- `curl` returns `HTTP/1.1 200 OK`.
- Then open `http://localhost` and sign in with `DASHBOARD_PASSWORD`.

## 6. Let the devices reach it

1. **Set this laptop's address.** Find its IP (`ipconfig` on Windows, `ip -4 addr` on Linux). Set `SENTINEL_PUBLIC_URL=http://<that IP>` in `.env`, then run `docker compose up -d`.
2. **Open port 80.**
   - Windows, in an Administrator PowerShell: `New-NetFirewallRule -DisplayName "AIops HTTP" -Direction Inbound -Protocol TCP -LocalPort 80 -Action Allow`
   - Linux: `sudo ufw allow 80/tcp`
3. **Public https link (optional).** Put `NGROK_AUTHTOKEN=` in `.env`, then run `docker compose up -d`.
4. **Reconnect the agents.** On each device, run the command from the dashboard's **Add Agent** tab, as Administrator on Windows. Devices that came over in the database show as offline until then. Remove the old entries under **Agents**.

**Test:**
- From another device: `curl -I http://<IP>/login`.
- For ngrok: `curl -s http://127.0.0.1:4040/api/tunnels` shows the `https://` URL.

## Backup and restore (on the new laptop)

Persistent data:

| Data | Where |
| --- | --- |
| Database | Docker volume `sentinel_sentinel_data` (`/data/sentinel.db`) |
| AI models | Volume `sentinel_ollama_data`. Re-downloadable, so it needs no backup |
| AI decisions | The `decisions/` folder |
| Settings and secrets | `.env` |

**Backup** (the app keeps running). Run in the folder:

```
docker compose exec -T sentinel python -c "import sqlite3; t = sqlite3.connect('/tmp/b.db'); sqlite3.connect('/data/sentinel.db').backup(t); t.close()"
docker compose cp sentinel:/tmp/b.db sentinel-backup.db
```

Also copy `decisions/` and `.env` next to `sentinel-backup.db`.

**Test:** this prints `ok`:

```
docker compose exec -T sentinel python -c "import sqlite3; print(sqlite3.connect('/tmp/b.db').execute('pragma integrity_check').fetchone()[0])"
```

**Restore:**

```
docker compose stop sentinel
docker compose cp sentinel-backup.db sentinel:/data/sentinel.db
docker compose start sentinel
```

**Test:** `docker compose ps sentinel` shows `healthy`, and the devices and history are back in the dashboard.

To move to yet another PC, put `sentinel-backup.db` in the folder as `data/sentinel.db` before the first `import`.

## Restarts

ollama, sentinel, nginx and ngrok have `restart: unless-stopped`, so they come back after a crash or reboot. `model-init` runs once per start on purpose. Docker itself must start at boot: use Docker Desktop's sign-in setting, or `systemctl enable docker` on Linux.

**Test:** reboot, wait a minute, then run `docker compose ps`.

## Problems

- **"These images are for linux/amd64 but this PC is linux/arm64"** (or the other way round): export again with `--platform linux/arm64` (or `linux/amd64`).
- **"Pool overlaps with other one on this address space":** the network already uses `172.28.5.0/24`. Change `172.28.5.` to a free range, such as `172.29.5.`, in `docker-compose.yml` (4 places) and in `deploy/nginx/aiops.conf` (2 places).
- **Port 80 is taken:** change `"80:80"` to `"8080:80"` in `docker-compose.yml` and use `http://localhost:8080`.
- **`env_file` / `path` error:** Docker Compose is older than 2.24, so update Docker.
- **Slow AI answers:** that is normal on a CPU. Give Docker more RAM, or pick a smaller model in the dashboard's model switcher.
- Port 8000 only listens on `127.0.0.1` in this package: devices and browsers use nginx on port 80.
