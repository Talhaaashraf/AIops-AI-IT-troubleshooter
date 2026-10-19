@echo off
rem Starts AIops on this PC from the folder that export.sh / export.bat made: loads the images, restores the
rem data in data\ (if any) into empty volumes, then runs docker compose up -d. Safe to run again.
setlocal
cd /d "%~dp0"
set "HOST="
for /f "delims=" %%a in ('docker version -f "{{.Server.Os}}/{{.Server.Arch}}" 2^>nul') do set "HOST=%%a"
if not defined HOST (echo Docker is not running: start Docker Desktop, then run this again. & exit /b 1)
for /f "usebackq delims=" %%p in ("PLATFORM") do set "WANT=%%p"
if not "%HOST%"=="%WANT%" (echo These images are for %WANT% but this PC is %HOST%. On the old PC run: deploy\export.bat --platform %HOST% & exit /b 1)

echo [1/5] .env
if not exist .env copy .env.example .env >nul
findstr /c:"=replace_with_" .env >nul || goto env_ok
echo Set DASHBOARD_PASSWORD and ADMIN_API_KEY in %CD%\.env, two different long secrets, then run this again.
exit /b 1
:env_ok

echo [2/5] Loading images
for %%f in (images\*.tar) do (docker load -i "%%f" || exit /b 1)

echo [3/5] Data
if not exist data\sentinel.db (echo no data\sentinel.db: starting with an empty database & goto models)
rem Only into an empty volume: a database already on this PC is never overwritten.
docker compose run --rm --no-deps -T -v "%CD%\data:/backup:ro" --entrypoint sh sentinel -c "if [ -e /data/sentinel.db ]; then echo database already on this PC: kept it; else cp /backup/sentinel.db /data/ && echo database restored; fi" || exit /b 1
:models
if not exist data\ollama-models.tar goto start
docker compose run --rm --no-deps -T -v "%CD%\data:/backup:ro" --entrypoint sh ollama -c "mkdir -p /root/.ollama/models && tar xf /backup/ollama-models.tar -C /root/.ollama/models && echo AI models restored" || exit /b 1

:start
echo [4/5] Starting: first start takes minutes, longer when the AI model has to be downloaded
docker compose up -d --wait --wait-timeout 3600 || (docker compose ps -a & echo Start failed: see docker compose logs SERVICE & exit /b 1)

echo [5/5] Check
docker compose ps
set "PORT="
for /f "tokens=2 delims=:" %%p in ('docker compose port nginx 80') do set "PORT=%%p"
curl -fsS -o NUL "http://localhost:%PORT%/login" || (echo nginx does not answer on http://localhost:%PORT%/login & exit /b 1)
echo OK: open http://localhost:%PORT% and sign in with DASHBOARD_PASSWORD from .env
exit /b 0
