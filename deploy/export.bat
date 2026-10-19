@echo off
rem Packs AIops for another PC into dist\aiops-deploy\: the Docker images (docker save), the compose file,
rem nginx config, .env.example and the import scripts. No source code is needed on the other PC.
rem
rem   deploy\export.bat                          images for this PC's CPU type (Intel/AMD or ARM)
rem   deploy\export.bat --platform linux/arm64   for an ARM PC (Apple Silicon, Snapdragon, Raspberry Pi 5)
rem   deploy\export.bat --platform linux/amd64   for an Intel/AMD PC
rem   --with-data     also the database, decisions\ and .env (private: never upload the package then)
rem   --with-models   also the AI model(s) the app uses, so the other PC needs no internet (about 2.5 GB each)
setlocal
cd /d "%~dp0.."
set "APP_IMAGE=sentinel-troubleshooter:latest"
set "OUT=dist\aiops-deploy"
set "HOST="
for /f "delims=" %%a in ('docker version -f "{{.Server.Os}}/{{.Server.Arch}}" 2^>nul') do set "HOST=%%a"
if not defined HOST (echo Docker is not running: start Docker Desktop first. & exit /b 1)
set "PLATFORM=%HOST%"
set "WITH_DATA="
set "WITH_MODELS="
:args
if "%~1"=="" goto args_done
if "%~1"=="--platform" (set "PLATFORM=%~2" & shift & shift & goto args)
if "%~1"=="--with-data" (set "WITH_DATA=1" & shift & goto args)
if "%~1"=="--with-models" (set "WITH_MODELS=1" & shift & goto args)
echo Unknown option: %~1
exit /b 2
:args_done
if not "%PLATFORM%"=="linux/amd64" if not "%PLATFORM%"=="linux/arm64" (echo --platform must be linux/amd64 for Intel/AMD or linux/arm64 for ARM & exit /b 2)

rem Empty the folder rather than delete it: a terminal open inside it would block that.
if not exist "%OUT%" mkdir "%OUT%"
for /d %%d in ("%OUT%\*") do rmdir /s /q "%%d"
del /f /q /a "%OUT%\*" 2>nul
for %%d in (images data deploy\nginx models decisions) do if not exist "%OUT%\%%d" mkdir "%OUT%\%%d"
for %%d in ("%OUT%") do set "OUTABS=%%~fd"
set "IMAGES= "
for /f "delims=" %%i in ('docker compose config --images') do call :add_image %%i

echo [1/4] Images for %PLATFORM%:%IMAGES%
if not "%PLATFORM%"=="%HOST%" goto cross
docker compose build sentinel || goto fail
for %%i in (%IMAGES%) do if not "%%i"=="%APP_IMAGE%" (docker image inspect %%i >nul 2>&1 || docker pull %%i || goto fail)
docker save -o "%OUT%\images\images.tar" %IMAGES% || goto fail
goto images_done
:cross
rem Another CPU type: buildx builds (under emulation) and fetches straight into tar files, so this
rem PC's own images are left as they are.
docker buildx inspect aiops-export >nul 2>&1 || docker buildx create --name aiops-export --driver docker-container >nul || goto fail
for %%i in (%IMAGES%) do call :cross_image %%i || goto fail
:images_done
>"%OUT%\PLATFORM" echo %PLATFORM%

echo [2/4] Compose file, nginx config, .env.example, agent installers
rem No "build:" (the other PC has no source). Port 8000 only for this PC itself: devices use nginx on port 80.
powershell -NoProfile -Command "$lines = Get-Content 'docker-compose.yml' | Where-Object { $_ -notmatch '^    build: \.\s*$' } | ForEach-Object { $_ -replace '(?<=\x22)8000:8000(?=\x22)', '127.0.0.1:8000:8000' }; [IO.File]::WriteAllLines('%OUTABS%\docker-compose.yml', [string[]]$lines)" || goto fail
copy /y .env.example "%OUT%\" >nul || goto fail
copy /y deploy\nginx\aiops.conf "%OUT%\deploy\nginx\" >nul || goto fail
for %%f in (import.sh import.bat deploy.md) do copy /y "deploy\%%f" "%OUT%\" >nul || goto fail
if exist agent_builds (xcopy /e /i /q /y agent_builds "%OUT%\agent_builds" >nul) else (mkdir "%OUT%\agent_builds")

if not defined WITH_DATA (echo [3/4] Data: skipped, add --with-data to move the database & goto models)
echo [3/4] Database, decisions\ and .env, private
rem SQLite's backup API gives a consistent copy even while the app is running.
docker compose run --rm --no-deps -T -v "%OUTABS%\data:/backup" sentinel python -c "import os, shutil, sqlite3, sys; p = '/data/sentinel.db'; os.path.exists(p) or sys.exit('No database in the sentinel_data volume yet'); t = sqlite3.connect('/tmp/s.db'); sqlite3.connect(p).backup(t); t.close(); shutil.copy('/tmp/s.db', '/backup/sentinel.db')" || goto fail
if exist decisions xcopy /e /i /q /y decisions "%OUT%\decisions" >nul
if exist .env copy /y .env "%OUT%\.env" >nul

:models
if not defined WITH_MODELS (echo [4/4] AI models: skipped, the other PC downloads them on first start; add --with-models for offline & goto done)
echo [4/4] AI models
rem The base model from .env and the one picked in the dashboard; aiops-brain is rebuilt from them on start.
docker compose run --rm --no-deps -T -v "%OUTABS%\data:/backup" sentinel python -c "import os; from backend.llm.catalog import selected_model; names = ' '.join(dict.fromkeys([os.getenv('OLLAMA_MODEL', 'qwen3:8b').strip(), selected_model()])); open('/backup/models.txt', 'w').write(names); print('Models:', names)" || goto fail
rem A model is its manifest plus the blobs it lists: copy exactly those files out of the ollama volume.
docker compose run --rm --no-deps -T -v "%OUTABS%\data:/backup" --entrypoint sh ollama -c "cd /root/.ollama/models && rm -f /tmp/files && for m in $(cat /backup/models.txt); do n=$(echo $m | cut -d: -f1); t=$(echo $m | cut -s -d: -f2); case $n in */*) ;; *) n=library/$n ;; esac; p=manifests/registry.ollama.ai/$n/${t:-latest}; if [ -f $p ]; then echo $p >> /tmp/files; grep -o 'sha256:[0-9a-f]*' $p | sed s,sha256:,blobs/sha256-, >> /tmp/files; echo packed $m; else echo skipped $m: not downloaded on this PC; fi; done; [ -s /tmp/files ] || { echo no model to pack >&2; exit 1; }; sort -u /tmp/files | tar cf /backup/ollama-models.tar -T -" || goto fail

:done
echo.
echo Done: copy the folder %OUTABS% to the other PC and run .\import.bat on Windows, or sh import.sh on Linux/macOS.
if defined WITH_DATA echo It holds your .env passwords and device data: copy it privately, e.g. by USB drive, never to GitHub.
exit /b 0

:fail
echo Export failed: see the error above.
exit /b 1

:add_image
echo "%IMAGES%" | findstr /c:" %1 " >nul && exit /b 0
set "IMAGES=%IMAGES%%1 "
exit /b 0

:cross_image
set "FILE=%~1"
set "FILE=%FILE:/=_%"
set "FILE=%OUT%\images\%FILE::=_%.tar"
if "%~1"=="%APP_IMAGE%" (
  docker buildx build --builder aiops-export --platform %PLATFORM% -t %~1 -o "type=docker,dest=%FILE%" .
) else (
  echo FROM %~1| docker buildx build --builder aiops-export --platform %PLATFORM% -t %~1 -o "type=docker,dest=%FILE%" -
)
exit /b %errorlevel%
