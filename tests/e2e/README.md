# End-to-end checks

These run against the **live** stack (Docker + nginx) and a real enrolled device. They are not collected by
pytest (no `test_` prefix). Base URL: `AIOPS_URL` (default `http://localhost`, i.e. through nginx; use
`http://localhost:8000` to bypass nginx, or the ngrok URL).

Find the device id under Agents, or: `curl -s -b cookies http://localhost/api/agents`.

## API flows

```bash
python -u tests/e2e/api_check.py "<dashboard password>" <device_id> [checks]
```

`checks` is a comma-separated subset; omit it to run everything.

| Check | What it does | Time on a laptop CPU |
|---|---|---|
| `status` | AI available, device online | seconds |
| `instant` | Rule-only diagnosis on the device | ~15 s |
| `fast` | Checks + one AI report | 1-3 min |
| `deep` | AI investigates with extra tools (deep thinking) | 5-10 min |
| `fix` | Diagnose, approve a low-risk fix, re-check | 2-4 min |
| `chat` | Ask Technician about the device | 1-2 min |
| `report` | Health report + AI analysis | 2-5 min |
| `logs` | AI analysis of the device's event logs | 1-2 min |
| `local` | Instant diagnosis of the server itself | seconds |

AI calls run one at a time, so run long checks in the background and do **not** rebuild or restart
containers while they run (that cuts the session off).

## Browser check (Playwright)

pip cannot install Playwright inside a long Windows path (260-character limit), so use a short temp path:

```bash
python -m venv "$TEMP/aiops-pw"
"$TEMP/aiops-pw/Scripts/python" -m pip install playwright
PLAYWRIGHT_BROWSERS_PATH="$TEMP/aiops-pw/browsers" "$TEMP/aiops-pw/Scripts/python" -m playwright install chromium-headless-shell
PYTHONIOENCODING=utf-8 PLAYWRIGHT_BROWSERS_PATH="$TEMP/aiops-pw/browsers" \
  "$TEMP/aiops-pw/Scripts/python" -u tests/e2e/browser_check.py "<password>" <screenshot dir> <device_id>
rm -rf "$TEMP/aiops-pw"   # when done
```

It collects JavaScript errors, checks every tab against the real server (sample data is served only for the
AI-analysis text and the software table, so no slow model call or real uninstall happens) and saves screenshots.

## Clean up after test tickets

Every diagnosis is stored as a learned case, and resolved ones teach the AI. Test tickets with made-up
complaints must not: after a run, remove the cases they created (adjust the time and issue texts):

```bash
docker compose exec -T sentinel python -c "
import sqlite3; c = sqlite3.connect('/data/sentinel.db')
issues = ('Internet is slow and websites take long to open', 'Disk is full', 'My laptop is very slow and hangs',
          'Websites stopped opening, maybe DNS', 'Some websites do not open but others work')
ids = [r[0] for r in c.execute('select id from learned_cases where created_at >= ? and issue in (%s)' % ','.join('?' * len(issues)), ('2026-10-15', *issues))]
c.execute('delete from learned_cases where id in (%s)' % ','.join('?' * len(ids)), ids); c.commit(); print('removed', ids)"
```
