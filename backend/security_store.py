"""Versioned, bounded security state. Never stores provider credentials or sample bytes."""
import hashlib
import json
import secrets
import sqlite3
import time

from .config import DB_PATH

POLICY_VERSION = "security-1"


class Connection(sqlite3.Connection):
    def __exit__(self, *args):
        try:
            return super().__exit__(*args)
        finally:
            self.close()


def connect():
    db = sqlite3.connect(DB_PATH, timeout=10, factory=Connection)
    db.row_factory = sqlite3.Row
    db.executescript("""
    CREATE TABLE IF NOT EXISTS security_jobs (
      id TEXT PRIMARY KEY, device TEXT NOT NULL, policy TEXT NOT NULL, kind TEXT NOT NULL,
      state TEXT NOT NULL, created REAL NOT NULL, updated REAL NOT NULL, body TEXT NOT NULL);
    CREATE UNIQUE INDEX IF NOT EXISTS security_baseline ON security_jobs(device,policy) WHERE kind='baseline';
    CREATE TABLE IF NOT EXISTS security_batches (device TEXT, id TEXT, received REAL, PRIMARY KEY(device,id));
    CREATE TABLE IF NOT EXISTS security_events (id TEXT PRIMARY KEY, device TEXT, received REAL, body TEXT);
    CREATE INDEX IF NOT EXISTS security_events_device ON security_events(device,received);
    CREATE TABLE IF NOT EXISTS security_findings (id TEXT PRIMARY KEY, device TEXT, updated REAL, body TEXT);
    CREATE INDEX IF NOT EXISTS security_findings_device ON security_findings(device,updated);
    CREATE TABLE IF NOT EXISTS security_state (name TEXT PRIMARY KEY, updated REAL, body TEXT);
    CREATE TABLE IF NOT EXISTS security_approvals (id TEXT PRIMARY KEY, device TEXT, expires REAL, state TEXT, body TEXT);
    CREATE TABLE IF NOT EXISTS intelligence_jobs (id TEXT PRIMARY KEY, provider TEXT, hash TEXT, operation TEXT,
      state TEXT, due REAL, created REAL, body TEXT, UNIQUE(provider,hash,operation));
    CREATE TABLE IF NOT EXISTS intelligence_usage (provider TEXT, stamp REAL);
    CREATE INDEX IF NOT EXISTS intelligence_usage_provider ON intelligence_usage(provider,stamp);
    CREATE TABLE IF NOT EXISTS intelligence_credentials (provider TEXT PRIMARY KEY, ciphertext TEXT NOT NULL);
    CREATE TABLE IF NOT EXISTS intelligence_observations (id TEXT PRIMARY KEY, device TEXT, hash TEXT, observed REAL, body TEXT);
    CREATE INDEX IF NOT EXISTS intelligence_observations_device ON intelligence_observations(device,observed);
    CREATE TABLE IF NOT EXISTS intelligence_audit (id TEXT PRIMARY KEY, stamp REAL, operation TEXT, body TEXT);
    CREATE TABLE IF NOT EXISTS intelligence_submissions (provider TEXT, hash TEXT, token TEXT, state TEXT,
      PRIMARY KEY(provider,hash));
    """)
    return db


def audit(operation, **metadata):
    # Callers pass identities/status only, never arbitrary request bodies or credentials.
    allowed = {key: value for key, value in metadata.items() if key in
               ("provider", "sha256", "device", "token", "state", "enabled", "business_authorized", "upload_authorized")}
    with connect() as db:
        db.execute("INSERT INTO intelligence_audit VALUES (?,?,?,?)", (secrets.token_hex(16), time.time(), operation, json.dumps(allowed)))


def unpack(row):
    if not row:
        return None
    value = dict(row)
    value.update(json.loads(value.pop("body")))
    return value


def job_create(device, kind="interactive", question=""):
    now = time.time()
    with connect() as db:
        db.execute("BEGIN IMMEDIATE")
        row = db.execute("SELECT * FROM security_jobs WHERE device=? AND (state IN ('queued','running') OR (kind='baseline' AND ?='baseline' AND policy=?)) ORDER BY created LIMIT 1", (device, kind, POLICY_VERSION)).fetchone()
        if row:
            return unpack(row)
        identity = secrets.token_hex(16)
        body = {"question": question[:2000], "steps": [], "evidence": [], "unfinished": [], "instruction_version": POLICY_VERSION}
        db.execute("INSERT INTO security_jobs VALUES (?,?,?,?,?,?,?,?)", (identity, device, POLICY_VERSION, kind, "queued", now, now, json.dumps(body)))
        return {"id": identity, "device": device, "kind": kind, "state": "queued", "created": now, **body}


def job_get(identity):
    with connect() as db:
        return unpack(db.execute("SELECT * FROM security_jobs WHERE id=?", (identity,)).fetchone())


def job_save(job):
    body = {key: value for key, value in job.items() if key not in ("id", "device", "policy", "kind", "state", "created", "updated")}
    with connect() as db:
        db.execute("UPDATE security_jobs SET state=?,updated=?,body=? WHERE id=?", (job["state"], time.time(), json.dumps(body), job["id"]))


def pending_jobs():
    with connect() as db:
        return [unpack(row) for row in db.execute("SELECT * FROM security_jobs WHERE state IN ('queued','running') ORDER BY created LIMIT 50")]


def state_get(name, default=None):
    with connect() as db:
        row = db.execute("SELECT body FROM security_state WHERE name=?", (name,)).fetchone()
    return json.loads(row[0]) if row else default


def state_set(name, body):
    with connect() as db:
        db.execute("INSERT OR REPLACE INTO security_state VALUES (?,?,?)", (name, time.time(), json.dumps(body)))


def ingest(device, batch):
    """ACK only after transaction commits; replayed batches/events are harmless."""
    now = time.time()
    with connect() as db:
        db.execute("BEGIN IMMEDIATE")
        if db.execute("SELECT 1 FROM security_batches WHERE device=? AND id=?", (device, batch["id"])).fetchone():
            return False
        for event in batch.get("events", [])[:500]:
            identity = hashlib.sha256((device + ":" + str(event["id"])).encode()).hexdigest()
            db.execute("INSERT OR IGNORE INTO security_events VALUES (?,?,?,?)", (identity, device, now, json.dumps({**event, "device": device, "received_at": now, "provenance": "endpoint"})))
        db.execute("INSERT INTO security_batches VALUES (?,?,?)", (device, batch["id"], now))
        db.execute("INSERT OR REPLACE INTO security_state VALUES (?,?,?)", ("coverage:" + device, now, json.dumps({"received_at": now, **batch.get("coverage", {})})))
    return True


def finding_put(device, finding):
    identity = hashlib.sha256((device + ":" + finding["key"]).encode()).hexdigest()
    with connect() as db:
        previous = db.execute("SELECT body FROM security_findings WHERE id=?", (identity,)).fetchone()
        old = json.loads(previous[0]) if previous else {}
        body = {**finding, "id": identity, "device": device, "provenance": "endpoint", "first_seen": old.get("first_seen", time.time()), "last_seen": time.time(), "status": old.get("status", "active")}
        db.execute("INSERT OR REPLACE INTO security_findings VALUES (?,?,?,?)", (identity, device, time.time(), json.dumps(body)))


def search(device, query="", severity="", status="", source="", rule="", since=0, until=None, offset=0, limit=50, events=False):
    table, timestamp = ("security_events", "received") if events else ("security_findings", "updated")
    with connect() as db:
        rows = db.execute(f"SELECT body FROM {table} WHERE device=? AND {timestamp}>=? AND {timestamp}<=? ORDER BY {timestamp} DESC", (device, since, until or time.time()))
        matched, results = 0, []
        terms = query.casefold().split()
        for row in rows:
            item = json.loads(row[0])
            if severity and item.get("severity") != severity or status and item.get("status") != status or source and item.get("source") != source or rule and item.get("rule") != rule:
                continue
            text = json.dumps(item, ensure_ascii=False).casefold()
            if not all(term in text for term in terms):
                continue
            if offset <= matched < offset + limit:
                results.append(item)
            matched += 1
    return {"items": results, "total": matched, "offset": offset, "limit": limit}


def approval_issue(device, body, ttl=600):
    identity = secrets.token_urlsafe(24)
    with connect() as db:
        db.execute("INSERT INTO security_approvals VALUES (?,?,?,?,?)", (identity, device, time.time() + ttl, "pending", json.dumps(body, sort_keys=True)))
    return identity


def approval_consume(identity, device, body):
    with connect() as db:
        cursor = db.execute("UPDATE security_approvals SET state='consumed' WHERE id=? AND device=? AND expires>? AND state='pending' AND body=?", (identity, device, time.time(), json.dumps(body, sort_keys=True)))
    return cursor.rowcount == 1


def cleanup():
    now = time.time()
    with connect() as db:
        for table, column, days in (("security_events", "received", 30), ("security_batches", "received", 30), ("security_findings", "updated", 90), ("security_approvals", "expires", 90), ("intelligence_usage", "stamp", 2)):
            db.execute(f"DELETE FROM {table} WHERE {column}<?", (now - days * 86400,))
        db.execute("DELETE FROM security_jobs WHERE kind!='baseline' AND state NOT IN ('queued','running') AND updated<?", (now - 90 * 86400,))
        db.execute("DELETE FROM security_state WHERE updated<? AND (name LIKE 'report:%' OR name LIKE 'submission:%' OR name LIKE 'transfer:%')", (now - 90 * 86400,))
        db.execute("DELETE FROM intelligence_observations WHERE observed<?", (now - 90 * 86400,))
        db.execute("DELETE FROM intelligence_audit WHERE stamp<?", (now - 90 * 86400,))
        db.execute("DELETE FROM intelligence_jobs WHERE created<? AND state NOT IN ('queued','running','retry')", (now - 90 * 86400,))
