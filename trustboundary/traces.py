"""SQLite append-only-like event log for synthetic, redacted metadata."""
import json, os, sqlite3, threading, uuid
from datetime import datetime, timezone
from pathlib import Path
DB = Path(os.getenv('TB_DB_PATH',str(Path(__file__).resolve().parent.parent/'data'/'audit.sqlite3')))
_lock=threading.Lock()

def init_db():
 DB.parent.mkdir(parents=True,exist_ok=True)
 with sqlite3.connect(DB) as db:
  db.execute('CREATE TABLE IF NOT EXISTS events (id INTEGER PRIMARY KEY AUTOINCREMENT, run_id TEXT, timestamp TEXT, state TEXT, details TEXT)')
  db.execute('CREATE INDEX IF NOT EXISTS idx_run ON events(run_id)')
  db.commit()

def new_run(): return str(uuid.uuid4())
def write(run_id,state,details=None):
 init_db()
 # Only structured safe metadata; no raw message content.
 safe={k:v for k,v in (details or {}).items() if k in {'role','categories','action','tool','allowed','policy','model','disposition','source_type','source_sha256','reason','result','mode','risk','category'}}
 with _lock, sqlite3.connect(DB) as db:
  db.execute('INSERT INTO events(run_id,timestamp,state,details) VALUES(?,?,?,?)',(run_id,datetime.now(timezone.utc).isoformat(),state,json.dumps(safe)))
  db.commit()

def read(run_id):
 init_db()
 with sqlite3.connect(DB) as db:
  db.row_factory=sqlite3.Row
  rows=db.execute('SELECT timestamp,state,details FROM events WHERE run_id=? ORDER BY id',(run_id,)).fetchall()
 return [{'timestamp':r['timestamp'],'state':r['state'],**json.loads(r['details'])} for r in rows]
def recent(limit=25):
 init_db()
 with sqlite3.connect(DB) as db:
  db.row_factory=sqlite3.Row
  rows=db.execute('SELECT run_id,MAX(timestamp) as timestamp,COUNT(*) as events FROM events GROUP BY run_id ORDER BY timestamp DESC LIMIT ?', (min(limit,100),)).fetchall()
 return [dict(r) for r in rows]
