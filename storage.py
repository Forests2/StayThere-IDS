"""SQLite 저장소: 수집 이벤트, 탐지 알림, 설정값(meta)"""
import json
import sqlite3
import threading
from datetime import datetime

SCHEMA = """
CREATE TABLE IF NOT EXISTS events (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    ts TEXT NOT NULL,
    host TEXT NOT NULL,
    kind TEXT NOT NULL,          -- logon / process / network
    data TEXT NOT NULL,          -- JSON
    sim INTEGER NOT NULL DEFAULT 0
);
CREATE TABLE IF NOT EXISTS alerts (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    ts TEXT NOT NULL,
    host TEXT NOT NULL,
    severity TEXT NOT NULL,      -- LOW / MEDIUM / HIGH
    rule TEXT NOT NULL,
    who TEXT,
    detail TEXT NOT NULL,        -- JSON
    sim INTEGER NOT NULL DEFAULT 0
);
CREATE TABLE IF NOT EXISTS meta (k TEXT PRIMARY KEY, v TEXT);
CREATE TABLE IF NOT EXISTS incidents (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    ts TEXT NOT NULL,            -- 확인(종료) 시각
    mode TEXT NOT NULL,          -- ai / hacker
    title TEXT NOT NULL,
    sim INTEGER NOT NULL DEFAULT 0,
    data TEXT NOT NULL           -- 사건 전체 JSON
);
CREATE INDEX IF NOT EXISTS ix_events_ts ON events(ts);
CREATE INDEX IF NOT EXISTS ix_alerts_ts ON alerts(ts);
"""


def _now():
    return datetime.now().isoformat(timespec="seconds")


class Storage:
    def __init__(self, path):
        self.conn = sqlite3.connect(path, check_same_thread=False)
        self.conn.row_factory = sqlite3.Row
        self.lock = threading.Lock()
        with self.lock:
            self.conn.executescript(SCHEMA)
            for t in ("events", "alerts"):   # 예전 DB 호환
                cols = [r[1] for r in self.conn.execute(f"PRAGMA table_info({t})")]
                if "sim" not in cols:
                    self.conn.execute(f"ALTER TABLE {t} ADD COLUMN sim INTEGER NOT NULL DEFAULT 0")
            self.conn.commit()

    # ---------- 쓰기 ----------
    def add_event(self, host, kind, data, sim=0):
        with self.lock:
            self.conn.execute(
                "INSERT INTO events(ts,host,kind,data,sim) VALUES(?,?,?,?,?)",
                (_now(), host, kind, json.dumps(data, ensure_ascii=False, default=str), sim))
            self.conn.commit()

    def add_alert(self, host, severity, rule, who, detail, sim=0):
        with self.lock:
            cur = self.conn.execute(
                "INSERT INTO alerts(ts,host,severity,rule,who,detail,sim) VALUES(?,?,?,?,?,?,?)",
                (_now(), host, severity, rule, who,
                 json.dumps(detail, ensure_ascii=False, default=str), sim))
            self.conn.commit()
            return cur.lastrowid

    def meta_set(self, k, v):
        with self.lock:
            self.conn.execute("INSERT OR REPLACE INTO meta(k,v) VALUES(?,?)",
                              (k, json.dumps(v, ensure_ascii=False, default=str)))
            self.conn.commit()

    # ---------- 읽기 ----------
    def meta_get(self, k, default=None):
        with self.lock:
            r = self.conn.execute("SELECT v FROM meta WHERE k=?", (k,)).fetchone()
        return json.loads(r["v"]) if r else default

    def _rows(self, sql, args=()):
        with self.lock:
            rows = self.conn.execute(sql, args).fetchall()
        out = []
        for r in rows:
            d = dict(r)
            for key in ("detail", "data"):
                if key in d:
                    try:
                        d[key] = json.loads(d[key])
                    except Exception:
                        pass
            out.append(d)
        return out

    def alerts_after(self, last_id, since_ts):
        return self._rows("SELECT * FROM alerts WHERE id>? AND ts>=? ORDER BY id ASC",
                          (last_id, since_ts))

    def max_alert_id(self):
        with self.lock:
            r = self.conn.execute("SELECT COALESCE(MAX(id),0) m FROM alerts").fetchone()
        return r["m"]

    def iter_events(self, since, kinds=("process", "network"), limit=200000):
        """평소 패턴 학습용: 시뮬레이션이 아닌 이벤트 (ts, kind, data)"""
        q = ("SELECT ts, kind, data FROM events WHERE sim=0 AND ts>=? AND kind IN (%s) ORDER BY id DESC LIMIT ?"
             % ",".join("?" * len(kinds)))
        with self.lock:
            rows = self.conn.execute(q, (since, *kinds, limit)).fetchall()
        for ts, kind, data in rows:
            try:
                yield ts, kind, json.loads(data)
            except Exception:
                continue

    def recent_events(self, limit=8):
        return self._rows("SELECT * FROM events ORDER BY id DESC LIMIT ?", (limit,))

    def recent_alerts(self, limit=50):
        return self._rows("SELECT * FROM alerts ORDER BY id DESC LIMIT ?", (limit,))

    # ---------- 메뉴 화면용 ----------
    def add_incident(self, inc):
        with self.lock:
            self.conn.execute("INSERT INTO incidents(ts,mode,title,sim,data) VALUES(?,?,?,?,?)",
                              (_now(), inc["mode"], inc["title"], 1 if inc.get("sim") else 0,
                               json.dumps(inc, ensure_ascii=False, default=str)))
            self.conn.commit()

    def incidents(self, limit=60, include_sim=True):
        q = "SELECT * FROM incidents" + ("" if include_sim else " WHERE sim=0") + " ORDER BY id DESC LIMIT ?"
        return self._rows(q, (limit,))

    def alerts_query(self, since_ts, severities, include_sim=True, limit=300):
        marks = ",".join("?" * len(severities))
        q = f"SELECT * FROM alerts WHERE ts>=? AND severity IN ({marks})" + \
            ("" if include_sim else " AND sim=0") + " ORDER BY id DESC LIMIT ?"
        return self._rows(q, (since_ts, *severities, limit))

    def rule_stats(self, since_ts):
        with self.lock:
            rows = self.conn.execute(
                "SELECT rule, sim, COUNT(*) c, MAX(ts) last FROM alerts WHERE ts>=? GROUP BY rule, sim",
                (since_ts,)).fetchall()
        return [dict(r) for r in rows]

    def find_ip(self, ip, limit=500):
        """이 IP가 들어간 알림·이벤트 (JSON 안의 "ip" 문자열 검색)"""
        pat = f'%"{ip}"%'
        alerts = self._rows("SELECT * FROM alerts WHERE detail LIKE ? OR who=? ORDER BY id DESC LIMIT ?",
                            (pat, ip, limit))
        events = self._rows("SELECT * FROM events WHERE data LIKE ? ORDER BY id DESC LIMIT ?", (pat, limit))
        return alerts, events

    def count_alerts_today(self):
        day = datetime.now().strftime("%Y-%m-%d")
        with self.lock:
            r = self.conn.execute("SELECT COUNT(*) c FROM alerts WHERE ts>=? AND severity='HIGH'",
                                  (day,)).fetchone()
        return r["c"]
