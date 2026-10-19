"""평소 패턴 학습 — 이 PC 에서 평소에 일어나는 일을 배워 두고, 처음 보는 행동이 몰리면 알림

방식 (외부 라이브러리 없이, 폐쇄망에서도 동작)
 - dds.db 에 쌓인 '실제' 이벤트(시뮬레이션 제외)로 다음 조합의 빈도를 셈
     프로세스: 부모 → 자식 이름, 실행 파일 폴더, 명령줄 첫 단어
     네트워크: 프로그램 → 원격 포트(나감), 내 포트 ← 들어옴
 - 학습량이 충분해지기 전(기본 7일 · 이벤트 3,000건)은 '학습 중' — 알림 없음
 - 학습 뒤에는 처음 보는 조합이 10분 안에 3개 이상 몰리면 baseline_anomaly (MEDIUM, 확인 필요)
 - 이상 점수만으로는 침입이라고 단정하지 않음 → 빨간 경보가 아니라 '확인 필요' 기록
   (AIPFL-IDS 설계 원칙: 불확실한 판단은 자동 차단하지 말고 사람에게 넘긴다)
"""
import ntpath
import threading
from collections import Counter, deque
from datetime import datetime, timedelta


def _dir(path):
    d = ntpath.dirname((path or "").lower())
    # 사용자 이름이 들어간 경로는 사람마다 달라서 묶음
    parts = d.split("\\")
    if len(parts) > 2 and parts[1] == "users":
        parts[2] = "<user>"
    return "\\".join(parts[:5])


def features(kind, d):
    """이벤트 → 학습할 조합 목록 [(종류, 값)]"""
    out = []
    if kind == "process":
        name = (d.get("name") or "").lower()
        parent = (d.get("parent") or "").lower()
        if not name:
            return out
        out.append(("pair", f"{parent}>{name}"))
        if d.get("exe"):
            out.append(("dir", f"{name}@{_dir(d.get('exe'))}"))
        cmd = (d.get("cmdline") or "").strip().lower().split()
        if len(cmd) > 1 and name in ("cmd.exe", "powershell.exe", "pwsh.exe"):
            arg = next((c for c in cmd[1:] if not c.startswith(("/", "-"))), "")
            out.append(("shellverb", f"{name}:{arg[:24]}"))
    elif kind == "network":
        proc = (d.get("process") or "").lower()
        k = d.get("kind")
        if k == "outbound" and d.get("raddr_port"):
            out.append(("out", f"{proc}>{d.get('raddr_port')}"))
        elif k == "inbound" and d.get("lport"):
            out.append(("in", f"{proc}<{d.get('lport')}"))
    return out


class Baseline:
    def __init__(self, cfg, db=None, now_fn=datetime.now):
        c = cfg.get("baseline", {})
        self.enabled = c.get("enabled", True)
        self.learn_days = c.get("learn_days", 7)
        self.min_events = c.get("min_events", 3000)
        self.burst = c.get("burst", 3)
        self.window = c.get("window_sec", 600)
        self.history_days = c.get("history_days", 30)
        self.db, self.now = db, now_fn
        self.counts = Counter()
        self.events = 0
        self.first_ts = None
        self.recent = deque()           # (시각, 조합, 설명)
        self.lock = threading.Lock()
        self.last_refresh = None

    # ---------- 학습 ----------
    def learn(self, kind, d, ts=None):
        for f in features(kind, d):
            self.counts[f] += 1
        self.events += 1
        if ts and (self.first_ts is None or ts < self.first_ts):
            self.first_ts = ts

    def refresh(self):
        """dds.db 에서 다시 학습 (시작할 때 · 1시간마다)"""
        if not self.db or not self.enabled:
            return
        since = (self.now() - timedelta(days=self.history_days)).isoformat(timespec="seconds")
        counts, n, first = Counter(), 0, None
        for ts, kind, d in self.db.iter_events(since):
            for f in features(kind, d):
                counts[f] += 1
            n += 1
            first = ts if first is None or ts < first else first
        with self.lock:
            self.counts, self.events = counts, n
            self.first_ts = datetime.fromisoformat(first) if first else None
            self.last_refresh = self.now()

    def ready(self):
        if not self.enabled or self.events < self.min_events or not self.first_ts:
            return False
        return (self.now() - self.first_ts).days >= self.learn_days

    def status(self):
        if not self.enabled:
            return "꺼짐"
        if self.ready():
            return f"사용 중 (학습 이벤트 {self.events:,}건 · 조합 {len(self.counts):,}개)"
        days = (self.now() - self.first_ts).days if self.first_ts else 0
        return f"학습 중 ({days}/{self.learn_days}일 · 이벤트 {self.events:,}/{self.min_events:,}건)"

    # ---------- 판단 ----------
    def check(self, kind, d):
        """새 이벤트 1건 → [(severity, rule, who, detail)]  (학습 중이면 학습만)"""
        if not self.enabled:
            return []
        now = self.now()
        feats = features(kind, d)
        alerts = []
        with self.lock:
            if self.ready():
                new = [f for f in feats if self.counts.get(f, 0) == 0]
                for f in new:
                    self.recent.append((now, f, d.get("name") or d.get("process") or ""))
                while self.recent and (now - self.recent[0][0]).total_seconds() > self.window:
                    self.recent.popleft()
                uniq = list(dict.fromkeys(x[1] for x in self.recent))
                if new and len(uniq) >= self.burst:
                    alerts.append(("MEDIUM", "baseline_anomaly", ", ".join(dict.fromkeys(x[2] for x in self.recent))[:80],
                                   {"new": [f"{a}:{b}" for a, b in uniq][:10], "count": len(uniq),
                                    "window_sec": self.window, "learned": self.events}))
                    self.recent.clear()
            for f in feats:                       # 본 것은 바로 배움 (같은 조합으로 반복 알림 안 함)
                self.counts[f] += 1
            self.events += 1
            if self.first_ts is None:
                self.first_ts = now
        return alerts
