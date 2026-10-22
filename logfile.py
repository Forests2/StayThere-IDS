"""화면에 찍히는 내용을 logs/dds_YYYY-MM-DD.log 에도 기록 (날짜별 파일 · 오래된 파일 자동 삭제)

  config.json  "retention": {"log_days": 30, "db_days": 30}
  - log_days : logs/ 폴더의 dds_*.log 를 며칠치 남길지 (0 = 파일 기록 안 함)
  - db_days  : dds.db 의 이벤트·경보·사건을 며칠치 남길지 (0 = 안 지움) — storage.prune 이 씀
run_dds.bat · run_dds.sh 로 띄우든 백그라운드(start.sh)로 띄우든 같은 파일에 쌓이고, 화면 출력은 그대로 나온다.
"""
import os
import sys
import threading
from datetime import datetime, timedelta

PREFIX = "dds_"


class _Tee:
    def __init__(self, stream, log_dir, keep_days):
        self.stream = stream
        self.dir = log_dir
        self.keep = keep_days
        self.day = None
        self.fh = None
        self.bol = True
        self.lock = threading.Lock()

    def _roll(self):
        day = datetime.now().strftime("%Y-%m-%d")
        if day == self.day and self.fh:
            return
        if self.fh:
            try:
                self.fh.close()
            except Exception:
                pass
        self.day = day
        try:
            os.makedirs(self.dir, exist_ok=True)
            self.fh = open(os.path.join(self.dir, f"{PREFIX}{day}.log"), "a", encoding="utf-8")
        except OSError:
            self.fh = None
        prune_logs(self.dir, self.keep)

    def write(self, s):
        try:
            self.stream.write(s)
        except Exception:
            pass
        if not s:
            return
        with self.lock:
            self._roll()
            if self.fh:
                try:
                    if self.bol and s.strip() and not s.startswith("["):   # 줄 앞에 시각 (이미 [시각] 이 있으면 생략)
                        self.fh.write(datetime.now().strftime("%H:%M:%S "))
                    self.fh.write(s)
                    self.bol = s.endswith("\n")
                    self.fh.flush()
                except Exception:
                    pass

    def flush(self):
        try:
            self.stream.flush()
        except Exception:
            pass
        if self.fh:
            try:
                self.fh.flush()
            except Exception:
                pass

    def __getattr__(self, name):        # encoding · isatty 등은 원래 스트림 것
        return getattr(self.stream, name)


def prune_logs(log_dir, keep_days):
    """logs/dds_YYYY-MM-DD.log 중 keep_days 일보다 오래된 파일 삭제 → 지운 파일 수"""
    if not keep_days or keep_days <= 0 or not os.path.isdir(log_dir):
        return 0
    cut = (datetime.now() - timedelta(days=keep_days)).strftime("%Y-%m-%d")
    n = 0
    for name in os.listdir(log_dir):
        if name.startswith(PREFIX) and name.endswith(".log") and name[len(PREFIX):-4] < cut:
            try:
                os.remove(os.path.join(log_dir, name))
                n += 1
            except OSError:
                pass
    return n


def install(base, cfg):
    """stdout · stderr 를 날짜별 로그 파일에도 쓰게 바꿈. 돌려주는 값: 로그 폴더 (꺼져 있으면 None)"""
    r = cfg.get("retention") or {}
    keep = int(r.get("log_days", 30) or 0)
    if keep <= 0:
        return None
    log_dir = os.path.join(base, "logs")
    sys.stdout = _Tee(sys.stdout, log_dir, keep)
    sys.stderr = _Tee(sys.stderr, log_dir, keep)
    return log_dir
