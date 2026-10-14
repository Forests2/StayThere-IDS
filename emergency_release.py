r"""긴급 차단 해제 (DDS 화면이 안 열릴 때 쓰는 비상용)

사용: emergency_release.bat 더블클릭  (관리자 권한 자동 요청)
     또는 관리자 CMD 에서  python emergency_release.py
하는 일
  1. DDS 가 긴급 격리 직전에 저장해 둔 방화벽 정책으로 되돌림
     (저장된 게 없으면 Windows 기본값: 들어옴 차단 · 나감 허용)
  2. dds.db 의 긴급 격리 상태를 '해제' 로 바꿈
  --all-ip  옵션을 주면 DDS 가 넣은 IP 차단 규칙(DDS_BLOCK_*)도 전부 지움
"""
import json
import os
import platform
import sqlite3
import subprocess
import sys
from datetime import datetime

BASE = os.path.dirname(os.path.abspath(__file__))
DEFAULT = "BlockInbound,AllowOutbound"


def is_admin():
    try:
        import ctypes
        return bool(ctypes.windll.shell32.IsUserAnAdmin())
    except Exception:
        return False


def read_meta(con, k):
    r = con.execute("SELECT v FROM meta WHERE k=?", (k,)).fetchone()
    return json.loads(r[0]) if r else None


def main():
    if platform.system() != "Windows":
        print("Windows 에서만 동작해요.")
        return 1
    if not is_admin():
        print("관리자 권한이 필요해요. emergency_release.bat 로 실행하거나 관리자 CMD 에서 실행하세요.")
        return 1

    snap, con = None, None
    db = os.path.join(BASE, "dds.db")
    try:
        cfgp = os.path.join(BASE, "config.json")
        if os.path.exists(cfgp):
            with open(cfgp, encoding="utf-8") as f:
                db = os.path.join(BASE, json.load(f).get("db_path", "dds.db"))
    except Exception:
        pass
    if os.path.exists(db):
        con = sqlite3.connect(db)
        try:
            st = read_meta(con, "emergency") or {}
            snap = st.get("snapshot")
            print(f"긴급 격리 기록: {'격리 중' if st.get('on') else '격리 아님'}"
                  + (f" ({st.get('at')} 부터)" if st.get("at") else ""))
        except Exception as e:
            print(f"DB 읽기 실패 (기본값으로 복구): {e}")

    print("\n[방화벽 정책 복구]")
    for prof in ("domainprofile", "privateprofile", "publicprofile"):
        pol = (snap or {}).get(prof) or DEFAULT
        r = subprocess.run(["netsh", "advfirewall", "set", prof, "firewallpolicy", pol],
                           capture_output=True, text=True)
        print(f"  {prof:15} → {pol:30} {'OK' if r.returncode == 0 else '실패: ' + (r.stdout or r.stderr).strip()}")

    if "--all-ip" in sys.argv:
        print("\n[DDS 가 넣은 IP 차단 규칙 삭제]")
        r = subprocess.run(["netsh", "advfirewall", "firewall", "show", "rule", "name=all"],
                           capture_output=True, text=True, errors="ignore")
        names = sorted({ln.split(":", 1)[1].strip() for ln in r.stdout.splitlines()
                        if ":" in ln and "DDS_BLOCK_" in ln})
        for n in names:
            subprocess.run(["netsh", "advfirewall", "firewall", "delete", "rule", f"name={n}"], capture_output=True)
            print(f"  삭제: {n}")
        if con:
            con.execute("INSERT OR REPLACE INTO meta(k,v) VALUES('blocked_ips', '[]')")
        print(f"  {len(names)}개 삭제")

    if con:
        con.execute("INSERT OR REPLACE INTO meta(k,v) VALUES('emergency', ?)",
                    (json.dumps({"on": False, "offAt": datetime.now().strftime("%m-%d %H:%M:%S"),
                                 "by": "emergency_release"}),))
        con.commit()
        con.close()
    print("\n긴급 차단을 풀었어요. 인터넷·사내망 연결을 확인하세요.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
