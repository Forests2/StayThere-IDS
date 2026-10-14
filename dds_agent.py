"""DDS 에이전트: 개인 PC에 설치해 침입자(누가)와 AI 해킹 도구(무엇이)를 탐지하고 화면에 표시

실행 (관리자 권한 명령 프롬프트 권장):
    python dds_agent.py                 # 감시 시작 + 대시보드 화면 자동으로 열림
    python dds_agent.py --no-browser    # 화면 자동 열기 끄기
    python dds_agent.py --alerts        # 최근 알림만 출력
대시보드 주소: http://127.0.0.1:8765
"""
import argparse
import json
import os
import sys
import threading
import webbrowser

from monitor import Monitor
from storage import Storage

BASE = os.path.dirname(os.path.abspath(__file__))


def load_cfg():
    with open(os.path.join(BASE, "config.json"), encoding="utf-8") as f:
        return json.load(f)


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--alerts", action="store_true", help="최근 알림 출력")
    ap.add_argument("--port", type=int, default=8765)
    ap.add_argument("--no-browser", action="store_true")
    args = ap.parse_args()

    cfg = load_cfg()
    db = Storage(os.path.join(BASE, cfg["db_path"]))
    if args.alerts:
        for a in db.recent_alerts():
            print(a["ts"], a["severity"], a["rule"], a["who"], "SIM" if a["sim"] else "")
        return

    import webui
    mon = Monitor(cfg, db)
    for w in mon.warnings:
        print("[경고]", w)
    from responder import Responder
    mon.responder = Responder(mon, args.port)
    print(f"자동 대응: {'켜짐' if mon.responder.enabled() else '꺼짐 (대시보드에서 켤 수 있음)'}")
    import llm
    llm.start_manager(mon)
    st = llm.status()
    print(f"AI 분석관: API {'설정됨' if st['cfg']['api']['url'] else '미설정'} · "
          f"GGUF 폴더 {len(st['ggufFiles'])}개 ({st['ggufDir']}) · llama-cpp {'있음' if st['llamaCpp'] else '없음'}")
    mon.start()

    srv = webui.serve(mon, args.port)
    url = f"http://127.0.0.1:{args.port}"
    print(f"DDS 감시 시작: {mon.host} · 대시보드 {url} · 종료는 Ctrl+C")
    if not args.no_browser:
        threading.Timer(1.0, lambda: webbrowser.open(url)).start()
    try:
        srv.serve_forever()
    except KeyboardInterrupt:
        print("종료")
    finally:
        mon.stop_evt.set()
        srv.server_close()


if __name__ == "__main__":
    sys.exit(main())
