"""ARTEX 공격 흐름 시뮬레이션 테스트 (실제 공격 아님, 가짜 이벤트를 탐지기에 주입)

실행: python test_artex_sim.py
 - 시나리오 A: ARTEX식 공격 → 각 단계가 탐지돼야 함
 - 시나리오 B: 정상 사용 → 알림이 없어야 함
"""
import json
import os
from datetime import datetime, timedelta

from detectors import RuleDetector

BASE = os.path.dirname(os.path.abspath(__file__))
CFG = json.load(open(os.path.join(BASE, "config.json"), encoding="utf-8"))


class Clock:
    def __init__(self, start):
        self.t = start

    def __call__(self):
        return self.t

    def tick(self, sec):
        self.t += timedelta(seconds=sec)


def proc(pid, ppid, name, parent, cmd=""):
    return {"pid": pid, "ppid": ppid, "name": name, "parent": parent, "cmdline": cmd}


def net(kind, rip, rport, lport, process="", ai_domain=""):
    return {"kind": kind, "raddr_ip": rip, "raddr_port": rport, "lport": lport,
            "process": process, "ai_domain": ai_domain}


def run(title, steps, det, clock):
    print(f"\n=== {title} ===")
    fired = []
    for label, kind, ev, wait in steps:
        clock.tick(wait)
        fn = {"logon": det.on_logon, "process": det.on_process, "network": det.on_network}[kind]
        alerts = fn(ev)
        tag = ", ".join(f"{s}:{r}" for s, r, _, _ in alerts) or "-"
        print(f"[{clock().strftime('%H:%M:%S')}] {label:38} → {tag}")
        fired += [r for _, r, _, _ in alerts]
    return fired


def scenario_attack():
    clock = Clock(datetime(2026, 10, 14, 2, 10, 0))
    det = RuleDetector(CFG, now_fn=clock)
    attacker = "101.53.80.20"     # CrowdStrike 공개 ARTEX 프록시 IP
    unknown = "45.11.22.33"       # IOC 목록에 없는 새 IP (IP 바꾼 경우)
    steps = []
    # 1) 새 IP로 포트 스캔 (IOC 미등록 IP)
    for i, port in enumerate([21, 22, 80, 135, 139, 443, 445, 1433, 3389, 8080, 8443]):
        steps.append((f"스캔 {unknown} → :{port}", "network",
                      net("inbound", unknown, 50000 + i, port), 1))
    # 2) IOC IP에서 웹 서비스 접속
    steps.append(("ARTEX 프록시 IP 접속 :443", "network",
                  net("inbound", attacker, 51111, 443, "w3wp.exe"), 5))
    # 3) 웹쉘: IIS가 cmd 실행
    steps.append(("w3wp.exe → cmd.exe", "process",
                  proc(5001, 4000, "cmd.exe", "w3wp.exe", "cmd /c whoami"), 20))
    # 4) 정찰 명령 연속 실행 (각각 cmd /c 로 띄워져 부모가 매번 다름)
    for i, c in enumerate(["whoami.exe", "ipconfig.exe", "net.exe", "systeminfo.exe"]):
        steps.append((f"정찰 {c}", "process",
                      proc(5100 + i, 5050 + i, c, "cmd.exe"), 2))
    # 5) 공격자 서버 18899 포트로 역접속
    steps.append(("역접속 38.244.50.120:18899", "network",
                  net("outbound", "38.244.50.120", 18899, 52000, "powershell.exe"), 10))
    return run("시나리오 A: ARTEX식 공격", steps, det, clock)


def scenario_normal():
    clock = Clock(datetime(2026, 10, 14, 10, 0, 0))
    det = RuleDetector(CFG, now_fn=clock)
    steps = [
        ("사용자 로컬 로그인", "logon",
         {"type": "logon_success", "user": "PC\\user", "logon_type": "interactive", "src_ip": "127.0.0.1"}, 0),
        ("explorer → chrome", "process", proc(100, 50, "chrome.exe", "explorer.exe"), 5),
        ("explorer → cmd (사람이 직접)", "process", proc(101, 50, "cmd.exe", "explorer.exe"), 30),
        ("ipconfig 한 번", "process", proc(102, 101, "ipconfig.exe", "cmd.exe"), 20),
        ("chrome → 웹사이트 443", "network", net("outbound", "142.250.1.1", 443, 60000, "chrome.exe"), 5),
        ("ping 한 번 (2분 뒤)", "process", proc(103, 101, "ping.exe", "cmd.exe"), 120),
    ]
    return run("시나리오 B: 정상 사용", steps, det, clock)


if __name__ == "__main__":
    a = scenario_attack()
    b = scenario_normal()
    expect = {"port_scan", "ioc_ip_match", "webserver_spawned_shell", "recon_burst"}
    print("\n=== 결과 ===")
    for r in sorted(expect):
        print(f"  {'OK ' if r in a else 'MISS'} {r}")
    print(f"  정상 사용 알림 수: {len(b)} ({'OK' if not b else '오탐 있음: ' + ', '.join(b)})")
