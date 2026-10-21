"""즉각 대응: 외부 침입이 잡히는 순간 알림 + (켜져 있으면) 자동 차단·종료·증거 저장

자동 대응은 확실한 경우만:
  - IP 차단   : BLOCK_RULES(ARTEX IP · 스캔 · 대입 · 외부 RDP · 위협 목록 · ARTEX User-Agent · 분산 IP 등)의 출발지 IP
               분산 IP 공격은 잡힌 IP 전부 (내부망 · 루프백 · trusted_ips 는 절대 자동 차단 안 함)
  - 프로세스 종료 : KILL_RULES(웹쉘 · 계정 정보 탈취 · 권한 상승 도구 · 반입한 공격 파일 · ARTEX 실행)
               해당 프로세스와 그 자식만 (웹 서버 자체는 안 건드림)
  - 증거 저장 : 사건 첫 HIGH 알림 때 한 번
애매한 것(AI 도구 활동, 이상 시간 로그인 등)은 사람이 판단 — 알림만.
"""
import ipaddress
import json
import os
import platform
import subprocess
import threading
import time
import webbrowser
from datetime import datetime

import psutil

from attack_taxonomy import BLOCK_RULES, INTRUSION_RULES, KILL_RULES  # 규칙 묶음은 한 곳에서 관리
import linux_fw
from osutil import IS_LINUX, IS_WIN, admin_word
from osutil import beep as _beep_os
from osutil import toast as _toast_os

BASE = os.path.dirname(os.path.abspath(__file__))

RULE_KO = {"port_scan": "포트 스캔", "ioc_ip_match": "ARTEX 공격 IP", "webserver_spawned_shell": "웹쉘",
           "recon_burst": "정찰 명령 연속", "brute_force": "비밀번호 대입", "remote_rdp_logon": "외부 RDP 로그인",
           "remote_network_logon": "외부 네트워크 로그인", "user_created": "계정 생성",
           "added_to_admin_group": "관리자 권한 획득", "threat_feed_match": "위협 목록 IP",
           "lolbin_outbound": "시스템 도구 외부 접속", "outbound_scan": "이 PC가 다른 PC 스캔",
           "artex_host_artifact": "ARTEX 설치 흔적", "artex_user_agent": "ARTEX 웹 정찰",
           "js_asset_burst": "웹 자동 정찰", "ioc_domain_query": "공격 중계 도메인 조회",
           "agent_command_style": "AI 에이전트식 명령", "retry_loop": "실패-수정 반복",
           "credential_dump": "계정 정보 탈취", "privilege_escalation": "권한 상승",
           "payload_staging": "공격 파일 반입", "distributed_ips": "IP 바꿔 가며 공격",
           "dev_tool_inbound": "AI 개발 도구로 외부 접속",
           "webshell_file_created": "웹쉘 파일 생성", "object_enumeration": "고객번호 열거 · 대량 조회",
           "log_theft": "로그 파일 탈취", "llm_malware_pattern": "LLM 을 부르는 악성코드",
           "llm_then_exec": "LLM 지시로 명령 실행", "autorun_change": "자동 실행 등록",
           "ransomware_prep": "랜섬웨어 준비 (백업 삭제)", "mass_file_change": "대량 파일 암호화 의심",
           "git_spawned_unusual": "git 설정으로 실행", "package_install_exec": "설치 스크립트 다운로드",
           "agent_secret_access": "AI 도구 토큰 탈취"}


# ================= 알림 외부 전송 (Logpresso · syslog 서버 · 사내 웹훅) =================
SEV_RANK = {"LOW": 1, "MEDIUM": 2, "HIGH": 3}


def notify_external(cfg, alert):
    """config.json 의 notify 설정대로 syslog(UDP) · 웹훅(HTTP POST JSON) 으로 보냄. 실패해도 감시는 계속."""
    n = cfg.get("notify", {}) or {}
    if SEV_RANK.get(alert.get("severity"), 0) < SEV_RANK.get(n.get("min_severity", "HIGH"), 3):
        return []
    sent = []
    body = json.dumps(alert, ensure_ascii=False, default=str)
    sl = n.get("syslog", {}) or {}
    if sl.get("enabled") and sl.get("host"):
        try:
            import socket
            pri = 8 * 13 + (2 if alert.get("severity") == "HIGH" else 4)     # facility log audit(13), crit/warning
            msg = f"<{pri}>1 {alert.get('ts')} {alert.get('host')} DDS - {alert.get('rule')} - {body}"
            with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as so:
                so.sendto(msg.encode("utf-8")[:8000], (sl["host"], int(sl.get("port", 514))))
            sent.append("syslog")
        except Exception as e:
            print(f"[알림 전송 실패 · syslog] {e}")
    wh = n.get("webhook", {}) or {}
    if wh.get("enabled") and wh.get("url"):
        try:
            import urllib.request
            req = urllib.request.Request(wh["url"], data=body.encode("utf-8"),
                                         headers={"Content-Type": "application/json"}, method="POST")
            urllib.request.urlopen(req, timeout=3).read()
            sent.append("webhook")
        except Exception as e:
            print(f"[알림 전송 실패 · 웹훅] {e}")
    return sent


# ================= 방화벽 =================
def valid_ip(ip):
    try:
        ipaddress.ip_address(str(ip))
        return True
    except Exception:
        return False


def blocked_list(db):
    return db.meta_get("blocked_ips", [])


def firewall_block(mon, ip, sim=False, by="수동"):
    if not valid_ip(ip):
        return False, "차단할 IP를 찾지 못했어요"
    if sim:
        return True, f"[시뮬레이션] {ip} 차단 명령 확인 (실제 방화벽은 안 바꿈)"
    if any(b["ip"] == ip for b in blocked_list(mon.db)):
        return True, f"{ip} 는 이미 차단돼 있어요"
    if not mon.admin:
        return False, f"{admin_word()}으로 실행해야 방화벽 규칙을 넣을 수 있어요"
    if IS_LINUX:
        ok, msg = linux_fw.block(ip)
        if ok:
            mon.db.meta_set("blocked_ips", blocked_list(mon.db) +
                            [{"ip": ip, "at": datetime.now().strftime("%m-%d %H:%M"), "by": by}])
        return ok, msg
    if not IS_WIN:
        return False, "Windows · Linux 에서만 방화벽 차단이 돼요"
    for dirn in ("in", "out"):
        r = subprocess.run(["netsh", "advfirewall", "firewall", "add", "rule",
                            f"name=DDS_BLOCK_{ip}_{dirn}", f"dir={dirn}", "action=block",
                            f"remoteip={ip}"], capture_output=True, text=True)
        if r.returncode != 0:
            return False, f"방화벽 규칙 실패: {r.stdout.strip() or r.stderr.strip()}"
    mon.db.meta_set("blocked_ips", blocked_list(mon.db) +
                    [{"ip": ip, "at": datetime.now().strftime("%m-%d %H:%M"), "by": by}])
    return True, f"{ip} 들어오고 나가는 연결 모두 차단했어요 (규칙 이름 DDS_BLOCK_{ip})"


def firewall_unblock(mon, ip):
    if not valid_ip(ip):
        return False, "IP 형식이 아니에요"
    if IS_LINUX:
        if not mon.admin:
            return False, f"{admin_word()}으로 실행해야 방화벽 규칙을 지울 수 있어요"
        linux_fw.unblock(ip)
    if IS_WIN:
        if not mon.admin:
            return False, "관리자 권한으로 실행해야 방화벽 규칙을 지울 수 있어요"
        for dirn in ("in", "out"):
            subprocess.run(["netsh", "advfirewall", "firewall", "delete", "rule",
                            f"name=DDS_BLOCK_{ip}_{dirn}"], capture_output=True, text=True)
    mon.db.meta_set("blocked_ips", [b for b in blocked_list(mon.db) if b["ip"] != ip])
    return True, f"{ip} 차단을 풀었어요"


def kill_tree(pid, sim=False):
    if not pid:
        return False, "종료할 프로세스를 찾지 못했어요"
    if sim:
        return True, f"[시뮬레이션] PID {pid} 종료 명령 확인 (실제 종료 안 함)"
    try:
        p = psutil.Process(pid)
        name = p.name()
        for c in p.children(recursive=True):
            try:
                c.kill()
            except Exception:
                pass
        p.kill()
        return True, f"{name} (PID {pid}) 와 자식 프로세스를 종료했어요"
    except psutil.NoSuchProcess:
        return True, f"PID {pid} 는 이미 종료돼 있어요"
    except Exception as e:
        return False, f"종료 실패: {e}"


# ================= 알림 =================
def _beep():
    _beep_os()


def _toast(title, text):
    _toast_os(title, text)


class Responder:
    def __init__(self, mon, port):
        self.mon = mon
        self.url = f"http://127.0.0.1:{port}"
        self.last_notify = 0
        self.last_ack = None
        self.handled = set()     # 이번 사건에서 이미 처리한 IP/PID (중복 방지)
        self.lock = threading.Lock()
        trusted = set(mon.cfg.get("trusted_ips", []))
        self.trusted = trusted

    # 설정 (UI 토글 → DB 에 저장, 재시작해도 유지)
    def enabled(self):
        v = self.mon.db.meta_get("auto_response")
        if v is None:
            v = bool(self.mon.cfg.get("auto_response", {}).get("enabled", False))
        return v

    def set_enabled(self, on):
        self.mon.db.meta_set("auto_response", bool(on))

    def actions(self, limit=30):
        return self.mon.db.meta_get("auto_actions", [])[-limit:]

    def _log(self, text, ok, sim, alert_id):
        acts = self.mon.db.meta_get("auto_actions", [])
        acts.append({"ts": datetime.now().strftime("%H:%M:%S"), "text": text, "ok": ok,
                     "sim": bool(sim), "alertId": alert_id})
        self.mon.db.meta_set("auto_actions", acts[-200:])
        print(f"[자동 대응] {'SIM ' if sim else ''}{text}")

    def _auto_ip(self, ip):
        if not valid_ip(ip):
            return False
        a = ipaddress.ip_address(ip)
        return not (a.is_private or a.is_loopback or a.is_link_local or ip in self.trusted)

    # 알림 하나가 저장될 때마다 호출 (monitor 에서)
    def on_alert(self, alert_id, sev, rule, who, detail, sim=0):
        if rule in INTRUSION_RULES and not sim:
            payload = {"ts": datetime.now().isoformat(timespec="seconds"), "host": self.mon.host, "severity": sev,
                       "rule": rule, "rule_ko": RULE_KO.get(rule, rule), "who": who,
                       "detail": {k: v for k, v in (detail if isinstance(detail, dict) else {}).items()
                                  if k not in ("ancestors", "text")}}
            threading.Thread(target=notify_external, args=(self.mon.cfg, payload), daemon=True).start()
        if rule not in INTRUSION_RULES or sev != "HIGH":
            return
        with self.lock:
            d = detail if isinstance(detail, dict) else {}
            now = time.time()
            ack = self.mon.db.meta_get("ack_id", 0)
            # 새 사건 = '감시 화면으로' 이후 첫 알림, 또는 60초 넘게 조용하다가 온 알림
            first = ack != self.last_ack or now - self.last_notify > 60
            if first:
                self.last_ack = ack
                self.handled = set()
                try:
                    import llm
                    if llm.MANAGER:
                        llm.MANAGER.on_incident()
                except Exception as e:
                    print(f"[AI 분석관 호출 오류] {e}")
            self.last_notify = now
            if first:
                title = "DDS 침입 감지" + (" (시뮬레이션)" if sim else "")
                text = f"{RULE_KO.get(rule, rule)} · {who}"
                threading.Thread(target=_beep, daemon=True).start()
                _toast(title, text)
                if not sim:
                    webbrowser.open(self.url)

            if not self.enabled():
                return
            # 1) IP 차단
            if rule in BLOCK_RULES:
                ip1 = d.get("raddr_ip") or d.get("src_ip") or (who if valid_ip(who) else None)
                targets = list(dict.fromkeys((d.get("ips") or []) + ([ip1] if ip1 else [])))   # 분산 IP 는 묶어서
                for ip in targets:
                    if ip in self.handled:
                        continue
                    self.handled.add(ip)
                    if self._auto_ip(ip):
                        ok, msg = firewall_block(self.mon, ip, sim, by="자동")
                        self._log(f"IP 자동 차단 — {msg}", ok, sim, alert_id)
                    else:
                        self._log(f"{ip} 는 내부망·예약·신뢰 주소라서 자동 차단 안 함 — 직접 확인 후 차단하세요", True, sim, alert_id)
            # 2) 웹쉘 종료
            if rule in KILL_RULES and d.get("pid") and d.get("pid") not in self.handled:
                self.handled.add(d.get("pid"))
                ok, msg = kill_tree(d.get("pid"), sim)
                self._log(f"{RULE_KO.get(rule, rule)} 프로세스 자동 종료 — {msg}", ok, sim, alert_id)
            # 3) 증거 저장 (사건당 한 번)
            if first:
                os.makedirs(os.path.join(BASE, "evidence"), exist_ok=True)
                path = os.path.join(BASE, "evidence", f"auto_{datetime.now():%Y%m%d_%H%M%S}.json")
                with open(path, "w", encoding="utf-8") as f:
                    json.dump({"trigger": {"rule": rule, "who": who, "detail": d, "sim": sim},
                               "recent_events": self.mon.db.recent_events(200)},
                              f, ensure_ascii=False, indent=2, default=str)
                self._log(f"증거 자동 저장 — evidence/{os.path.basename(path)}", True, sim, alert_id)


# ================= 긴급 버튼: 네트워크 격리 =================
def _fw_policy_snapshot():
    """프로필별 현재 방화벽 정책 저장 (해제할 때 그대로 되돌리려고)"""
    out = {}
    for prof in ("domainprofile", "privateprofile", "publicprofile"):
        r = subprocess.run(["netsh", "advfirewall", "show", prof, "firewallpolicy"],
                           capture_output=True, text=True)
        m = None
        for line in r.stdout.splitlines():
            if "," in line and ("Inbound" in line or "inbound" in line):
                m = line.split()[-1]
        out[prof] = m or "BlockInbound,AllowOutbound"
    return out


def emergency_on(mon, reason="긴급 버튼", keep_ips=()):
    st = mon.db.meta_get("emergency", {})
    if st.get("on"):
        return True, "이미 긴급 격리 중이에요"
    done = []
    sim_only = not (IS_WIN or (IS_LINUX and linux_fw.available()))
    if not sim_only and not mon.admin:
        return False, f"{admin_word()}으로 실행해야 긴급 격리를 할 수 있어요"
    snap = None
    if IS_LINUX and not sim_only:
        allow = list(dict.fromkeys(list(mon.cfg.get("emergency_allow_ips", [])) + list(keep_ips)))   # 버튼 누른 PC 는 유지
        ok, msg, path = linux_fw.isolate(allow)
        if not ok:
            return False, msg
        snap = {"linux": True, "file": path}
        done.append(msg)
        if not allow:
            done.append("SSH 로 접속 중이었다면 연결도 끊김 — 서버 콘솔에서 emergency_release.sh 로 해제")
    elif not sim_only:
        snap = _fw_policy_snapshot()
        subprocess.run(["netsh", "advfirewall", "set", "allprofiles", "state", "on"], capture_output=True)
        r = subprocess.run(["netsh", "advfirewall", "set", "allprofiles", "firewallpolicy",
                            "blockinboundalways,blockoutbound"], capture_output=True, text=True)
        if r.returncode != 0:
            return False, f"방화벽 설정 실패: {r.stdout.strip() or r.stderr.strip()}"
        done.append("들어오는 연결 전부 차단 (허용 규칙 무시)")
        done.append("나가는 연결 차단 (허용 규칙이 있는 시스템 통신만 예외)")
    if sim_only:
        done.append("[방화벽 도구가 없어서 방화벽은 안 바꿈]")
    # 진행 중 사건의 웹쉘·공격 프로세스 종료
    try:
        import webui
        inc = webui.build_state(mon).get("incident")
        if inc and inc.get("targetPid") and not inc.get("sim"):
            ok, msg = kill_tree(inc["targetPid"])
            done.append(msg)
    except Exception as e:
        done.append(f"프로세스 정리 건너뜀: {e}")
    os.makedirs(os.path.join(BASE, "evidence"), exist_ok=True)
    path = os.path.join(BASE, "evidence", f"emergency_{datetime.now():%Y%m%d_%H%M%S}.json")
    with open(path, "w", encoding="utf-8") as f:
        json.dump({"reason": reason, "recent_events": mon.db.recent_events(300),
                   "recent_alerts": mon.db.recent_alerts(100)}, f, ensure_ascii=False, indent=2, default=str)
    done.append(f"증거 저장 — evidence/{os.path.basename(path)}")
    mon.db.meta_set("emergency", {"on": True, "at": datetime.now().strftime("%m-%d %H:%M:%S"),
                                  "snapshot": snap, "done": done, "reason": reason, "simOnly": sim_only})
    acts = mon.db.meta_get("auto_actions", [])
    acts.append({"ts": datetime.now().strftime("%H:%M:%S"), "text": "긴급 격리 실행 — " + " · ".join(done),
                 "ok": True, "sim": sim_only, "alertId": mon.db.max_alert_id()})
    mon.db.meta_set("auto_actions", acts[-200:])
    _toast("DDS 긴급 격리", "이 PC 의 네트워크를 차단했어요")
    return True, "긴급 격리했어요 — " + " · ".join(done)


def emergency_off(mon):
    st = mon.db.meta_get("emergency", {})
    if not st.get("on"):
        return True, "긴급 격리 중이 아니에요"
    if IS_LINUX and linux_fw.available():
        if not mon.admin:
            return False, f"{admin_word()}으로 실행해야 해제할 수 있어요"
        linux_fw.release()
    if IS_WIN:
        if not mon.admin:
            return False, "관리자 권한으로 실행해야 해제할 수 있어요"
        snap = st.get("snapshot") or {}
        for prof in ("domainprofile", "privateprofile", "publicprofile"):
            pol = snap.get(prof) or "BlockInbound,AllowOutbound"
            subprocess.run(["netsh", "advfirewall", "set", prof, "firewallpolicy", pol], capture_output=True)
    mon.db.meta_set("emergency", {"on": False, "offAt": datetime.now().strftime("%m-%d %H:%M:%S")})
    acts = mon.db.meta_get("auto_actions", [])
    acts.append({"ts": datetime.now().strftime("%H:%M:%S"), "text": "긴급 차단 해제 — 방화벽 정책을 차단 전으로 복구",
                 "ok": True, "sim": not (IS_WIN or (IS_LINUX and linux_fw.available())), "alertId": mon.db.max_alert_id()})
    mon.db.meta_set("auto_actions", acts[-200:])
    _toast("DDS 긴급 차단 해제", "네트워크 연결을 다시 열었어요")
    return True, "긴급 차단을 해제했어요 — 방화벽 정책을 차단 전으로 되돌렸어요"
