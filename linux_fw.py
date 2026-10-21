"""리눅스 방화벽 (iptables · ip6tables) — DDS 가 넣은 규칙만 다룸

IP 차단   : INPUT  -s IP -j DROP  /  OUTPUT -d IP -j DROP   (주석 DDS_BLOCK_<IP>)
긴급 격리 : DDS_ISOLATE_IN / DDS_ISOLATE_OUT 체인을 INPUT·OUTPUT 맨 앞에 걸어 루프백·허용 IP 말고 전부 DROP
            격리 직전 iptables-save 결과를 evidence/ 에 저장 (사람이 직접 복구할 때 참고)
해제      : DDS 체인과 점프 규칙만 지움 → 다른 방화벽 규칙은 건드리지 않음
"""
import ipaddress
import os
import shutil
import subprocess
from datetime import datetime

BASE = os.path.dirname(os.path.abspath(__file__))
CHAINS = (("INPUT", "DDS_ISOLATE_IN", "-i"), ("OUTPUT", "DDS_ISOLATE_OUT", "-o"))


def _bin(ip=None):
    v6 = False
    if ip:
        try:
            v6 = ipaddress.ip_address(ip).version == 6
        except ValueError:
            pass
    return shutil.which("ip6tables" if v6 else "iptables")


def available():
    return bool(shutil.which("iptables"))


def _run(args):
    r = subprocess.run(args, capture_output=True, text=True, timeout=15)
    return r.returncode == 0, (r.stderr or r.stdout).strip()


def _exists(b, chain, spec):
    return subprocess.run([b, "-w", "-C", chain] + spec, capture_output=True, timeout=15).returncode == 0


def block(ip):
    b = _bin(ip)
    if not b:
        return False, "iptables 가 없어서 차단할 수 없어요 (sudo apt/dnf install iptables)"
    tag = ["-m", "comment", "--comment", f"DDS_BLOCK_{ip}"]
    for chain, spec in (("INPUT", ["-s", ip, "-j", "DROP"] + tag), ("OUTPUT", ["-d", ip, "-j", "DROP"] + tag)):
        if _exists(b, chain, spec):
            continue
        ok, msg = _run([b, "-w", "-I", chain, "1"] + spec)
        if not ok:
            return False, f"iptables 실패: {msg}"
    return True, f"{ip} 들어오고 나가는 연결 모두 차단했어요 (iptables 주석 DDS_BLOCK_{ip})"


def unblock(ip):
    b = _bin(ip)
    if not b:
        return False, "iptables 가 없어요"
    tag = ["-m", "comment", "--comment", f"DDS_BLOCK_{ip}"]
    for chain, spec in (("INPUT", ["-s", ip, "-j", "DROP"] + tag), ("OUTPUT", ["-d", ip, "-j", "DROP"] + tag)):
        while _exists(b, chain, spec):
            _run([b, "-w", "-D", chain] + spec)
    return True, f"{ip} 차단을 풀었어요"


def is_blocked(ip):
    b = _bin(ip)
    if not b:
        return None
    return _exists(b, "INPUT", ["-s", ip, "-j", "DROP", "-m", "comment", "--comment", f"DDS_BLOCK_{ip}"])


def remove_all_blocks():
    """DDS_BLOCK_ 주석이 붙은 규칙 전부 삭제 (emergency_release --all-ip)"""
    n = 0
    for b in filter(None, (shutil.which("iptables"), shutil.which("ip6tables"))):
        save = shutil.which(os.path.basename(b) + "-save")
        if not save:
            continue
        out = subprocess.run([save], capture_output=True, text=True).stdout
        for line in out.splitlines():
            if line.startswith("-A ") and "DDS_BLOCK_" in line:
                parts = [x.strip('"') for x in line.split()]   # 주석에 공백이 없으니 단순 분리 + 따옴표 제거
                ok, _ = _run([b, "-w", "-D"] + parts[1:])
                n += ok
    return n


def isolate(allow_ips=()):
    """긴급 격리: 루프백과 allow_ips 만 남기고 들어오고 나가는 연결 전부 차단"""
    if not available():
        return False, "iptables 가 없어서 격리할 수 없어요", None
    os.makedirs(os.path.join(BASE, "evidence"), exist_ok=True)
    snap = os.path.join(BASE, "evidence", f"iptables_before_isolate_{datetime.now():%Y%m%d_%H%M%S}.rules")
    try:
        with open(snap, "w") as f:
            f.write(subprocess.run(["iptables-save"], capture_output=True, text=True).stdout)
    except Exception:
        snap = None
    for b in filter(None, (shutil.which("iptables"), shutil.which("ip6tables"))):
        for parent, chain, iface in CHAINS:
            _run([b, "-w", "-N", chain])
            _run([b, "-w", "-F", chain])
            _run([b, "-w", "-A", chain, iface, "lo", "-j", "RETURN"])
            v6 = b.endswith("ip6tables")
            for ip in allow_ips:
                try:
                    if (ipaddress.ip_network(ip, strict=False).version == 6) != v6:
                        continue
                except ValueError:
                    continue
                _run([b, "-w", "-A", chain, "-s" if parent == "INPUT" else "-d", ip, "-j", "RETURN"])
            _run([b, "-w", "-A", chain, "-j", "DROP"])
            if not _exists(b, parent, ["-j", chain]):
                ok, msg = _run([b, "-w", "-I", parent, "1", "-j", chain])
                if not ok and not v6:
                    return False, f"iptables 실패: {msg}", snap
    return True, "들어오고 나가는 연결 전부 차단 (루프백" + (f" · 허용 IP {len(allow_ips)}개" if allow_ips else "") + " 제외)", snap


def release():
    """긴급 격리 해제: DDS 체인과 점프 규칙만 지움"""
    if not available():
        return False, "iptables 가 없어요"
    for b in filter(None, (shutil.which("iptables"), shutil.which("ip6tables"))):
        for parent, chain, _ in CHAINS:
            while _exists(b, parent, ["-j", chain]):
                _run([b, "-w", "-D", parent, "-j", chain])
            _run([b, "-w", "-F", chain])
            _run([b, "-w", "-X", chain])
    return True, "격리를 풀었어요 (DDS 격리 체인만 지움 · 다른 방화벽 규칙은 그대로)"


def is_isolated():
    b = shutil.which("iptables")
    return bool(b) and _exists(b, "INPUT", ["-j", "DDS_ISOLATE_IN"])
