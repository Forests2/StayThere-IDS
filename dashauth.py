"""대시보드 접속 제어 — 내부망에서 다른 PC 가 볼 때 (config.json 의 dashboard)

  host      : 127.0.0.1 이면 이 PC 에서만 (기본). 0.0.0.0 이면 내부망에서 접속 가능
  port      : 대시보드 포트
  allow_ips : 접속을 허락할 IP · 대역 (CIDR). 여기 없으면 403
  password  : false 면 비밀번호 없이 allow_ips 대역만 확인 (기본 true)
  password_file : 내부망 접속 비밀번호 (set_password.sh 로 만듦, 해시만 저장)
이 PC(127.0.0.1)에서 여는 건 비밀번호를 묻지 않고, 다른 PC 에서 열면 비밀번호를 물음.
"""
import base64
import getpass
import hashlib
import hmac
import ipaddress
import json
import os
import secrets
import sys

BASE = os.path.dirname(os.path.abspath(__file__))
DEFAULT = {"host": "127.0.0.1", "port": 8765, "allow_ips": ["127.0.0.1/32", "::1/128"],
           "password": True, "password_file": "data/dashboard_auth.json"}


def settings(cfg):
    d = {**DEFAULT, **(cfg.get("dashboard") or {})}
    p = d["password_file"]
    d["password_path"] = p if os.path.isabs(p) else os.path.join(BASE, p)
    return d


def remote_mode(d):
    return d["host"] not in ("127.0.0.1", "localhost", "::1")


def is_loopback(ip):
    try:
        return ipaddress.ip_address(ip.split("%")[0]).is_loopback
    except ValueError:
        return False


def ip_allowed(d, ip):
    try:
        a = ipaddress.ip_address(ip.split("%")[0])
        if a.version == 6 and a.ipv4_mapped:
            a = a.ipv4_mapped
    except ValueError:
        return False
    if a.is_loopback:
        return True
    for n in d.get("allow_ips", []):
        try:
            if a in ipaddress.ip_network(n, strict=False):
                return True
        except ValueError:
            continue
    return False


def _hash(pw, salt, it):
    return hashlib.pbkdf2_hmac("sha256", pw.encode("utf-8"), bytes.fromhex(salt), it).hex()


def has_password(d):
    return os.path.isfile(d["password_path"])


def check_basic(d, header):
    """Authorization: Basic ... → 비밀번호가 맞으면 True"""
    if not header or not header.startswith("Basic ") or not has_password(d):
        return False
    try:
        user_pw = base64.b64decode(header[6:]).decode("utf-8", "ignore")
        pw = user_pw.split(":", 1)[1] if ":" in user_pw else user_pw
        with open(d["password_path"], encoding="utf-8") as f:
            st = json.load(f)
        return hmac.compare_digest(_hash(pw, st["salt"], st["iter"]), st["hash"])
    except Exception:
        return False


def set_password(d, pw):
    salt, it = secrets.token_hex(16), 200_000
    os.makedirs(os.path.dirname(d["password_path"]), exist_ok=True)
    with open(d["password_path"], "w", encoding="utf-8") as f:
        json.dump({"salt": salt, "iter": it, "hash": _hash(pw, salt, it)}, f)
    try:
        os.chmod(d["password_path"], 0o600)
    except OSError:
        pass


def main():
    """python3 dashauth.py  → 대시보드 비밀번호 설정 (set_password.sh)"""
    with open(os.path.join(BASE, "config.json"), encoding="utf-8") as f:
        d = settings(json.load(f))
    print(f"대시보드 비밀번호 설정 — 다른 PC 에서 http://<이 서버 IP>:{d['port']} 접속할 때 물어봅니다 (아이디는 아무거나)")
    while True:
        a = getpass.getpass("새 비밀번호 (8자 이상): ")
        if len(a) < 8:
            print("8자 이상으로 해 주세요")
            continue
        if a != getpass.getpass("한 번 더: "):
            print("두 번 입력한 게 달라요")
            continue
        break
    set_password(d, a)
    print(f"저장했어요 → {d['password_path']} (해시만 저장)")
    return 0


if __name__ == "__main__":
    sys.exit(main())
