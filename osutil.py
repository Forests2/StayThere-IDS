"""운영체제별 도우미 (Windows · Linux)"""
import os
import platform
import shutil
import subprocess
import time

IS_WIN = platform.system() == "Windows"
IS_LINUX = platform.system() == "Linux"


def is_admin():
    if IS_WIN:
        try:
            import ctypes
            return bool(ctypes.windll.shell32.IsUserAnAdmin())
        except Exception:
            return False
    try:
        return os.geteuid() == 0
    except AttributeError:
        return False


def admin_word():
    return "관리자 권한" if IS_WIN else "root 권한(sudo)"


def beep():
    try:
        if IS_WIN:
            import winsound
            for _ in range(3):
                winsound.Beep(1200, 180)
                time.sleep(0.08)
        else:
            print("\a", end="", flush=True)
    except Exception:
        pass


def toast(title, text):
    """바탕화면 알림 — Windows: 풍선 알림(PowerShell) · Linux: notify-send (화면이 있을 때만)"""
    try:
        if IS_WIN:
            t = title.replace("'", "''")[:60]
            m = text.replace("'", "''")[:200]
            ps = ("Add-Type -AssemblyName System.Windows.Forms;Add-Type -AssemblyName System.Drawing;"
                  "$n=New-Object System.Windows.Forms.NotifyIcon;$n.Icon=[System.Drawing.SystemIcons]::Warning;"
                  f"$n.BalloonTipTitle='{t}';$n.BalloonTipText='{m}';$n.Visible=$true;"
                  "$n.ShowBalloonTip(8000);Start-Sleep -Seconds 9;$n.Dispose()")
            subprocess.Popen(["powershell", "-NoProfile", "-WindowStyle", "Hidden", "-Command", ps],
                             creationflags=getattr(subprocess, "CREATE_NO_WINDOW", 0))
        elif (os.environ.get("DISPLAY") or os.environ.get("WAYLAND_DISPLAY")) and shutil.which("notify-send"):
            subprocess.Popen(["notify-send", "-u", "critical", title[:60], text[:200]])
        # 화면 없는 서버: 콘솔 출력 · syslog/웹훅 전송(config notify)으로 알림
    except Exception:
        pass
