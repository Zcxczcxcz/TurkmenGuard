import time
import subprocess
import win32gui
import win32ui
import win32con
from PIL import Image

EXE = r"C:\Users\one\Desktop\antivirus\TurkmenGuard\src\TurkmenGuard\bin\Release\TurkmenGuard.exe"
SHOT = r"C:\Users\one\Desktop\antivirus\TurkmenGuard\screenshot-main.png"


def find_hwnd():
    found = []

    def cb(hwnd, _):
        title = win32gui.GetWindowText(hwnd)
        if "Gorag" in title or "Turkmen" in title:
            found.append(hwnd)

    win32gui.EnumWindows(cb, None)
    return found[0] if found else None


hwnd = find_hwnd()
if not hwnd:
    subprocess.Popen([EXE])
    time.sleep(6)
    hwnd = find_hwnd()

if not hwnd:
    raise SystemExit("window not found")

win32gui.SetForegroundWindow(hwnd)
time.sleep(2)
left, top, right, bottom = win32gui.GetWindowRect(hwnd)
w, h = right - left, bottom - top

hwnd_dc = win32gui.GetWindowDC(hwnd)
mfc_dc = win32ui.CreateDCFromHandle(hwnd_dc)
save_dc = mfc_dc.CreateCompatibleDC()
bmp = win32ui.CreateBitmap()
bmp.CreateCompatibleBitmap(mfc_dc, w, h)
save_dc.SelectObject(bmp)
save_dc.BitBlt((0, 0), (w, h), mfc_dc, (0, 0), win32con.SRCCOPY)
info = bmp.GetInfo()
bits = bmp.GetBitmapBits(True)
img = Image.frombuffer("RGB", (info["bmWidth"], info["bmHeight"]), bits, "raw", "BGRX", 0, 1)
img.save(SHOT)
print(f"saved {SHOT} {img.size}")
