Add-Type -AssemblyName System.Drawing
Add-Type @"
using System;
using System.Runtime.InteropServices;
using System.Drawing;
using System.Drawing.Imaging;
public class WinCap {
    [DllImport("user32.dll")] public static extern bool SetForegroundWindow(IntPtr hWnd);
    [DllImport("user32.dll")] public static extern bool GetWindowRect(IntPtr hWnd, out RECT lpRect);
    public struct RECT { public int Left, Top, Right, Bottom; }
    public static void Capture(string titlePart, string path) {
        foreach (var p in System.Diagnostics.Process.GetProcesses()) {
            if (!string.IsNullOrEmpty(p.MainWindowTitle) && p.MainWindowTitle.IndexOf(titlePart, StringComparison.OrdinalIgnoreCase) >= 0) {
                var h = p.MainWindowHandle;
                SetForegroundWindow(h);
                System.Threading.Thread.Sleep(1500);
                RECT r; GetWindowRect(h, out r);
                int w = r.Right - r.Left; int hgt = r.Bottom - r.Top;
                using (var bmp = new Bitmap(w, hgt)) {
                    using (var g = Graphics.FromImage(bmp))
                        g.CopyFromScreen(r.Left, r.Top, 0, 0, new Size(w, hgt));
                    bmp.Save(path, ImageFormat.Png);
                }
                return;
            }
        }
        throw new Exception("Window not found: " + titlePart);
    }
}
"@

$exe = Join-Path $PSScriptRoot "src\TurkmenGuard\bin\Release\TurkmenGuard.exe"
$shot = Join-Path $PSScriptRoot "screenshot-main.png"

$running = Get-Process -Name "TurkmenGuard" -ErrorAction SilentlyContinue
if (-not $running) {
    Start-Process $exe
    Start-Sleep -Seconds 5
}

[WinCap]::Capture("Gorag", $shot)
Write-Host "Screenshot saved: $shot"
