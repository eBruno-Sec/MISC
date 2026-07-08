# strip-exif.ps1
# Strips ALL metadata (GPS location, camera model, timestamps, etc.)
# from food photos before they go into the website.
#
# HOW TO USE:
#   1. Drop your renamed .jpg photos into the  images\  folder
#   2. Right-click this file → "Run with PowerShell"
#   3. Originals are backed up to  images\originals\  first,
#      then clean copies replace them in  images\
#
# ── PHOTO NAMING CONVENTION ──────────────────────────────────────
#
#   images\hero.jpg           →  hero panel (homepage right side)
#   images\menu-classic.jpg   →  Classic Chicken Katsu card
#   images\menu-curry.jpg     →  Katsu Curry Bowl card
#   images\menu-sando.jpg     →  Katsu Sando card
#   images\menu-spicy.jpg     →  Spicy Katsu Don card
#   images\menu-set.jpg       →  Katsu Set Meal card
#   images\menu-kids.jpg      →  Kids' Mini Katsu card
#
# ── iPHONE NOTE ──────────────────────────────────────────────────
#   If photos are .HEIC: open in Windows Photos → ... → Save a copy
#   → choose JPEG, then rename and drop into images\
# ─────────────────────────────────────────────────────────────────

Set-StrictMode -Version Latest
$ErrorActionPreference = "Stop"

Add-Type -AssemblyName System.Drawing

$imagesDir = Join-Path $PSScriptRoot "images"
$backupDir = Join-Path $imagesDir   "originals"

if (-not (Test-Path $imagesDir)) {
    Write-Host "`n  images\ folder not found next to this script." -ForegroundColor Red
    Read-Host "`nPress Enter to close"; exit
}

if (-not (Test-Path $backupDir)) {
    New-Item -ItemType Directory -Path $backupDir | Out-Null
}

$files = Get-ChildItem -Path $imagesDir -File |
         Where-Object { $_.Extension -match '^\.(jpg|jpeg)$' }

if (-not $files) {
    Write-Host "`n  No .jpg / .jpeg files found in  images\"  -ForegroundColor Yellow
    Write-Host "  Add your renamed photos there and run again."
    Read-Host "`nPress Enter to close"; exit
}

$codec = [System.Drawing.Imaging.ImageCodecInfo]::GetImageEncoders() |
         Where-Object { $_.MimeType -eq "image/jpeg" } |
         Select-Object -First 1

$encParams = New-Object System.Drawing.Imaging.EncoderParameters(1)
$encParams.Param[0] = New-Object System.Drawing.Imaging.EncoderParameter(
    [System.Drawing.Imaging.Encoder]::Quality, [long]92
)

Write-Host ""
Write-Host "  Stripping metadata from $($files.Count) file(s) in images\" -ForegroundColor Cyan
Write-Host ""

$ok = 0; $fail = 0

foreach ($file in $files) {
    Write-Host "  $($file.Name)" -NoNewline
    $src = $file.FullName
    $tmp = $src + ".tmp"

    try {
        Copy-Item -Path $src -Destination (Join-Path $backupDir $file.Name) -Force

        $img = [System.Drawing.Image]::FromFile($src)
        $bmp = New-Object System.Drawing.Bitmap($img.Width, $img.Height)
        $bmp.SetResolution($img.HorizontalResolution, $img.VerticalResolution)
        $g   = [System.Drawing.Graphics]::FromImage($bmp)
        $g.InterpolationMode  = [System.Drawing.Drawing2D.InterpolationMode]::HighQualityBicubic
        $g.CompositingQuality = [System.Drawing.Drawing2D.CompositingQuality]::HighQuality
        $g.DrawImage($img, 0, 0, $img.Width, $img.Height)
        $g.Dispose(); $img.Dispose()

        $bmp.Save($tmp, $codec, $encParams)
        $bmp.Dispose()

        Remove-Item -Path $src -Force
        Rename-Item -Path $tmp -NewName $file.Name

        Write-Host "  ✓" -ForegroundColor Green
        $ok++
    }
    catch {
        Write-Host "  ✗  $_" -ForegroundColor Red
        if (Test-Path $tmp) { Remove-Item $tmp -Force -ErrorAction SilentlyContinue }
        $fail++
    }
}

Write-Host ""
Write-Host "  Done — $ok cleaned, $fail failed." -ForegroundColor Cyan
Write-Host "  Originals saved to  images\originals\" -ForegroundColor DarkGray
Write-Host ""
Read-Host "Press Enter to close"
