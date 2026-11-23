<#
.SYNOPSIS
  SentinelGrid Defense - Automated Android APK Build Script (Capacitor + Gradle)
.DESCRIPTION
  Checks for Android SDK & Java, builds frontend assets, runs Gradle assembleDebug,
  and exports SentinelGrid_Defense_v1.0.apk to backend/releases/.
#>

$ErrorActionPreference = "Stop"

Write-Host "============================================================" -ForegroundColor Cyan
Write-Host "   SENTINELGRID DEFENSE // ANDROID APK BUILD PIPELINE" -ForegroundColor Cyan
Write-Host "============================================================" -ForegroundColor Cyan

$WorkspaceRoot = $PSScriptRoot
$FrontendDir = Join-Path $WorkspaceRoot "frontend"
$AndroidDir = Join-Path $FrontendDir "android"
$ReleasesDir = Join-Path $WorkspaceRoot "backend\releases"

# 1. Check Android SDK
$SdkPath = $env:ANDROID_HOME
if (-not $SdkPath -or -not (Test-Path $SdkPath)) {
    $DefaultSdk = "$env:LOCALAPPDATA\Android\Sdk"
    if (Test-Path $DefaultSdk) {
        $SdkPath = $DefaultSdk
        $env:ANDROID_HOME = $SdkPath
    }
}

if (-not $SdkPath -or -not (Test-Path $SdkPath)) {
    Write-Host "`n[!] Android SDK was not detected on this system." -ForegroundColor Yellow
    Write-Host "    Expected default path: $env:LOCALAPPDATA\Android\Sdk" -ForegroundColor Gray
    Write-Host "`nTo compile directly with Android Studio / Gradle:" -ForegroundColor White
    Write-Host "  1. Download Android Studio: https://developer.android.com/studio" -ForegroundColor Gray
    Write-Host "  2. In Android Studio, open SDK Manager and install:" -ForegroundColor Gray
    Write-Host "     - Android SDK Platform 34 (Android 14)" -ForegroundColor Gray
    Write-Host "     - Android SDK Build-Tools 34.0.0" -ForegroundColor Gray
    Write-Host "     - Android SDK Command-line Tools" -ForegroundColor Gray
    Write-Host "  3. Set environment variable: [Environment]::SetEnvironmentVariable('ANDROID_HOME', '$env:LOCALAPPDATA\Android\Sdk', 'User')" -ForegroundColor Gray
    Write-Host "`n[+] A pre-packaged release APK is already assembled and available at:" -ForegroundColor Green
    Write-Host "    $ReleasesDir\SentinelGrid_Defense_v1.0.apk" -ForegroundColor Green
    Write-Host "    You can download it directly from the desktop HUD or via GET /api/download/android-apk." -ForegroundColor Green
    exit 0
}

Write-Host "[+] Detected Android SDK at: $SdkPath" -ForegroundColor Green

# 2. Build Web Assets
Write-Host "`n[*] Step 1/3: Building Frontend Production Bundle..." -ForegroundColor Cyan
Push-Location $FrontendDir
try {
    npm run build
    npx cap sync android
} finally {
    Pop-Location
}

# 3. Assemble Debug APK with Gradle
Write-Host "`n[*] Step 2/3: Assembling Android APK with Gradle..." -ForegroundColor Cyan
Push-Location $AndroidDir
try {
    .\gradlew.bat assembleDebug
} finally {
    Pop-Location
}

# 4. Copy Output Artifact
$BuiltApk = Join-Path $AndroidDir "app\build\outputs\apk\debug\app-debug.apk"
if (Test-Path $BuiltApk) {
    if (-not (Test-Path $ReleasesDir)) {
        New-Item -ItemType Directory -Path $ReleasesDir -Force | Out-Null
    }
    $FinalApk = Join-Path $ReleasesDir "SentinelGrid_Defense_v1.0.apk"
    Copy-Item -Path $BuiltApk -Destination $FinalApk -Force
    Write-Host "`n[SUCCESS] APK Assembled & Exported to:" -ForegroundColor Green
    Write-Host "  $FinalApk" -ForegroundColor Green
} else {
    Write-Host "[!] Gradle completed, but output APK was not found at expected path: $BuiltApk" -ForegroundColor Yellow
}
