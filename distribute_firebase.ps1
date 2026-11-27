param(
    [Parameter(Mandatory=$true)]
    [string]$FirebaseAppId,
    [string]$Testers = "",
    [string]$Groups = "testers",
    [string]$ReleaseNotes = "SentinelGrid Defense Release APK - Samsung & Android 16 Verified"
)

$apkPath = Join-Path $PSScriptRoot "frontend\android\app\build\outputs\apk\release\app-release.apk"
if (-not (Test-Path $apkPath)) {
    Write-Error "Signed Release APK not found at: $apkPath"
    exit 1
}

$argsList = @(
    "firebase-tools",
    "appdistribution:distribute",
    $apkPath,
    "--app", $FirebaseAppId,
    "--release-notes", $ReleaseNotes
)

if ($Testers) {
    $argsList += @("--testers", $Testers)
} else {
    $argsList += @("--groups", $Groups)
}

Write-Host "Uploading signed Release APK to Firebase App Distribution..." -ForegroundColor Cyan
npx @argsList
