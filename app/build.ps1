# Build a hand-rolled, dependency-free GhostLock root-manager APK.
# Requires: JDK 21 (javac/keytool/jar on PATH) + Android SDK (build-tools, platforms).
# No Gradle, no AndroidX, no aapt2 'compile' (we ship no resources).
$ErrorActionPreference = "Stop"
$here = Split-Path -Parent $MyInvocation.MyCommand.Path
Set-Location $here

function Fail($m) { Write-Host "ERROR: $m" -ForegroundColor Red; exit 1 }

$sdk = $env:ANDROID_SDK_ROOT
if (-not $sdk) { $sdk = $env:ANDROID_HOME }
if (-not $sdk) { $sdk = Join-Path $env:LOCALAPPDATA "Android\Sdk" }
if (-not (Test-Path $sdk)) { Fail "Android SDK not found (set ANDROID_SDK_ROOT)" }

# newest build-tools that actually has the 4 tools we need
$bt = Get-ChildItem (Join-Path $sdk "build-tools") -Directory |
      Where-Object { (Test-Path (Join-Path $_.FullName "aapt2.exe")) -and
                     (Test-Path (Join-Path $_.FullName "d8.bat")) -and
                     (Test-Path (Join-Path $_.FullName "zipalign.exe")) -and
                     (Test-Path (Join-Path $_.FullName "apksigner.bat")) } |
      Sort-Object { [version]($_.Name) } | Select-Object -Last 1
if (-not $bt) { Fail "no usable build-tools" }
$AAPT2     = Join-Path $bt.FullName "aapt2.exe"
$D8        = Join-Path $bt.FullName "d8.bat"
$ZIPALIGN  = Join-Path $bt.FullName "zipalign.exe"
$APKSIGNER = Join-Path $bt.FullName "apksigner.bat"

# newest platform android.jar
$plat = Get-ChildItem (Join-Path $sdk "platforms") -Directory |
        Where-Object { Test-Path (Join-Path $_.FullName "android.jar") } |
        Sort-Object Name | Select-Object -Last 1
if (-not $plat) { Fail "no platform android.jar" }
$ANDROID_JAR = Join-Path $plat.FullName "android.jar"

Write-Host "build-tools : $($bt.Name)"
Write-Host "platform    : $($plat.Name)"
Write-Host "aapt2       : $AAPT2"
Write-Host "android.jar : $ANDROID_JAR"

$minSdk = 26
$targetSdk = 27
$build  = Join-Path $here "build"
$outDir = Join-Path $here "out"
$appDir = Join-Path $here "app"
Remove-Item $build -Recurse -Force -ErrorAction SilentlyContinue
New-Item -ItemType Directory -Force $build, $outDir | Out-Null
$dexDir = Join-Path $build "dex"; New-Item -ItemType Directory -Force $dexDir | Out-Null
$clsDir = Join-Path $build "classes"; New-Item -ItemType Directory -Force $clsDir | Out-Null

# 1) keystore (debug)
$ks = Join-Path $here "debug.keystore"
if (-not (Test-Path $ks)) {
    & keytool -genkeypair -keystore $ks -storepass android -keypass android `
        -alias androiddebugkey -keyalg RSA -keysize 2048 -validity 10000 `
        -dname "CN=Android Debug,O=Android,C=US"
    if ($LASTEXITCODE -ne 0) { Fail "keytool failed" }
}

# 2) aapt2 link (manifest only, no resources)
$base = Join-Path $build "base.apk"
$assetsDir = Join-Path $appDir "assets"
$assetsArg = @()
if (Test-Path $assetsDir) { $assetsArg = @("-A", $assetsDir); Write-Host "assets       : $assetsDir" }
$resDir = Join-Path $appDir "res"
$resZip = $null
if (Test-Path $resDir) {
    $resZip = Join-Path $build "res.zip"
    & $AAPT2 compile --dir $resDir -o $resZip
    if ($LASTEXITCODE -ne 0) { Fail "aapt2 compile failed" }
    Write-Host "res          : $resDir -> $resZip"
}
$resLinkArg = @()
if ($resZip) { $resLinkArg = @($resZip) }
& $AAPT2 link -o $base `
    --manifest (Join-Path $appDir "AndroidManifest.xml") `
    -I $ANDROID_JAR `
    --min-sdk-version $minSdk --target-sdk-version $targetSdk `
    @resLinkArg @assetsArg
if ($LASTEXITCODE -ne 0) { Fail "aapt2 link failed" }

# 3) javac
$src = Get-ChildItem (Join-Path $appDir "java") -Recurse -Filter *.java | ForEach-Object { $_.FullName }
& javac -source 8 -target 8 -encoding UTF-8 -classpath $ANDROID_JAR -d $clsDir $src
if ($LASTEXITCODE -ne 0) { Fail "javac failed" }

# 4) d8 -> classes.dex
& $D8 --lib $ANDROID_JAR --min-api $minSdk --output $dexDir (Get-ChildItem $clsDir -Recurse -Filter *.class | ForEach-Object { $_.FullName })
if ($LASTEXITCODE -ne 0) { Fail "d8 failed" }
if (-not (Test-Path (Join-Path $dexDir "classes.dex"))) { Fail "d8 produced no classes.dex" }

# 5) inject classes.dex into base.apk
$dex = Join-Path $dexDir "classes.dex"
$withDex = Join-Path $build "withdex.apk"
$py = $null
foreach ($c in @("python","py")) { if (Get-Command $c -ErrorAction SilentlyContinue) { $py = $c; break } }
if ($py) {
    & $py (Join-Path $here "tools\inject_dex.py") $base $dex $withDex
    if ($LASTEXITCODE -ne 0) { Fail "python dex injection failed" }
} else {
    Copy-Item $base $withDex -Force
    & jar uf $withDex -C $dexDir classes.dex
    if ($LASTEXITCODE -ne 0) { Fail "jar dex injection failed" }
}

# 6) zipalign
$aligned = Join-Path $build "aligned.apk"
& $ZIPALIGN -f -p 4 $withDex $aligned
if ($LASTEXITCODE -ne 0) { Fail "zipalign failed" }

# 7) sign
$final = Join-Path $outDir "GhostLockManager.apk"
& $APKSIGNER sign --ks $ks --ks-pass pass:android --key-pass pass:android `
    --min-sdk-version $minSdk `
    --v1-signing-enabled false --v2-signing-enabled true --v3-signing-enabled true --v4-signing-enabled false `
    --out $final $aligned
if ($LASTEXITCODE -ne 0) { Fail "apksigner sign failed" }

& $APKSIGNER verify --print-certs $final
if ($LASTEXITCODE -ne 0) { Fail "apksigner verify failed" }

Write-Host ""
Write-Host "BUILT: $final" -ForegroundColor Green
Write-Host "package : com.ghostlock.manager"
Write-Host "activity: com.ghostlock.manager.MainActivity"
