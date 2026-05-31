# Build de l'executable portable autonome NTDS HIBP Checker
# Auteur : Ayi NEDJIMI Consultants - https://ayinedjimi-consultants.fr
#
# Usage :  .\build.ps1
# Resultat : dist\NTDS-HIBP-Checker.exe  (exe unique, autonome)

$ErrorActionPreference = "Stop"
$root = $PSScriptRoot
$py = Join-Path $root ".venv\Scripts\python.exe"

if (-not (Test-Path $py)) {
    Write-Host "Creation de l'environnement virtuel..." -ForegroundColor Cyan
    py -m venv (Join-Path $root ".venv")
    $py = Join-Path $root ".venv\Scripts\python.exe"
    & $py -m pip install --upgrade pip
    & $py -m pip install -r (Join-Path $root "requirements.txt")
}

Write-Host "Compilation avec PyInstaller..." -ForegroundColor Cyan

$iconArg = @()
$icon = Join-Path $root "assets\app.ico"
if (Test-Path $icon) { $iconArg = @("--icon", $icon) }

# Splash natif (affiche immediatement par le bootloader, pendant l'extraction
# de l'exe onefile) : evite l'impression que l'appli ne se lance pas.
New-Item -ItemType Directory -Force (Join-Path $root "assets") | Out-Null
$splash = Join-Path $root "assets\splash.png"
& $py -c "from ntds_hibp_checker.gui import make_splash_png; make_splash_png(r'$splash')"
$splashArg = @()
if (Test-Path $splash) { $splashArg = @("--splash", $splash) }

# Exe TOTALEMENT autonome : on embarque explicitement chaque dependance
# (code, sous-modules ET fichiers de donnees), y compris la pile reseau/TLS
# (certifi cacert.pem indispensable au HTTPS HIBP).
& $py -m PyInstaller `
    --noconfirm `
    --onefile `
    --windowed `
    --name "NTDS-HIBP-Checker" `
    --collect-all customtkinter `
    --collect-all impacket `
    --collect-submodules impacket `
    --collect-all Cryptodome `
    --collect-all requests `
    --collect-all urllib3 `
    --collect-all certifi `
    --collect-all charset_normalizer `
    --collect-all idna `
    --collect-all windnd `
    --collect-all pyasn1 `
    --collect-all pyasn1_modules `
    --collect-all six `
    --collect-all ldap3 `
    --collect-all ldapdomaindump `
    --copy-metadata impacket `
    --hidden-import "Cryptodome" `
    @iconArg `
    @splashArg `
    (Join-Path $root "app.py")

Write-Host ""
Write-Host "Termine. Executable autonome : dist\NTDS-HIBP-Checker.exe" -ForegroundColor Green
