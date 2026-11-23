<#
  Entfernt verwaiste Treiber-Reste sicher in zwei Schritten (mit geschuetzter Sicherung).
  Welche Treiber, bestimmt -Satz:

    CreativeCorel (Standard): CtiIo64.sys (Creative), PxHlpa64.sys (Corel, Filter der CD/DVD-Klasse)
    Verwaist:  gdrv.sys, gdrv3.sys (GIGABYTE), TmHid.sys (Thrustmaster), inpoutx64.sys,
               nur noch Datei: Capsax64Drv.sys (Colasoft)
    Asus:      AsIO2.sys, AsIO3.sys, GLCKIO2.sys, IOMap64.sys (erst, wenn keine ASUS-Software mehr installiert ist)
               und die zurueckgebliebenen ASUS-Dienste asComSvc und AsusCertService (Programmordner bleibt)

  Ist bei einem Treiber kein Dienst mehr eingetragen, die Datei aber noch da, wird nur die Datei
  in die Sicherung verschoben.

  Ein Treiber wird uebersprungen, solange das zugehoerige Programm noch installiert ist oder
  ein laufendes Programm ihn geladen hat. Jeder Satz hat einen eigenen Sicherungsordner.

  Das Skript wird mit "k9 dienst aktualisieren" nach C:\Program Files\K9 kopiert
  (dort nur fuer Administratoren aenderbar). Aufruf in einer PowerShell ALS ADMINISTRATOR:

    Pruefen:  powershell -ExecutionPolicy Bypass -File "C:\Program Files\K9\treiber-aufraeumen.ps1" -Satz Verwaist -Phase Pruefen
              (nur lesen, aendert nichts; zeigt, was Phase 1 aendern wuerde)
    Phase 1:  powershell -ExecutionPolicy Bypass -File "C:\Program Files\K9\treiber-aufraeumen.ps1" -Satz Verwaist -Phase 1
    Phase 2:  powershell -ExecutionPolicy Bypass -File "C:\Program Files\K9\treiber-aufraeumen.ps1" -Satz Verwaist -Phase 2
    Zurueck:  powershell -ExecutionPolicy Bypass -File "C:\Program Files\K9\treiber-aufraeumen.ps1" -Satz Verwaist -Phase Wiederherstellen

  Es wird nichts geloescht: Dateien werden in den geschuetzten Sicherungsordner verschoben.
  Konsolentexte bewusst ohne Umlaute.
#>
param(
    [Parameter(Mandatory = $true)]
    [ValidateSet('Pruefen', '1', '2', 'Wiederherstellen')]
    [string]$Phase,
    [ValidateSet('CreativeCorel', 'Verwaist', 'Asus')]
    [string]$Satz = 'CreativeCorel'
)

$ErrorActionPreference = 'Stop'
$BackupRoot = Join-Path $env:ProgramData 'K9\treiberbackup'
# CreativeCorel keeps the original folder (a run may already be stored there).
$Backup = if ($Satz -eq 'CreativeCorel') { $BackupRoot } else { Join-Path $BackupRoot $Satz.ToLowerInvariant() }
$State = Join-Path $Backup 'zustand.json'
$Hashes = Join-Path $Backup 'pruefsummen.json'
$ClassRoot = 'HKLM:\SYSTEM\CurrentControlSet\Control\Class'
$EnumRoot = 'HKLM:\SYSTEM\CurrentControlSet\Enum'
$CdClassGuid = '{4D36E965-E325-11CE-BFC1-08002BE10318}'
$CdClassKey = "$ClassRoot\$CdClassGuid"
$CdClassReg = "HKLM\SYSTEM\CurrentControlSet\Control\Class\$CdClassGuid"
$ServicesKey = 'HKLM:\SYSTEM\CurrentControlSet\Services'
$DriversDir = Join-Path $env:SystemRoot 'System32\drivers'
$UninstallKeys = @(
    'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall',
    'HKLM:\SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall',
    'HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall'
)

# Files to clean up; service names and paths are read from the registry (ImagePath).
#   Dienst:   expected service name (other name = unexpected, stop)
#   Pfad:     the one allowed location outside System32\drivers (exact path)
#   NurDatei: no service any more, only the file is moved to the backup
#   NurDienst: a left-over program service: switched off and removed, its file stays
#   Signierer: required signer (valid Authenticode, name as regex) before a file without
#              service is moved; without it such a file is never moved
#   Programm: owning program (DisplayName/Publisher in the uninstall list); while installed: skip
#   Filter:   driver is a filter of the CD/DVD class (that entry is removed in phase 1)
$AsusPrograms = 'ASUS|AURA|ARMOURY|GLCKIO|ROG Live|^VGA$'
$Sets = @{
    'CreativeCorel' = @(
        @{ Datei = 'CtiIo64.sys';  Name = 'Creative CtiIo64'; Filter = $false },
        @{ Datei = 'PxHlpa64.sys'; Name = 'Corel PxHlpa64';   Filter = $true }
    )
    'Verwaist' = @(
        @{ Datei = 'gdrv.sys';        Name = 'GIGABYTE gdrv';      Dienst = 'gdrv';      Pfad = (Join-Path $env:SystemRoot 'gdrv.sys'); Programm = 'GIGABYTE|GIGA-BYTE' },
        @{ Datei = 'gdrv3.sys';       Name = 'GIGABYTE gdrv3';     Dienst = 'gdrv3';     Programm = 'GIGABYTE|GIGA-BYTE' },
        @{ Datei = 'TmHid.sys';       Name = 'Thrustmaster TmHid'; Dienst = 'TmHid';     Programm = 'Thrustmaster|WARTHOG|Guillemot' },
        @{ Datei = 'inpoutx64.sys';   Name = 'inpoutx64';          Dienst = 'inpoutx64'; Programm = 'inpout|Highresolution' },
        @{ Datei = 'Capsax64Drv.sys'; Name = 'Colasoft Capsa';     NurDatei = $true;     Programm = 'Colasoft'; Signierer = '^Colasoft Co\., Ltd$' }
    )
    'Asus' = @(
        @{ Datei = 'AsIO2.sys';   Name = 'ASUS AsIO2';   Dienst = 'Asusgio2'; Programm = $AsusPrograms },
        @{ Datei = 'AsIO3.sys';   Name = 'ASUS AsIO3';   Dienst = 'Asusgio3'; Programm = $AsusPrograms },
        @{ Datei = 'GLCKIO2.sys'; Name = 'ASUS GLCKIO2'; Dienst = 'GLCKIO2';  Programm = $AsusPrograms },
        @{ Datei = 'IOMap64.sys'; Name = 'ASUS IOMap64'; Dienst = 'IOMap';    Programm = $AsusPrograms; Signierer = '^ASUSTeK COMPUTER INC\.$' },
        @{ Datei = 'atkexComSvc.exe';     Name = 'ASUS-Dienst asComSvc (AXSP)'; Dienst = 'asComSvc';        NurDienst = $true; Programm = $AsusPrograms
           Pfad = (Join-Path ${env:ProgramFiles(x86)} 'ASUS\AXSP\4.02.12\atkexComSvc.exe') },
        @{ Datei = 'AsusCertService.exe'; Name = 'ASUS-Dienst AsusCertService';  Dienst = 'AsusCertService'; NurDienst = $true; Programm = $AsusPrograms
           Pfad = (Join-Path ${env:ProgramFiles(x86)} 'ASUS\AsusCertService\AsusCertService.exe') }
    )
}
$Targets = $Sets[$Satz]

function Say([string]$t) { Write-Host $t }
function Stop-With([string]$t) { Write-Host "ABBRUCH: $t" -ForegroundColor Red; exit 1 }

$SidSystem = 'S-1-5-18'
$SidAdmins = 'S-1-5-32-544'
$SidTrusted = 'S-1-5-80-956008885-3418522649-1831038044-1853292631-2271478464' # TrustedInstaller
$SidCreatorOwner = 'S-1-3-0'

$admin = ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
if (-not $admin -and $Phase -ne 'Pruefen') { Stop-With 'Bitte die PowerShell "Als Administrator ausfuehren" und den Befehl wiederholen.' }

# Runs reg.exe/sc.exe; native programs do not throw, so the exit code is checked.
function Invoke-Native([string]$exe, [string[]]$arguments, [string]$what) {
    & $exe @arguments | Out-Null
    if ($LASTEXITCODE -ne 0) { Stop-With "$what fehlgeschlagen ($exe, Exitcode $LASTEXITCODE)." }
}

# ------------------------------------------------------------ folder checks
# Real write bits only (FullControl/Modify also contain read bits). Inherit-only
# ACEs may carry raw generic values, so GENERIC_ALL/GENERIC_WRITE count as write.
$WriteMask = [int64](0x2 -bor 0x4 -bor 0x10 -bor 0x100 -bor 0x40 -bor 0x10000 -bor 0x40000 -bor 0x80000 -bor 0x10000000 -bor 0x40000000)
#           WriteData AppendData WriteEA WriteAttributes DeleteSubdirectoriesAndFiles Delete WriteDAC WriteOwner GENERIC_ALL GENERIC_WRITE

# Returns $null if only SYSTEM, Administrators and TrustedInstaller may write,
# otherwise the reason. CREATOR OWNER is ignored on purpose: it only grants rights
# to whoever creates a new object, and creating requires WriteData/AppendData,
# which is checked for every other principal - so only an administrator or
# SYSTEM can become such a creator.
function Test-ProtectedFolder([string]$path) {
    $acl = Get-Acl -Path $path
    $owner = (New-Object Security.Principal.NTAccount($acl.Owner)).Translate([Security.Principal.SecurityIdentifier]).Value
    if ($owner -notin @($SidSystem, $SidAdmins, $SidTrusted)) { return "Besitzer ist $($acl.Owner)" }
    foreach ($ace in $acl.Access) {
        if ($ace.AccessControlType -ne 'Allow') { continue }
        $sid = $ace.IdentityReference.Translate([Security.Principal.SecurityIdentifier]).Value
        if ($sid -in @($SidSystem, $SidAdmins, $SidTrusted, $SidCreatorOwner)) { continue }
        if (([int64]$ace.FileSystemRights -band $WriteMask) -ne 0) { return "Schreibrecht fuer $($ace.IdentityReference) ($($ace.FileSystemRights))" }
    }
    return $null
}

# For -Phase Pruefen: the folder state as text (without admin rights some folders are not readable).
function Get-FolderStatus([string]$path) {
    try { $problem = Test-ProtectedFolder $path } catch { return 'ohne Administratorrechte nicht pruefbar' }
    if ($problem) { return "NICHT geschuetzt ($problem)" }
    return 'geschuetzt'
}

function New-ProtectedFolder([string]$path) {
    if (Test-Path $path) {
        $problem = Test-ProtectedFolder $path
        if ($problem) { Stop-With "Sicherungsordner $path ist nicht geschuetzt ($problem). Bitte pruefen - moeglicherweise manipuliert." }
        return
    }
    $parent = Split-Path $path -Parent
    if (-not (Test-Path $parent)) { Stop-With "$parent fehlt - ist der K9-Dienst eingerichtet?" }
    $problem = Test-ProtectedFolder $parent
    if ($problem) { Stop-With "$parent ist nicht geschuetzt ($problem)." }
    New-Item -ItemType Directory -Path $path | Out-Null
    $acl = New-Object Security.AccessControl.DirectorySecurity
    $acl.SetAccessRuleProtection($true, $false)
    $inherit = [Security.AccessControl.InheritanceFlags]'ContainerInherit, ObjectInherit'
    foreach ($sid in $SidSystem, $SidAdmins) {
        $id = New-Object Security.Principal.SecurityIdentifier($sid)
        $acl.AddAccessRule((New-Object Security.AccessControl.FileSystemAccessRule($id, 'FullControl', $inherit, 'None', 'Allow')))
    }
    $acl.SetOwner((New-Object Security.Principal.SecurityIdentifier($SidAdmins)))
    Set-Acl -Path $path -AclObject $acl
    $problem = Test-ProtectedFolder $path
    if ($problem) { Stop-With "Sicherungsordner konnte nicht geschuetzt werden ($problem)." }
}

# The set's backup folder (and the common parent folder for the newer sets).
function New-BackupFolder {
    if ($Backup -ne $BackupRoot) { New-ProtectedFolder $BackupRoot }
    New-ProtectedFolder $Backup
}

function Get-FileHashHex([string]$path) { (Get-FileHash -Path $path -Algorithm SHA256).Hash.ToLowerInvariant() }

# ---------------------------------------------------------- driver lookups
# Full file path from a service ImagePath (\??\C:\..., \SystemRoot\..., System32\...).
function Resolve-ImagePath([string]$image) {
    $p = $image.Trim().Trim('"')
    if ($p.StartsWith('\??\')) { $p = $p.Substring(4) }
    elseif ($p -match '^\\SystemRoot\\') { $p = Join-Path $env:SystemRoot $p.Substring(12) }
    elseif ($p -match '^(System32|SysWOW64)\\') { $p = Join-Path $env:SystemRoot $p }
    return [IO.Path]::GetFullPath($p)
}

# Only System32\drivers or the one exact path named for this target.
function Test-AllowedPath($target, [string]$file) {
    if ((Split-Path $file -Parent) -ieq $DriversDir) { return $true }
    return ($target.Pfad -and ([IO.Path]::GetFullPath($target.Pfad) -ieq $file))
}

function Get-Target([string]$file) {
    $leaf = Split-Path $file -Leaf
    return ($Targets | Where-Object { $_.Datei -ieq $leaf } | Select-Object -First 1)
}

# Driver services whose image is one of the target files (names from the registry).
function Find-Services([string]$file) {
    $out = @()
    foreach ($k in Get-ChildItem $ServicesKey) {
        $p = Get-ItemProperty $k.PSPath
        if ($p.ImagePath -and ([string]$p.ImagePath).Trim().Trim('"').ToLowerInvariant().EndsWith('\' + $file.ToLowerInvariant())) {
            $out += [pscustomobject]@{ Dienst = $k.PSChildName; Start = $p.Start; Group = $p.Group; Image = [string]$p.ImagePath }
        }
    }
    return $out
}

# Installed programs (also hidden system components) matching the owner pattern.
function Find-Program([string]$pattern) {
    if (-not $pattern) { return @() }
    $out = @()
    foreach ($root in $UninstallKeys) {
        foreach ($k in Get-ChildItem $root -ErrorAction SilentlyContinue) {
            $p = Get-ItemProperty $k.PSPath -ErrorAction SilentlyContinue
            if (-not $p.DisplayName) { continue }
            if ($p.DisplayName -match $pattern -or ($p.Publisher -and $p.Publisher -match $pattern)) { $out += [string]$p.DisplayName }
        }
    }
    return @($out | Select-Object -Unique)
}

# Signer name of a validly signed file, else $null.
function Get-SignerName([string]$file) {
    $sig = Get-AuthenticodeSignature -FilePath $file
    if ($sig.Status -ne 'Valid' -or -not $sig.SignerCertificate) { return $null }
    return $sig.SignerCertificate.GetNameInfo([Security.Cryptography.X509Certificates.X509NameType]::SimpleName, $false)
}

# A file without service may only be moved if no service names it (a driver can only be
# loaded through a service entry; after the reboot before phase 2 nothing else holds it)
# and it carries the expected signature. Returns $null or the reason.
function Test-FileOnly($target, [string]$file) {
    $svcs = @(Find-Services (Split-Path $file -Leaf))
    if ($svcs.Count -gt 0) { return "bei Dienst $(($svcs | ForEach-Object Dienst) -join ', ') eingetragen" }
    if (-not $target.Signierer) { return 'kein erwarteter Herausgeber hinterlegt' }
    $signer = Get-SignerName $file
    if (-not $signer) { return 'keine gueltige digitale Signatur' }
    if ($signer -notmatch $target.Signierer) { return "signiert von $signer statt des erwarteten Herausgebers" }
    return $null
}

function Get-DriverState([string]$service) {
    $drv = @(Get-CimInstance Win32_SystemDriver -Filter "Name='$service'" -ErrorAction SilentlyContinue)
    if ($drv.Count -eq 0) { $drv = @(Get-CimInstance Win32_Service -Filter "Name='$service'" -ErrorAction SilentlyContinue) }
    if ($drv.Count -eq 0) { return 'unbekannt' }
    return [string]$drv[0].State
}

$script:Unreadable = @()

# All references to a service name: filters of device classes and device
# instances (Enum), dependencies of other services. Unreadable keys are listed.
function Find-References([string]$service, [string]$group) {
    $refs = @()
    if ($group) {
        # A group dependency only matters if this driver is the only member of the group.
        $members = @(Get-ChildItem $ServicesKey | Where-Object { (Get-ItemProperty $_.PSPath).Group -eq $group })
        if ($members.Count -gt 1) { $group = $null }
    }
    foreach ($cls in Get-ChildItem $ClassRoot) {
        $p = Get-ItemProperty $cls.PSPath
        foreach ($v in 'UpperFilters', 'LowerFilters') {
            if (@($p.$v) -contains $service) { $refs += "Klasse $($cls.PSChildName) $v" }
        }
    }
    foreach ($k in Get-ChildItem $ServicesKey) {
        $p = Get-ItemProperty $k.PSPath
        if (@($p.DependOnService) -contains $service) { $refs += "Dienst $($k.PSChildName) haengt ab von $service" }
        if ($group -and (@($p.DependOnGroup) -contains $group)) { $refs += "Dienst $($k.PSChildName) haengt ab von Gruppe $group" }
        foreach ($v in 'UpperFilters', 'LowerFilters') {
            if (@($p.$v) -contains $service) { $refs += "Dienst $($k.PSChildName) $v" }
        }
    }
    # Device instances: HKLM\...\Enum\<Bus>\<Device>\<Instance>
    foreach ($bus in Get-ChildItem $EnumRoot -ErrorAction SilentlyContinue) {
        try { $devices = @(Get-ChildItem $bus.PSPath -ErrorAction Stop) } catch { $script:Unreadable += $bus.Name; continue }
        foreach ($dev in $devices) {
            try { $instances = @(Get-ChildItem $dev.PSPath -ErrorAction Stop) } catch { $script:Unreadable += $dev.Name; continue }
            foreach ($inst in $instances) {
                try { $p = Get-ItemProperty $inst.PSPath -ErrorAction Stop } catch { $script:Unreadable += $inst.Name; continue }
                foreach ($v in 'UpperFilters', 'LowerFilters') {
                    if (@($p.$v) -contains $service) { $refs += "Geraet $($inst.Name -replace '^HKEY_LOCAL_MACHINE\\SYSTEM\\CurrentControlSet\\Enum\\','') $v" }
                }
                if ([string]$p.Service -eq $service) { $refs += "Geraet $($inst.Name -replace '^HKEY_LOCAL_MACHINE\\SYSTEM\\CurrentControlSet\\Enum\\','') nutzt $service als Funktionstreiber" }
            }
        }
    }
    return $refs
}

# Checks shared by -Phase Pruefen and -Phase 1. Returns the drivers to change.
function Get-Plan {
    $found = @()
    foreach ($t in $Targets) {
        Say "- $($t.Name) ($($t.Datei))"
        $svcs = @(Find-Services $t.Datei)
        $programs = @(Find-Program $t.Programm)
        if ($t.Programm) { Say "    Programm noch installiert: $(if ($programs) { $programs -join '; ' } else { 'nein' })" }

        # A driver whose service is already gone: only the file is left (not for program services).
        if ($t.NurDatei -or ($svcs.Count -eq 0 -and -not $t.NurDienst -and $Satz -ne 'CreativeCorel')) {
            if ($svcs.Count -gt 0) { Stop-With "$($t.Datei) ist bei Dienst $(($svcs | ForEach-Object Dienst) -join ', ') eingetragen - unerwartet fuer einen reinen Datei-Rest. Nichts geaendert." }
            $file = if ($t.Pfad) { [IO.Path]::GetFullPath($t.Pfad) } else { Join-Path $DriversDir $t.Datei }
            $exists = Test-Path $file
            Say "    Dienst: keiner | Datei $file vorhanden: $(if ($exists) { 'ja' } else { 'nein' })"
            if (-not $exists) { Say '    -> nichts zu tun.'; continue }
            if ($programs) { Say '    -> UEBERSPRUNGEN: zugehoeriges Programm ist noch installiert (zuerst deinstallieren).'; continue }
            $why = Test-FileOnly $t $file
            if ($why) { Say "    -> UEBERSPRUNGEN: $why."; continue }
            Say "    Signatur: $(Get-SignerName $file) (gueltig)"
            Say '    -> wird beruecksichtigt (nur Datei in die Sicherung verschieben).'
            $found += [pscustomobject]@{ Dienst = $null; Datei = $file; Name = $t.Name; Filter = $false; Start = $null; NurDatei = $true; NurDienst = $false }
            continue
        }

        if ($svcs.Count -eq 0) { Say '    Dienst: nicht eingetragen -> wird uebersprungen.'; continue }
        if ($svcs.Count -gt 1) { Stop-With "$($t.Datei) ist bei mehreren Diensten eingetragen ($(($svcs | ForEach-Object Dienst) -join ', ')) - unerwartet." }
        $svc = $svcs[0]
        if ($t.Dienst -and $svc.Dienst -ne $t.Dienst) { Stop-With "$($t.Datei) gehoert zu Dienst $($svc.Dienst) statt $($t.Dienst) - unerwartet, nichts geaendert." }
        $file = Resolve-ImagePath $svc.Image
        if (-not (Test-AllowedPath $t $file)) { Stop-With "$($svc.Dienst): Datei $file liegt nicht in $DriversDir - unerwartet, nichts geaendert." }
        $exists = Test-Path $file
        $state = Get-DriverState $svc.Dienst
        Say "    Dienst $($svc.Dienst) | Start $($svc.Start) | geladen: $state | Datei $file vorhanden: $(if ($exists) { 'ja' } else { 'nein' })"
        $refs = @(Find-References $svc.Dienst $svc.Group)
        Say "    Verweise: $(if ($refs) { $refs -join '; ' } else { 'keine' })"
        if ($programs) { Say '    -> UEBERSPRUNGEN: zugehoeriges Programm ist noch installiert (zuerst deinstallieren).'; continue }
        # Demand-start drivers are only running when a program loaded them.
        if ($state -eq 'Running' -and [int]$svc.Start -ge 3) { Say '    -> UEBERSPRUNGEN: ein laufendes Programm hat den Treiber geladen (wird noch verwendet).'; continue }
        $expected = if ($t.Filter) { @("Klasse $CdClassGuid LowerFilters") } else { @() }
        $unexpected = @($refs | Where-Object { $_ -notin $expected })
        if ($unexpected.Count -gt 0) { Stop-With "$($svc.Dienst) wird noch verwendet: $($unexpected -join '; '). Nichts geaendert." }
        Say '    -> wird beruecksichtigt.'
        $found += [pscustomobject]@{ Dienst = $svc.Dienst; Datei = $file; Name = $t.Name; Filter = [bool]$t.Filter; Start = $svc.Start; NurDatei = $false; NurDienst = [bool]$t.NurDienst }
    }
    if ($script:Unreadable.Count -gt 0) {
        $list = ($script:Unreadable | Select-Object -Unique)
        Say "Nicht lesbare Registry-Schluessel unter Enum ($($list.Count)): $(($list | Select-Object -First 10) -join '; ')$(if ($list.Count -gt 10) { ' ...' })"
        if ($admin) { Stop-With 'Als Administrator muessen alle Geraete-Schluessel lesbar sein - Pruefung unvollstaendig, nichts geaendert.' }
        Say '  (ohne Administratorrechte normal; Phase 1 prueft sie erneut als Administrator)'
    }
    return $found
}

function Get-RecentRestorePoint {
    try { $points = @(Get-ComputerRestorePoint -ErrorAction Stop) } catch { return 'unbekannt' }
    $recent = @($points | Where-Object { ([Management.ManagementDateTimeConverter]::ToDateTime($_.CreationTime)) -gt (Get-Date).AddHours(-24) })
    if ($recent.Count -gt 0) { return $recent[-1].Description }
    return $null
}

function Remove-FilterEntry([string]$valueName, [string]$entry) {
    $vals = (Get-ItemProperty -Path $CdClassKey -Name $valueName -ErrorAction SilentlyContinue).$valueName
    if ($null -eq $vals) { return $false }
    $vals = @($vals)
    if (-not ($vals -contains $entry)) { return $false }
    $rest = @($vals | Where-Object { $_ -ne $entry })
    if ($rest.Count -eq 0) {
        Remove-ItemProperty -Path $CdClassKey -Name $valueName
        Say "  $valueName enthielt nur $entry -> Wert entfernt."
    } else {
        Set-ItemProperty -Path $CdClassKey -Name $valueName -Value ([string[]]$rest) -Type MultiString
        Say "  $entry aus $valueName entfernt, verbleibend: $($rest -join ', ')"
    }
    return $true
}

$CmdBase = "powershell -ExecutionPolicy Bypass -File `"C:\Program Files\K9\treiber-aufraeumen.ps1`" -Satz $Satz -Phase"

# ------------------------------------------------------------- read only
if ($Phase -eq 'Pruefen') {
    Say "=== Pruefen, Satz $Satz (nur lesen, aendert nichts) ==="
    Say "Administratorrechte: $(if ($admin) { 'ja' } else { 'nein (einige Pruefungen eingeschraenkt)' })"
    $found = @(Get-Plan)
    $parent = Split-Path $BackupRoot -Parent
    if (Test-Path $parent) {
        Say "Ordner ${parent}: $(Get-FolderStatus $parent)"
    } else { Say "Ordner $parent fehlt (K9-Dienst nicht eingerichtet?)" }
    if (Test-Path $Backup) {
        Say "Sicherungsordner ${Backup}: $(Get-FolderStatus $Backup)"
        $known = $false
        try { $known = Test-Path $State -ErrorAction Stop } catch { Say '  (Zustand ohne Administratorrechte nicht lesbar)' }
        if ($known) { Say "Achtung: Es gibt bereits einen Zustand fuer diesen Satz: Phase $((Get-Content $State -Raw | ConvertFrom-Json).phase)" }
    } else { Say "Sicherungsordner $Backup wird in Phase 1 geschuetzt angelegt." }
    $rp = Get-RecentRestorePoint
    if ($rp -eq 'unbekannt') { Say 'Wiederherstellungspunkt: ohne Administratorrechte nicht pruefbar.' }
    elseif ($rp) { Say "Wiederherstellungspunkt der letzten 24 Stunden: $rp" }
    else { Say 'Wiederherstellungspunkt: keiner aus den letzten 24 Stunden - Phase 1 legt einen an (bricht ab, wenn der Computerschutz aus ist).' }
    $cd = @((Get-ItemProperty $CdClassKey).LowerFilters)
    Say ''
    if ($found.Count -eq 0) { Say 'Phase 1 wuerde nichts aendern (kein Treiber dieses Satzes ist bereit).'; exit 0 }
    Say 'Phase 1 wuerde aendern:'
    foreach ($f in $found) {
        if ($f.Filter) {
            $rest = @($cd | Where-Object { $_ -ne $f.Dienst })
            Say "  - CD/DVD-Klasse LowerFilters: $($cd -join ', ') -> $(if ($rest.Count) { $rest -join ', ' } else { '(Wert wird entfernt)' })"
        }
        if ($f.NurDatei) { Say "  - Datei $($f.Datei): nur Pruefsumme sichern (verschoben wird in Phase 2)" }
        else { Say "  - Dienst $($f.Dienst): Start $($f.Start) -> 4 (deaktiviert)$(if ($f.NurDienst) { '; Programmdatei bleibt liegen' })" }
    }
    Say "  - Sicherung (reg export + SHA-256) nach $Backup"
    Say 'Phase 2 wuerde nach einem Neustart die Dienste austragen und die Dateien in die Sicherung verschieben.'
    exit 0
}

# ----------------------------------------------------------------- phase 1
if ($Phase -eq '1') {
    Say "=== Phase 1, Satz ${Satz}: Pruefung, Sicherung und Deaktivierung ==="
    New-BackupFolder
    if (Test-Path $State) {
        $s = Get-Content $State -Raw | ConvertFrom-Json
        Stop-With "Phase $($s.phase) wurde fuer diesen Satz bereits am $($s.zeit) ausgefuehrt. Weiter mit Phase 2 (nach Neustart) oder -Phase Wiederherstellen."
    }
    $found = @(Get-Plan)
    if ($found.Count -eq 0) { Stop-With 'Kein Treiber dieses Satzes ist bereit - nichts zu tun.' }

    # Restore point (last 24 h, else create one; without system protection: stop).
    $rp = Get-RecentRestorePoint
    if ($rp -and $rp -ne 'unbekannt') {
        Say "Wiederherstellungspunkt vorhanden: $rp"
    } else {
        Say 'Lege Wiederherstellungspunkt an ...'
        try {
            Checkpoint-Computer -Description 'Vor Treiber-Aufraeumen (K9)' -RestorePointType MODIFY_SETTINGS -ErrorAction Stop
        } catch {
            Stop-With "Wiederherstellungspunkt konnte nicht angelegt werden ($($_.Exception.Message)). Ist der Computerschutz fuer C: ausgeschaltet? Einschalten unter Systemsteuerung > System > Computerschutz, dann erneut starten."
        }
        $recent = @(Get-ComputerRestorePoint | Where-Object { ([Management.ManagementDateTimeConverter]::ToDateTime($_.CreationTime)) -gt (Get-Date).AddMinutes(-30) })
        if ($recent.Count -eq 0) { Stop-With 'Kein Wiederherstellungspunkt nachweisbar (Computerschutz aus oder nur einer pro 24 Stunden erlaubt). Bitte von Hand anlegen und erneut starten.' }
        Say 'Wiederherstellungspunkt angelegt.'
    }

    # Registry backup + checksums (also of the driver files).
    $sums = [ordered]@{}
    if (@($found | Where-Object Filter).Count -gt 0) {
        $cls = Join-Path $Backup 'cdrom-klasse.reg'
        Invoke-Native 'reg.exe' @('export', $CdClassReg, $cls, '/y') 'Sicherung der CD/DVD-Klasse'
        $sums['cdrom-klasse.reg'] = Get-FileHashHex $cls
    }
    foreach ($f in $found) {
        if (-not $f.NurDatei) {
            $reg = Join-Path $Backup ($f.Dienst + '.reg')
            Invoke-Native 'reg.exe' @('export', ("HKLM\SYSTEM\CurrentControlSet\Services\" + $f.Dienst), $reg, '/y') "Sicherung des Dienstes $($f.Dienst)"
            $sums[$f.Dienst + '.reg'] = Get-FileHashHex $reg
        }
        if (-not $f.NurDienst -and (Test-Path $f.Datei)) { $sums[(Split-Path $f.Datei -Leaf)] = Get-FileHashHex $f.Datei }
    }
    $sums | ConvertTo-Json | Set-Content $Hashes -Encoding UTF8

    # Corel filter out of the CD/DVD class (exactly this entry), then switch off.
    foreach ($f in $found | Where-Object Filter) {
        $lower = Remove-FilterEntry 'LowerFilters' $f.Dienst
        $upper = Remove-FilterEntry 'UpperFilters' $f.Dienst
        if (-not ($lower -or $upper)) { Say "$($f.Dienst) stand in keiner Filterliste der CD/DVD-Klasse." }
    }
    foreach ($f in $found | Where-Object { -not $_.NurDatei }) {
        Set-ItemProperty -Path (Join-Path $ServicesKey $f.Dienst) -Name Start -Value 4 -Type DWord
        Say "Deaktiviert: $($f.Dienst) (wirkt nach dem Neustart)"
    }
    @{ phase = 1; zeit = (Get-Date).ToString('o'); satz = $Satz; dienste = @($found | ForEach-Object { @{ dienst = $_.Dienst; datei = $_.Datei; nurdatei = [bool]$_.NurDatei; nurdienst = [bool]$_.NurDienst } }) } |
        ConvertTo-Json -Depth 4 | Set-Content $State -Encoding UTF8
    Say ''
    Say "Sicherung (geschuetzt): $Backup"
    Say 'Nach dem Neustart laden diese Treiber nicht mehr.'
    Say 'Bitte jetzt "Neu starten" waehlen (nicht "Herunterfahren": mit Schnellstart bleiben die Treiber sonst geladen).'
    Say "Danach: $CmdBase 2"
    Say "Bei Problemen: $CmdBase Wiederherstellen"
    exit 0
}

# ----------------------------------------------------------------- phase 2
if ($Phase -eq '2') {
    Say "=== Phase 2, Satz ${Satz}: Pruefen und endgueltig austragen ==="
    if (-not (Test-Path $State)) { Stop-With 'Phase 1 wurde fuer diesen Satz noch nicht ausgefuehrt.' }
    New-BackupFolder
    $s = Get-Content $State -Raw | ConvertFrom-Json
    if ($s.phase -ne 1) { Stop-With "Phase $($s.phase) ist der letzte Stand - Phase 2 ist nicht (mehr) moeglich." }
    $boot = (Get-CimInstance Win32_OperatingSystem).LastBootUpTime
    if ($boot -le [datetime]::Parse($s.zeit)) { Stop-With 'Seit Phase 1 wurde nicht neu gestartet (Herunterfahren mit Schnellstart zaehlt nicht). Bitte "Neu starten" waehlen.' }
    $ok = $true
    foreach ($d in $s.dienste) {
        if ($d.nurdatei) {
            # Same file as in phase 1 (checksum), still without service and with the expected signature.
            $leaf = Split-Path $d.datei -Leaf
            $t = Get-Target $d.datei
            if (-not $t -or -not (Test-AllowedPath $t ([IO.Path]::GetFullPath($d.datei)))) { Say "FEHLER: unerwarteter Pfad $($d.datei)."; $ok = $false; continue }
            if (-not (Test-Path $d.datei)) { Say "Datei-Rest ${leaf}: nicht mehr vorhanden."; continue }
            $sums1 = Get-Content $Hashes -Raw | ConvertFrom-Json
            if ((Get-FileHashHex $d.datei) -ne $sums1.$leaf) { Say "FEHLER: $leaf wurde seit Phase 1 veraendert."; $ok = $false; continue }
            $why = Test-FileOnly $t $d.datei
            if ($why) { Say "FEHLER: ${leaf}: $why."; $ok = $false; continue }
            Say "Datei-Rest ${leaf}: kein Dienst, Pruefsumme und Signatur stimmen."
            continue
        }
        $class = if ($d.nurdienst) { 'Win32_Service' } else { 'Win32_SystemDriver' }
        $drv = @(Get-CimInstance $class -Filter "Name='$($d.dienst)'")
        if ($drv.Count -eq 0) { Say "FEHLER: Treiberdienst $($d.dienst) nicht gefunden - unerwartet nach Phase 1."; $ok = $false }
        elseif ($drv[0].State -ne 'Stopped') { Say "FEHLER: Treiber $($d.dienst) ist noch aktiv ($($drv[0].State))."; $ok = $false }
        else { Say "Treiber $($d.dienst): nicht geladen (Start $($drv[0].StartMode))." }
    }
    if ($Satz -eq 'CreativeCorel') {
        $cd = @(Get-PnpDevice -Class CDROM -PresentOnly -ErrorAction SilentlyContinue)
        if ($cd.Count -eq 0) { Say 'CD/DVD: kein Laufwerk angeschlossen (nichts zu pruefen).' }
        foreach ($c in $cd) {
            if ($c.Status -ne 'OK') { Say "FEHLER: CD/DVD-Laufwerk $($c.FriendlyName) meldet $($c.Status)."; $ok = $false } else { Say "CD/DVD OK: $($c.FriendlyName)" }
        }
    }
    $audio = @(Get-PnpDevice -Class AudioEndpoint -PresentOnly -ErrorAction SilentlyContinue | Where-Object { $_.Status -eq 'OK' })
    if ($audio.Count -eq 0) { Say 'FEHLER: kein funktionierendes Audiogeraet gefunden.'; $ok = $false } else { Say "Ton OK: $($audio.Count) Audio-Endpunkte bereit" }
    $bad = @(Get-PnpDevice -PresentOnly -ErrorAction SilentlyContinue | Where-Object { $_.Status -eq 'Error' })
    if ($bad.Count -gt 0) { Say "Hinweis: Geraete mit Fehler: $(($bad | Select-Object -First 5 | ForEach-Object FriendlyName) -join '; ')" }
    $answer = Read-Host 'Funktioniert alles wie gewohnt (Ton, Maus/Tastatur, Spiele-Controller, Netzwerk)? (j/n)'
    if ($answer -notmatch '^(j|ja|y)$') { $ok = $false }
    if (-not $ok) { Stop-With "Pruefung nicht bestanden - nichts entfernt. Zurueck mit: $CmdBase Wiederherstellen" }
    foreach ($d in $s.dienste) {
        if (-not $d.nurdatei) {
            Invoke-Native 'sc.exe' @('delete', $d.dienst) "Austragen des Dienstes $($d.dienst)"
            Say "Dienst $($d.dienst) ausgetragen."
        }
        if (-not $d.nurdienst -and (Test-Path $d.datei)) {
            Move-Item -Path $d.datei -Destination (Join-Path $Backup (Split-Path $d.datei -Leaf)) -Force
            Say "Datei $(Split-Path $d.datei -Leaf) in die Sicherung verschoben."
        }
    }
    @{ phase = 2; zeit = (Get-Date).ToString('o'); satz = $Satz; dienste = $s.dienste } | ConvertTo-Json -Depth 4 | Set-Content $State -Encoding UTF8
    Say ''
    Say 'Fertig. Die Treiber-Reste sind entfernt (Dateien liegen weiterhin in der Sicherung).'
    Say 'Pruefen: & "C:\Program Files\K9\k9.exe" treiber'
    exit 0
}

# ---------------------------------------------------------- restore backup
if ($Phase -eq 'Wiederherstellen') {
    Say "=== Wiederherstellen aus der Sicherung, Satz $Satz ==="
    if (-not (Test-Path $Backup)) { Stop-With "Keine Sicherung gefunden ($Backup)." }
    New-BackupFolder
    if (-not (Test-Path $Hashes) -or -not (Test-Path $State)) { Stop-With 'Pruefsummen oder Zustand fehlen - Sicherung wird nicht verwendet.' }
    $sums = Get-Content $Hashes -Raw | ConvertFrom-Json
    $s = Get-Content $State -Raw | ConvertFrom-Json
    # Everything is checked first; nothing is changed if one file does not match.
    $plan = @()
    foreach ($name in $sums.PSObject.Properties.Name) {
        $f = Join-Path $Backup $name
        $isSys = $name.ToLowerInvariant().EndsWith('.sys')
        if (-not (Test-Path $f)) {
            if ($isSys) { continue } # still in place (phase 2 not done)
            Stop-With "Sicherungsdatei $name fehlt."
        }
        if ((Get-FileHashHex $f) -ne $sums.$name) { Stop-With "Pruefsumme von $name stimmt nicht - Sicherung wurde veraendert. Nichts wiederhergestellt." }
        $plan += $f
    }
    foreach ($d in $s.dienste) {
        $target = [IO.Path]::GetFullPath($d.datei)
        # Only back to the original place of a known target (System32\drivers or its exact path).
        $t = Get-Target $target
        if (-not $t -or -not (Test-AllowedPath $t $target)) { Stop-With "Unerwarteter Zielpfad $target." }
        $saved = Join-Path $Backup (Split-Path $target -Leaf)
        if (-not $d.nurdienst -and (Test-Path $saved) -and -not (Test-Path $target)) {
            # Only a file whose checksum was recorded in phase 1 goes back.
            if ($plan -notcontains $saved) { Stop-With "Fuer $(Split-Path $saved -Leaf) gibt es keine Pruefsumme - nicht zurueckgelegt." }
            Move-Item -Path $saved -Destination $target
            Say "Datei $(Split-Path $target -Leaf) zurueckgelegt."
        }
        if ($d.nurdatei) { continue }
        $reg = Join-Path $Backup ($d.dienst + '.reg')
        if ($plan -contains $reg) {
            Invoke-Native 'reg.exe' @('import', $reg) "Wiederherstellen des Dienstes $($d.dienst)"
            Say "Dienst $($d.dienst) wieder eingetragen."
        }
    }
    $cls = Join-Path $Backup 'cdrom-klasse.reg'
    if ($plan -contains $cls) {
        Invoke-Native 'reg.exe' @('import', $cls) 'Wiederherstellen der CD/DVD-Klasse'
        Say 'Filtereintraege der CD/DVD-Klasse wiederhergestellt.'
    }
    Remove-Item $State
    Say 'Bitte jetzt "Neu starten" waehlen. Danach ist alles wie vor Phase 1.'
    exit 0
}
