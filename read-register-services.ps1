# Ruta del archivo de log
$logFilePath = "C:\RegeditLogFile.txt"

# Check if the script is running with admin rights
if (-not ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole] "Administrator")) {
    Write-Warning "This script requires administrative privileges to run properly."
    $scriptPath = $MyInvocation.MyCommand.Path
    Start-Process powershell.exe -ArgumentList "-File `"$scriptPath`"" -Verb RunAs
    Exit
}

# Check if the log file exists, create it if it doesn't
if (-not (Test-Path $logFilePath)) {
    New-Item -Path $logFilePath -ItemType File | Out-Null
}

# Función para mostrar el valor del registro y registrar la salida
function Show-RegistryValue {
    param (
        [string]$keyPath,
        [string]$valueName,
        [string]$logFilePath
    )

    try {
        if (Test-Path $keyPath) {
            $value = Get-ItemProperty -Path $keyPath -Name $valueName -ErrorAction Stop
            if ($null -ne $value) {
                $output = "Service: $keyPath, $valueName $($value.$valueName)"
            } else {
                $output = "Service: $keyPath, $valueName Not found"
            }
        } else {
            $output = "Service: $keyPath, Path: Not found"
        }
    } catch {
        $output = "Error accessing $keyPath $_"
    }

    Write-Host $output
    Add-Content -Path $logFilePath -Value $output
}

# Lista de servicios y sus valores de registro
$services = @(
    @{Name = "BITS"; KeyPath = "HKLM:\SYSTEM\CurrentControlSet\Services\BITS"},
    @{Name = "BTAGService"; KeyPath = "HKLM:\SYSTEM\CurrentControlSet\Services\BTAGService"},
    @{Name = "bthserv"; KeyPath = "HKLM:\SYSTEM\CurrentControlSet\Services\bthserv"},
    @{Name = "lfsvc"; KeyPath = "HKLM:\SYSTEM\CurrentControlSet\Services\lfsvc"},
    @{Name = "DiagTrack"; KeyPath = "HKLM:\SYSTEM\CurrentControlSet\Services\DiagTrack"},
    @{Name = "HvHost"; KeyPath = "HKLM:\SYSTEM\CurrentControlSet\Services\HvHost"},
    @{Name = "vmickvpexchange"; KeyPath = "HKLM:\SYSTEM\CurrentControlSet\Services\vmickvpexchange"},
    @{Name = "vmicguestinterface"; KeyPath = "HKLM:\SYSTEM\CurrentControlSet\Services\vmicguestinterface"},
    @{Name = "vmicshutdown"; KeyPath = "HKLM:\SYSTEM\CurrentControlSet\Services\vmicshutdown"},
    @{Name = "vmicheartbeat"; KeyPath = "HKLM:\SYSTEM\CurrentControlSet\Services\vmicheartbeat"},
    @{Name = "vmicvmsession"; KeyPath = "HKLM:\SYSTEM\CurrentControlSet\Services\vmicvmsession"},
    @{Name = "vmicrdv"; KeyPath = "HKLM:\SYSTEM\CurrentControlSet\Services\vmicrdv"},
    @{Name = "vmictimesync"; KeyPath = "HKLM:\SYSTEM\CurrentControlSet\Services\vmictimesync"},
    @{Name = "vmicvss"; KeyPath = "HKLM:\SYSTEM\CurrentControlSet\Services\vmicvss"},
    @{Name = "PhoneSvc"; KeyPath = "HKLM:\SYSTEM\CurrentControlSet\Services\PhoneSvc"},
    @{Name = "Spooler"; KeyPath = "HKLM:\SYSTEM\CurrentControlSet\Services\Spooler"},
    @{Name = "QWAVE"; KeyPath = "HKLM:\SYSTEM\CurrentControlSet\Services\QWAVE"},
    @{Name = "SysMain"; KeyPath = "HKLM:\SYSTEM\CurrentControlSet\Services\SysMain"},
    @{Name = "WSearch"; KeyPath = "HKLM:\SYSTEM\CurrentControlSet\Services\WSearch"},
    @{Name = "UserDataSvc"; KeyPath = "HKLM:\SYSTEM\CurrentControlSet\Services\UserDataSvc"},
    @{Name = "UnistoreSvc"; KeyPath = "HKLM:\SYSTEM\CurrentControlSet\Services\UnistoreSvc"},
    @{Name = "UdkUserSvc"; KeyPath = "HKLM:\SYSTEM\CurrentControlSet\Services\UdkUserSvc"},
    @{Name = "PimIndexMaintenanceSvc"; KeyPath = "HKLM:\SYSTEM\CurrentControlSet\Services\PimIndexMaintenanceSvc"},
    @{Name = "DevicesFlowUserSvc"; KeyPath = "HKLM:\SYSTEM\CurrentControlSet\Services\DevicesFlowUserSvc"},
    @{Name = "PrintWorkflowUserSvc"; KeyPath = "HKLM:\SYSTEM\CurrentControlSet\Services\PrintWorkflowUserSvc"},
    @{Name = "PenService"; KeyPath = "HKLM:\SYSTEM\CurrentControlSet\Services\PenService"},
    @{Name = "P9RdrService"; KeyPath = "HKLM:\SYSTEM\CurrentControlSet\Services\P9RdrService"},
    @{Name = "MessagingService"; KeyPath = "HKLM:\SYSTEM\CurrentControlSet\Services\MessagingService"},
    @{Name = "BluetoothUserService"; KeyPath = "HKLM:\SYSTEM\CurrentControlSet\Services\BluetoothUserService"},
    @{Name = "webthreatdefusersvc"; KeyPath = "HKLM:\SYSTEM\CurrentControlSet\Services\webthreatdefusersvc"},
    @{Name = "NPSMSvc"; KeyPath = "HKLM:\SYSTEM\CurrentControlSet\Services\NPSMSvc"},
    @{Name = "OneSyncSvc"; KeyPath = "HKLM:\SYSTEM\CurrentControlSet\Services\OneSyncSvc"},
    @{Name = "WpnUserService"; KeyPath = "HKLM:\SYSTEM\CurrentControlSet\Services\WpnUserService"},
    @{Name = "CDPUserSvc"; KeyPath = "HKLM:\SYSTEM\CurrentControlSet\Services\CDPUserSvc"}
)

# Leer y registrar los registros actuales
foreach ($service in $services) {
    Write-Host "Checking current value for service: $($service.Name)"
    Show-RegistryValue -keyPath $service.KeyPath -valueName "Start" -logFilePath $logFilePath
}

Write-Host "All services have been checked."
