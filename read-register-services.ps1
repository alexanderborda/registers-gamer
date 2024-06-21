# Obtener la fecha y hora actual
$now = Get-Date -Format "yyyy-MM-dd_HH-mm-ss"

# Ruta del archivo de log
$logFilePath = "C:\Register_Logs_$now.txt"

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

# Inicializar contador de registros y keys no encontrados
$keypathsNoFound = 0
$keysNoFound = 0
$missingKeyPaths = @()

# Función para mostrar el valor actual de las claves leidas.
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
                $output = "KeyPath: $keyPath, $valueName $($value.$valueName)"
            }
            else {
                $output = "Key: $valueName Key Not found"
                $global:keysNoFound++
            }
        }
        else {
            $output = "KeyPath: $keyPath, keyPath Not found"
            # Agregar keyPath no encontrado al arreglo
            $global:missingKeyPaths += $keyPath
            # Incrementar contador de rutas no encontradas
            $global:keypathsNoFound++
        }
    }
    catch {
        $output = "Error accessing $keyPath $_"
        # Agregar keyPath no encontrado al arreglo
        $global:missingKeyPaths += $keyPath
        # Incrementar contador de rutas no encontradas
        $global:keypathsNoFound++
    }
    Write-Host $output
    Add-Content -Path $logFilePath -Value $output
    
}
$registryKeys = @(
    # Lista de servicios y sus valores de registro
    @{Name = "Start"; KeyPath = "HKLM:\SYSTEM\CurrentControlSet\Services\BITS" },
    @{Name = "Start"; KeyPath = "HKLM:\SYSTEM\CurrentControlSet\Services\BTAGService" },
    @{Name = "Start"; KeyPath = "HKLM:\SYSTEM\CurrentControlSet\Services\bthserv" },
    @{Name = "Start"; KeyPath = "HKLM:\SYSTEM\CurrentControlSet\Services\lfsvc" },
    @{Name = "Start"; KeyPath = "HKLM:\SYSTEM\CurrentControlSet\Services\DiagTrack" },
    @{Name = "Start"; KeyPath = "HKLM:\SYSTEM\CurrentControlSet\Services\HvHost" },
    @{Name = "Start"; KeyPath = "HKLM:\SYSTEM\CurrentControlSet\Services\vmickvpexchange" },
    @{Name = "Start"; KeyPath = "HKLM:\SYSTEM\CurrentControlSet\Services\vmicguestinterface" },
    @{Name = "Start"; KeyPath = "HKLM:\SYSTEM\CurrentControlSet\Services\vmicshutdown" },
    @{Name = "Start"; KeyPath = "HKLM:\SYSTEM\CurrentControlSet\Services\vmicheartbeat" },
    @{Name = "Start"; KeyPath = "HKLM:\SYSTEM\CurrentControlSet\Services\vmicvmsession" },
    @{Name = "Start"; KeyPath = "HKLM:\SYSTEM\CurrentControlSet\Services\vmicrdv" },
    @{Name = "Start"; KeyPath = "HKLM:\SYSTEM\CurrentControlSet\Services\vmictimesync" },
    @{Name = "Start"; KeyPath = "HKLM:\SYSTEM\CurrentControlSet\Services\vmicvss" },
    @{Name = "Start"; KeyPath = "HKLM:\SYSTEM\CurrentControlSet\Services\PhoneSvc" },
    @{Name = "Start"; KeyPath = "HKLM:\SYSTEM\CurrentControlSet\Services\Spooler" },
    @{Name = "Start"; KeyPath = "HKLM:\SYSTEM\CurrentControlSet\Services\QWAVE" },
    @{Name = "Start"; KeyPath = "HKLM:\SYSTEM\CurrentControlSet\Services\SysMain" },
    @{Name = "Start"; KeyPath = "HKLM:\SYSTEM\CurrentControlSet\Services\WSearch" },
    @{Name = "Start"; KeyPath = "HKLM:\SYSTEM\CurrentControlSet\Services\UserDataSvc" },
    @{Name = "Start"; KeyPath = "HKLM:\SYSTEM\CurrentControlSet\Services\UnistoreSvc" },
    @{Name = "Start"; KeyPath = "HKLM:\SYSTEM\CurrentControlSet\Services\UdkUserSvc" },
    @{Name = "Start"; KeyPath = "HKLM:\SYSTEM\CurrentControlSet\Services\PimIndexMaintenanceSvc" },
    @{Name = "Start"; KeyPath = "HKLM:\SYSTEM\CurrentControlSet\Services\DevicesFlowUserSvc" },
    @{Name = "Start"; KeyPath = "HKLM:\SYSTEM\CurrentControlSet\Services\PrintWorkflowUserSvc" },
    @{Name = "Start"; KeyPath = "HKLM:\SYSTEM\CurrentControlSet\Services\PenService" },
    @{Name = "Start"; KeyPath = "HKLM:\SYSTEM\CurrentControlSet\Services\P9RdrService" },
    @{Name = "Start"; KeyPath = "HKLM:\SYSTEM\CurrentControlSet\Services\MessagingService" },
    @{Name = "Start"; KeyPath = "HKLM:\SYSTEM\CurrentControlSet\Services\BluetoothUserService" },
    @{Name = "Start"; KeyPath = "HKLM:\SYSTEM\CurrentControlSet\Services\webthreatdefusersvc" },
    @{Name = "Start"; KeyPath = "HKLM:\SYSTEM\CurrentControlSet\Services\NPSMSvc" },
    @{Name = "Start"; KeyPath = "HKLM:\SYSTEM\CurrentControlSet\Services\OneSyncSvc" },
    @{Name = "Start"; KeyPath = "HKLM:\SYSTEM\CurrentControlSet\Services\WpnUserService" },
    @{Name = "Start"; KeyPath = "HKLM:\SYSTEM\CurrentControlSet\Services\CDPUserSvc" }
    @{Name = "Start"; KeyPath = "HKLM:\SYSTEM\CurrentControlSet\Services\GpuEnergyDrv" },
    # Miscellaneous system settings for better overall performance
    @{Name = "PowerThrottlingOff"; KeyPath = "HKLM:\SYSTEM\CurrentControlSet\Control\Power\PowerThrottling" },
    @{Name = "NetworkThrottlingIndex"; KeyPath = "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Multimedia\SystemProfile" },
    @{Name = "SystemResponsiveness"; KeyPath = "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Multimedia\SystemProfile" },
    @{Name = "Affinity"; KeyPath = "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Multimedia\SystemProfile\Tasks\Games" },
    @{Name = "Background Only"; KeyPath = "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Multimedia\SystemProfile\Tasks\Games" },
    @{Name = "Clock Rate"; KeyPath = "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Multimedia\SystemProfile\Tasks\Games" },
    @{Name = "GPU Priority"; KeyPath = "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Multimedia\SystemProfile\Tasks\Games" },
    @{Name = "Priority"; KeyPath = "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Multimedia\SystemProfile\Tasks\Games" },
    @{Name = "Scheduling Category"; KeyPath = "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Multimedia\SystemProfile\Tasks\Games" },
    @{Name = "SFIO Priority"; KeyPath = "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Multimedia\SystemProfile\Tasks\Games" },
    @{Name = "ShowSleepOption"; KeyPath = "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\FlyoutMenuSettings" },
    @{Name = "HibernateEnabled"; KeyPath = "HKLM:\SYSTEM\CurrentControlSet\Control\Power" },
    @{Name = "MaintenanceDisabled"; KeyPath = "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Schedule\Maintenance" },
    @{Name = "MenuShowDelay"; KeyPath = "HKCU:\Control Panel\Desktop" },
    @{Name = "Default"; KeyPath = "HKCU:\Software\Classes\CLSID\{86ca1aa0-34aa-4e8b-a509-50c905bae2a2}\InprocServer32" },
    @{Name = "GlobalUserDisabled"; KeyPath = "HKCU:\Software\Microsoft\Windows\CurrentVersion\BackgroundAccessApplications" },
    @{Name = "AllowNewsAndInterests"; KeyPath = "HKLM:\SOFTWARE\Policies\Microsoft\Dsh" },
    @{Name = "AllowTelemetry"; KeyPath = "HKLM:\SOFTWARE\Policies\Microsoft\Windows\DataCollection" },
    @{Name = "WaitToKillServiceTimeout"; KeyPath = "HKLM:\SYSTEM\CurrentControlSet\Control" },
    @{Name = "TaskbarAnimations"; KeyPath = "HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced" },
    @{Name = "ListviewAlphaSelect"; KeyPath = "HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced" },
    @{Name = "MaxThreads"; KeyPath = "HKLM:\SYSTEM\ControlSet001\Services\LanmanWorkstation\Parameters" },
    @{Name = "MaxCmds"; KeyPath = "HKLM:\SYSTEM\ControlSet001\Services\LanmanWorkstation\Parameters" },
    @{Name = "SearchOrderConfig"; KeyPath = "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\DriverSearching" },
    @{Name = "SynchronousUserGroupPolicy"; KeyPath = "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System" },
    @{Name = "VerboseStatus"; KeyPath = "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System" },
    @{Name = "SynchronousMachineGroupPolicy"; KeyPath = "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System" },
    @{Name = "NetworkThrottlingIndex"; KeyPath = "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Multimedia\SystemProfile" },
    @{Name = "SystemResponsiveness"; KeyPath = "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Multimedia\SystemProfile" },
    @{Name = "Affinity"; KeyPath = "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Multimedia\SystemProfile\Tasks\DisplayPostProcessing" },
    @{Name = "IRQ8Priority"; KeyPath = "HKLM:\SYSTEM\CurrentControlSet\Control\PriorityControl" },
    @{Name = "AdditionalCriticalWorkerThreads"; KeyPath = "HKLM:\SYSTEM\CurrentControlSet\Control\Session Manager\Executive" },
    @{Name = "SecondLevelDataCache"; KeyPath = "HKLM:\SYSTEM\CurrentControlSet\Control\Session Manager\Memory Management" },
    @{Name = "EnablePrefetcher"; KeyPath = "HKLM:\SYSTEM\CurrentControlSet\Control\Session Manager\Memory Management\PrefetchParameters" },
    @{Name = "DisableDeleteNotification"; KeyPath = "HKLM:\SYSTEM\CurrentControlSet\Control\FileSystem" },
    @{Name = "TCPNoDelay"; KeyPath = "HKLM:\SOFTWARE\Microsoft\MSMQ\Parameters" },
    @{Name = "EnableFirstLogonAnimation"; KeyPath = "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System" },
    @{Name = "StartupDelayInMSec"; KeyPath = "HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\Serialize" },
    @{Name = "Max Cached Icons"; KeyPath = "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer" },
    @{Name = "ExtendedUIHoverTime"; KeyPath = "HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced" },
    @{Name = "MaxCollectionCount"; KeyPath = "HKLM:\SYSTEM\ControlSet001\Services\LanmanWorkstation\Parameters" },
    @{Name = "Auto"; KeyPath = "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\AeDebug" },
    @{Name = "AutoChkTimeOut"; KeyPath = "HKLM:\SYSTEM\ControlSet001\Control\Session Manager" },
    @{Name = "AllowTelemetry"; KeyPath = "HKLM:\SOFTWARE\Policies\Microsoft\Windows\DataCollection" },
    @{Name = "HiberbootEnabled"; KeyPath = "HKLM:\SYSTEM\CurrentControlSet\Control\Session Manager\Power" },
    @{Name = "WaitToKillServiceTimeout"; KeyPath = "HKLM:\SYSTEM\CurrentControlSet\Control" },
    @{Name = "ExtendedUIHoverTime"; KeyPath = "HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced" },
    @{Name = "TaskbarAnimations"; KeyPath = "HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced" },
    @{Name = "ListviewAlphaSelect"; KeyPath = "HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced" },
    @{Name = "MaxCollectionCount"; KeyPath = "HKLM:\SYSTEM\ControlSet001\Services\LanmanWorkstation\Parameters" },
    @{Name = "MaxThreads"; KeyPath = "HKLM:\SYSTEM\ControlSet001\Services\LanmanWorkstation\Parameters" },
    @{Name = "MaxCmds"; KeyPath = "HKLM:\SYSTEM\ControlSet001\Services\LanmanWorkstation\Parameters" },
    @{Name = "SearchOrderConfig"; KeyPath = "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\DriverSearching" },
    @{Name = "HiberBootEnabled"; KeyPath = "HKLM:\SYSTEM\CurrentControlSet\Control\Session Manager\Power" },
    @{Name = "EnableFirstLogonAnimation"; KeyPath = "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System" },
    @{Name = "SynchronousUserGroupPolicy"; KeyPath = "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System" },
    @{Name = "VerboseStatus"; KeyPath = "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System" },
    @{Name = "SynchronousMachineGroupPolicy"; KeyPath = "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System" },
    @{Name = "NetworkThrottlingIndex"; KeyPath = "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Multimedia\SystemProfile" },
    @{Name = "SystemResponsiveness"; KeyPath = "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Multimedia\SystemProfile" },
    @{Name = "Affinity"; KeyPath = "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Multimedia\SystemProfile\Tasks\Games" },
    @{Name = "Background Only"; KeyPath = "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Multimedia\SystemProfile\Tasks\Games" },
    @{Name = "Clock Rate"; KeyPath = "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Multimedia\SystemProfile\Tasks\Games" },
    @{Name = "GPU Priority"; KeyPath = "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Multimedia\SystemProfile\Tasks\Games" },
    @{Name = "Priority"; KeyPath = "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Multimedia\SystemProfile\Tasks\Games" },
    @{Name = "Scheduling Category"; KeyPath = "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Multimedia\SystemProfile\Tasks\Games" },
    @{Name = "SFIO Priority"; KeyPath = "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Multimedia\SystemProfile\Tasks\Games" },
    @{Name = "HungAppTimeout"; KeyPath = "HKCU:\Control Panel\Desktop" },
    @{Name = "MenuShowDelay"; KeyPath = "HKCU:\Control Panel\Desktop" },
    @{Name = "WaitToKillAppTimeout"; KeyPath = "HKCU:\Control Panel\Desktop" },
    @{Name = "Max Cached Icons"; KeyPath = "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer" },
    @{Name = "NoInternetOpenWith"; KeyPath = "HKCU:\Software\Microsoft\Windows\CurrentVersion\Policies\Explorer" },
    @{Name = "NoResolveTrack"; KeyPath = "HKCU:\Software\Microsoft\Windows\CurrentVersion\Policies\Explorer" },
    @{Name = "PowerThrottlingOff"; KeyPath = "HKLM:\SYSTEM\CurrentControlSet\Control\Power\PowerThrottling" },
    @{Name = "ShowSleepOption"; KeyPath = "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\FlyoutMenuSettings" },
    @{Name = "HibernateEnabled"; KeyPath = "HKLM:\SYSTEM\CurrentControlSet\Control\Power" },
    @{Name = "MaintenanceDisabled"; KeyPath = "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Schedule\Maintenance" },
    @{Name = "AutoEndTasks"; KeyPath = "HKCU:\Control Panel\Desktop" },
    @{Name = "LowLevelHooksTimeout"; KeyPath = "HKCU:\Control Panel\Desktop" },
    @{Name = "GameDVR_Enabled"; KeyPath = "HKCU:\System\GameConfigStore" },
    @{Name = "GameDVR_FSEBehaviorMode"; KeyPath = "HKCU:\System\GameConfigStore" },
    @{Name = "GameDVR_HonorUserFSEBehaviorMode"; KeyPath = "HKCU:\System\GameConfigStore" },
    @{Name = "GameDVR_DXGIHonorFSEWindowsCompatible"; KeyPath = "HKCU:\System\GameConfigStore" },
    @{Name = "GameDVR_EFSEFeatureFlags"; KeyPath = "HKCU:\System\GameConfigStore" },
    @{Name = "PowerThrottlingOff"; KeyPath = "HKLM:\SYSTEM\CurrentControlSet\Control\Power\PowerThrottling" },
    @{Name = "HiberbootEnabled"; KeyPath = "HKLM:\SYSTEM\CurrentControlSet\Control\Session Manager\Power" }
    @{Name = "PowerThrottlingOff"; KeyPath = "HKLM:\SYSTEM\CurrentControlSet\Control\Power\PowerThrottling" },
    @{Name = "NetworkThrottlingIndex"; KeyPath = "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Multimedia\SystemProfile" },
    @{Name = "SystemResponsiveness"; KeyPath = "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Multimedia\SystemProfile" },
    @{Name = "Affinity"; KeyPath = "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Multimedia\SystemProfile\Tasks\Games" },
    @{Name = "Background Only"; KeyPath = "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Multimedia\SystemProfile\Tasks\Games" },
    @{Name = "Clock Rate"; KeyPath = "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Multimedia\SystemProfile\Tasks\Games" },
    @{Name = "GPU Priority"; KeyPath = "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Multimedia\SystemProfile\Tasks\Games" },
    @{Name = "Priority"; KeyPath = "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Multimedia\SystemProfile\Tasks\Games" },
    @{Name = "Scheduling Category"; KeyPath = "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Multimedia\SystemProfile\Tasks\Games" },
    @{Name = "SFIO Priority"; KeyPath = "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Multimedia\SystemProfile\Tasks\Games" },
    @{Name = "ShowSleepOption"; KeyPath = "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\FlyoutMenuSettings" },
    @{Name = "HibernateEnabled"; KeyPath = "HKLM:\SYSTEM\CurrentControlSet\Control\Power" },
    @{Name = "MaintenanceDisabled"; KeyPath = "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Schedule\Maintenance" },
    @{Name = "MenuShowDelay"; KeyPath = "HKCU:\Control Panel\Desktop" },
    @{Name = "Default"; KeyPath = "HKCU:\Software\Classes\CLSID\{86ca1aa0-34aa-4e8b-a509-50c905bae2a2}\InprocServer32" },
    @{Name = "GlobalUserDisabled"; KeyPath = "HKCU:\Software\Microsoft\Windows\CurrentVersion\BackgroundAccessApplications" },
    @{Name = "AllowNewsAndInterests"; KeyPath = "HKLM:\SOFTWARE\Policies\Microsoft\Dsh" },
    @{Name = "AllowTelemetry"; KeyPath = "HKLM:\SOFTWARE\Policies\Microsoft\Windows\DataCollection" },
    @{Name = "WaitToKillServiceTimeout"; KeyPath = "HKLM:\SYSTEM\CurrentControlSet\Control" },
    @{Name = "TaskbarAnimations"; KeyPath = "HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced" },
    @{Name = "ListviewAlphaSelect"; KeyPath = "HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced" },
    @{Name = "MaxThreads"; KeyPath = "HKLM:\SYSTEM\ControlSet001\Services\LanmanWorkstation\Parameters" },
    @{Name = "MaxCmds"; KeyPath = "HKLM:\SYSTEM\ControlSet001\Services\LanmanWorkstation\Parameters" },
    @{Name = "SearchOrderConfig"; KeyPath = "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\DriverSearching" },
    @{Name = "SynchronousUserGroupPolicy"; KeyPath = "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System" },
    @{Name = "VerboseStatus"; KeyPath = "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System" },
    @{Name = "SynchronousMachineGroupPolicy"; KeyPath = "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System" },
    @{Name = "Affinity"; KeyPath = "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Multimedia\SystemProfile\Tasks\DisplayPostProcessing" },
    @{Name = "IRQ8Priority"; KeyPath = "HKLM:\SYSTEM\CurrentControlSet\Control\PriorityControl" },
    @{Name = "AdditionalCriticalWorkerThreads"; KeyPath = "HKLM:\SYSTEM\CurrentControlSet\Control\Session Manager\Executive" },
    @{Name = "SecondLevelDataCache"; KeyPath = "HKLM:\SYSTEM\CurrentControlSet\Control\Session Manager\Memory Management" },
    @{Name = "EnablePrefetcher"; KeyPath = "HKLM:\SYSTEM\CurrentControlSet\Control\Session Manager\Memory Management\PrefetchParameters" },
    @{Name = "DisableDeleteNotification"; KeyPath = "HKLM:\SYSTEM\CurrentControlSet\Control\FileSystem" },
    @{Name = "TCPNoDelay"; KeyPath = "HKLM:\SOFTWARE\Microsoft\MSMQ\Parameters" },
    @{Name = "EnableFirstLogonAnimation"; KeyPath = "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System" },
    @{Name = "StartupDelayInMSec"; KeyPath = "HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\Serialize" },
    @{Name = "Max Cached Icons"; KeyPath = "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer" },
    @{Name = "ExtendedUIHoverTime"; KeyPath = "HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced" },
    @{Name = "MaxCollectionCount"; KeyPath = "HKLM:\SYSTEM\ControlSet001\Services\LanmanWorkstation\Parameters" },
    @{Name = "Auto"; KeyPath = "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\AeDebug" },
    @{Name = "AutoChkTimeOut"; KeyPath = "HKLM:\SYSTEM\ControlSet001\Control\Session Manager" },
    @{Name = "HiberbootEnabled"; KeyPath = "HKLM:\SYSTEM\CurrentControlSet\Control\Session Manager\Power" }
    @{Name = "Affinity"; KeyPath = "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Multimedia\SystemProfile\Tasks\Games" },
    @{Name = "Background Only"; KeyPath = "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Multimedia\SystemProfile\Tasks\Games" },
    @{Name = "Clock Rate"; KeyPath = "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Multimedia\SystemProfile\Tasks\Games" },
    @{Name = "GPU Priority"; KeyPath = "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Multimedia\SystemProfile\Tasks\Games" },
    @{Name = "Priority"; KeyPath = "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Multimedia\SystemProfile\Tasks\Games" },
    @{Name = "Scheduling Category"; KeyPath = "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Multimedia\SystemProfile\Tasks\Games" },
    @{Name = "SFIO Priority"; KeyPath = "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Multimedia\SystemProfile\Tasks\Games" },
    @{Name = "GameDVR_Enabled"; KeyPath = "HKCU:\System\GameConfigStore" },
    @{Name = "GameDVR_FSEBehaviorMode"; KeyPath = "HKCU:\System\GameConfigStore" },
    @{Name = "GameDVR_HonorUserFSEBehaviorMode"; KeyPath = "HKCU:\System\GameConfigStore" },
    @{Name = "GameDVR_DXGIHonorFSEWindowsCompatible"; KeyPath = "HKCU:\System\GameConfigStore" },
    @{Name = "GameDVR_EFSEFeatureFlags"; KeyPath = "HKCU:\System\GameConfigStore" },
)

# Recorrer la lista de registros y mostrar sus valores
foreach ($item in $registryKeys) {
    Write-Host "Checking current value of the key: $($item.Name) in the "
    Show-RegistryValue -keyPath $item.KeyPath -valueName $item.Name -logFilePath $logFilePath
    Start-Sleep -Seconds 0.5
}

Write-Host "All keypath have been checked."
Write-Output "keyPath no encontrados: $keypathsNoFound"
Write-Output "keys no encontrados: $keysNoFound"

# Mostrar keyPath no encontrados
if ($missingKeyPaths.Count -gt 0) {
    "KeyPaths no encontrados:"
    $missingKeyPaths | ForEach-Object {
        "  $_"
    }
}
else {
    "No se encontraron keyPaths."
}

# Mostrar mensaje de confirmación
Write-Output "Registros guardados en: $logFilePath"

# Solicitar confirmación para cerrar la ventana de PowerShell
Write-Output "Presiona Enter para salir..."
$null = Read-Host
