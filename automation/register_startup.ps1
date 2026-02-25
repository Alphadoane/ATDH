$ActionBackend = New-ScheduledTaskAction -Execute "wscript.exe" -Argument "`"d:\cyberSec\automation\run_hidden.vbs`" `"d:\cyberSec\automation\start_backend.bat`""
$ActionCollector = New-ScheduledTaskAction -Execute "wscript.exe" -Argument "`"d:\cyberSec\automation\run_hidden.vbs`" `"d:\cyberSec\automation\start_collector.bat`""

$Trigger = New-ScheduledTaskTrigger -AtLogOn
$Settings = New-ScheduledTaskSettingsSet -AllowStartIfOnBatteries -DontStopIfGoingOnBatteries -ExecutionTimeLimit 0

# Register Backend (Normal Privileges)
Register-ScheduledTask -TaskName "ATDH_Backend" -Action $ActionBackend -Trigger $Trigger -Settings $Settings -Description "Starts ATDH Backend silently at logon" -Force

# Register Collector (Highest Privileges for Windows Logs)
$PrincipalCollector = New-ScheduledTaskPrincipal -UserId $env:USERNAME -LogonType Interactive -RunLevel Highest
Register-ScheduledTask -TaskName "ATDH_Collector" -Action $ActionCollector -Trigger $Trigger -Settings $Settings -Principal $PrincipalCollector -Description "Starts ATDH Collector silently at logon with Admin rights" -Force

Write-Host "Success! ATDH Backend and Collector have been registered to run silently at login." -ForegroundColor Green
Write-Host "You can manage these tasks in 'Task Scheduler' under names starting with 'ATDH_'."
