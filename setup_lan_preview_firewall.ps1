$ErrorActionPreference = 'Stop'
$ruleName = 'AI视觉中控台2.0 局域网预览'
$pythonPath = 'C:\Users\Administrator\.cache\codex-runtimes\codex-primary-runtime\dependencies\python\pythonw.exe'

Get-NetFirewallRule -DisplayName $ruleName -ErrorAction SilentlyContinue |
    Remove-NetFirewallRule -ErrorAction SilentlyContinue

New-NetFirewallRule `
    -DisplayName $ruleName `
    -Direction Inbound `
    -Action Allow `
    -Protocol TCP `
    -LocalPort 8081 `
    -RemoteAddress LocalSubnet `
    -Profile Any `
    -Program $pythonPath `
    -Description '仅允许本地子网访问 AI视觉中控台2.0'
