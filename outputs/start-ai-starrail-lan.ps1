$ErrorActionPreference = 'Stop'
$siteRoot = Split-Path -Parent $PSCommandPath
$port = 8080

Write-Host "AI星轨设计台正在局域网共享…" -ForegroundColor Cyan
Write-Host "请让同事访问: http://192.168.2.59:$port/ai-starrail-design-console.html" -ForegroundColor Yellow
Write-Host "按 Ctrl+C 停止共享。"

try {
    $rule = Get-NetFirewallRule -DisplayName 'AI Starrail Design LAN' -ErrorAction SilentlyContinue
    if (-not $rule) {
        New-NetFirewallRule -DisplayName 'AI Starrail Design LAN' -Direction Inbound -Action Allow -Protocol TCP -LocalPort $port -Profile Private | Out-Null
    }
} catch {
    Write-Host "防火墙规则未自动添加。若同事无法访问，请以管理员身份运行此脚本一次。" -ForegroundColor Yellow
}

Set-Location $siteRoot
python workflow_test_server.py --port $port
