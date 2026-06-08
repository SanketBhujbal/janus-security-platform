param(
    [string]$Token = $env:GITHUB_TOKEN,
    [string]$Owner = "SanketBhujbal",
    [string]$Repo  = "speedpay-demo"
)

if (-not $Token) { Write-Error "GITHUB_TOKEN not set"; exit 1 }

$headers = @{
    Authorization = "Bearer $Token"
    Accept = "application/vnd.github+json"
    "User-Agent" = "speedpay-setup"
    "X-GitHub-Api-Version" = "2022-11-28"
}
$targetDir = (Resolve-Path "$PSScriptRoot\..\sandbox\target-dotnet-api").Path
$repoSlug  = "$Owner/$Repo"

# 1. Verify token
Write-Host "`n-> Verifying token..." -ForegroundColor Cyan
$me = Invoke-RestMethod -Uri "https://api.github.com/user" -Headers $headers
Write-Host "OK Authenticated as: $($me.login)" -ForegroundColor Green

# 2. Create repo (skip if already exists)
Write-Host "`n-> Checking for existing repo..." -ForegroundColor Cyan
$repoUrl  = ""
$cloneUrl = ""
try {
    $existing = Invoke-RestMethod -Uri "https://api.github.com/repos/$repoSlug" -Headers $headers
    Write-Host "OK Repo already exists: $($existing.html_url)" -ForegroundColor Green
    $repoUrl  = $existing.html_url
    $cloneUrl = $existing.clone_url
} catch {
    Write-Host "-> Creating repo $repoSlug ..." -ForegroundColor Cyan
    $bodyObj = @{ name = $Repo; description = "Seeded vulnerable ASP.NET Core payments API for the Agentic Security Platform demo"; private = $false; auto_init = $false }
    $bodyJson = $bodyObj | ConvertTo-Json
    $created = Invoke-RestMethod -Uri "https://api.github.com/user/repos" -Method Post -Headers $headers -Body $bodyJson -ContentType "application/json"
    Write-Host "OK Created: $($created.html_url)" -ForegroundColor Green
    $repoUrl  = $created.html_url
    $cloneUrl = $created.clone_url
}

# 3. Write .gitignore
$gitignoreContent = "bin/`nobj/`n*.user`n.vs/`n.security_workdir/`n*.original`n"
[System.IO.File]::WriteAllText("$targetDir\.gitignore", $gitignoreContent)

# 4. Write README
$readmeContent = "# SpeedPay Demo API`n`nSeeded **vulnerable** ASP.NET Core payments API for the Agentic Security Platform demo.`n`n## Seeded vulnerabilities (PCI-DSS)`n`n| Endpoint | Vulnerability |`n|---|---|`n| POST /api/payments/charge | PAN + CVV written to logs |`n| POST /api/payments/transfer | No idempotency-key dedup |`n| POST /api/webhook/gateway | Trusts callback amount blindly |`n`n> **DO NOT USE IN PRODUCTION.**`n"
[System.IO.File]::WriteAllText("$targetDir\README.md", $readmeContent)
Write-Host "OK Wrote .gitignore and README.md" -ForegroundColor Green

# 5. Set git env vars (bypass corporate TLS proxy)
$env:GIT_SSL_NO_VERIFY   = "true"
$env:GIT_AUTHOR_NAME     = "SecurityBrain"
$env:GIT_AUTHOR_EMAIL    = "securitybrain@aci.local"
$env:GIT_COMMITTER_NAME  = "SecurityBrain"
$env:GIT_COMMITTER_EMAIL = "securitybrain@aci.local"

# Token passed via GIT_ASKPASS/credential helper, not embedded in URL.
$remoteUrl = "https://github.com/$repoSlug.git"

Push-Location $targetDir

if (Test-Path ".git") {
    Write-Host "`n-> Git repo already initialised - resetting remote..." -ForegroundColor Cyan
    git remote remove origin 2>$null
} else {
    Write-Host "`n-> Initialising git repo..." -ForegroundColor Cyan
    git init -b main
}

git remote add origin $remoteUrl
git add -A
git commit -m "feat: seeded vulnerable payments API (PCI-DSS demo)"
Write-Host "-> Pushing to main..." -ForegroundColor Cyan
git push -u origin main --force

Pop-Location

$line = "=" * 60
Write-Host "`n$line" -ForegroundColor Green
Write-Host "DONE! Repo is live:" -ForegroundColor Green
Write-Host "  $repoUrl" -ForegroundColor Yellow
Write-Host ""
Write-Host "Use these in the UI (GitHub PR section):" -ForegroundColor Cyan
Write-Host "  Repo slug   : $repoSlug"
Write-Host "  Base branch : main"
Write-Host "$line`n" -ForegroundColor Green
