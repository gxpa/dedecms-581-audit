<#
.SYNOPSIS
    Publish this folder as a new GitHub repository using the REST API (no git required).

.EXAMPLE
    $env:GITHUB_TOKEN = "ghp_xxxxxxxx"
    .\publish.ps1 -Repo dedecms-581-audit

.EXAMPLE
    .\publish.ps1 -Repo dedecms-581-audit -Private
#>
param(
    [string]$Repo = "dedecms-581-audit",
    [string]$Token = $env:GITHUB_TOKEN,
    [string]$Description = "DedeCMS v5.8.1 code audit: ShowMsg() Referer injection to template cache RCE",
    [switch]$Private
)

$ErrorActionPreference = "Stop"
if ([string]::IsNullOrWhiteSpace($Token)) {
    throw "GITHUB_TOKEN is empty. Set it first: `$env:GITHUB_TOKEN = 'ghp_xxx'"
}

$Api = "https://api.github.com"
$Headers = @{
    Authorization          = "Bearer $Token"
    Accept                 = "application/vnd.github+json"
    "X-GitHub-Api-Version" = "2022-11-28"
    "User-Agent"           = "dedecms-581-audit-publisher"
}

function Invoke-GitHub {
    param(
        [string]$Method,
        [string]$Path,
        $Body
    )
    $params = @{
        Method      = $Method
        Uri         = "$Api$Path"
        Headers     = $Headers
        TimeoutSec  = 60
        ErrorAction = "Stop"
    }
    if ($null -ne $Body) {
        $params.Body = ($Body | ConvertTo-Json -Depth 10 -Compress)
        $params.ContentType = "application/json; charset=utf-8"
    }
    return Invoke-RestMethod @params
}

$me = Invoke-GitHub -Method GET -Path "/user"
$owner = $me.login
Write-Host "[*] account: $owner"

$full = "$owner/$Repo"
try {
    $null = Invoke-GitHub -Method GET -Path "/repos/$full"
    Write-Host "[*] repo exists: $full"
} catch {
    if ($_.Exception.Response.StatusCode.value__ -ne 404) { throw }
    Write-Host "[*] creating repo: $full"
    $null = Invoke-GitHub -Method POST -Path "/user/repos" -Body @{
        name        = $Repo
        description = $Description
        private     = [bool]$Private
        auto_init   = $false
    }
    Start-Sleep -Seconds 2
}

$root = Split-Path -Parent $MyInvocation.MyCommand.Path
$files = Get-ChildItem -LiteralPath $root -Recurse -File |
    Where-Object { $_.FullName -notmatch '\\\.git\\' }

$ok = 0
$fail = 0
foreach ($f in $files) {
    $rel = $f.FullName.Substring($root.Length + 1).Replace('\', '/')
    $b64 = [Convert]::ToBase64String([IO.File]::ReadAllBytes($f.FullName))
    $body = @{
        message = "add $rel"
        content = $b64
    }
    try {
        $existing = Invoke-GitHub -Method GET -Path "/repos/$full/contents/$rel"
        $body.message = "update $rel"
        $body.sha = $existing.sha
    } catch {
        if ($_.Exception.Response.StatusCode.value__ -ne 404) { throw }
    }
    try {
        $null = Invoke-GitHub -Method PUT -Path "/repos/$full/contents/$rel" -Body $body
        Write-Host "[+] $rel"
        $ok++
    } catch {
        Write-Host "[-] $rel : $($_.Exception.Message)"
        $fail++
    }
}

$meta = Invoke-GitHub -Method GET -Path "/repos/$full"
Write-Host ""
Write-Host "done: $ok ok / $fail failed"
Write-Host "repo: $($meta.html_url)"
Write-Host "default branch: $($meta.default_branch)"
