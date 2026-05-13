<#
.SYNOPSIS
    Corrige automáticamente rutas de imágenes inconsistentes en los writeups
.DESCRIPTION
    Detecta y corrige:
    - Rutas con barra inicial inconsistente
    - Rutas que mezclan /assets/images/ y /assets/img/
    - Sugiere fixes para imágenes que no existen
#>

$ErrorActionPreference = "Continue"
$script:fixes = 0
$script:unfixable = @()

Write-Host "`n==============================================" -ForegroundColor Cyan
Write-Host " IMAGE PATH AUTO-FIXER" -ForegroundColor Cyan
Write-Host "==============================================`n" -ForegroundColor Cyan

$mdFiles = Get-ChildItem -Path "_posts" -Filter "*.md" -Recurse

foreach ($file in $mdFiles) {
    $originalContent = Get-Content $file.FullName -Raw
    $newContent = $originalContent
    
    Write-Host "Processing: $($file.Name)" -ForegroundColor White
    
    # Fix 1: Convert old /assets/images/ paths to /assets/img/
    if ($originalContent -match '/assets/images/') {
        Write-Host "  Fixing: /assets/images/ -> /assets/img/" -ForegroundColor Yellow
        $newContent = $newContent -replace '/assets/images/', '/assets/img/'
        $script:fixes++
    }
    
    # Fix 2: Normalize - ensure all paths start with /assets/ (with leading slash)
    # Find paths starting with "assets/" without leading slash
    $withoutSlash = [regex]::Matches($newContent, '\]\(assets/(img|images)/[^)]+\)')
    foreach ($match in $withoutSlash) {
        $old = $match.Value
        $new = $old -replace '\]\(assets/', '](/assets/'
        $newContent = $newContent -replace [regex]::Escape($old), $new
        Write-Host "  Fixing: Leading slash added: $old -> $new" -ForegroundColor Yellow
        $script:fixes++
    }
    
    # Fix 3: Remove spaces before closing parenthesis in image paths
    $spacesInPath = [regex]::Matches($newContent, '\]\(([^)]*\s+)\)')
    foreach ($match in $spacesInPath) {
        if ($match.Value -match '!\[\]') {
            $old = $match.Value
            $new = $old -replace '\s+\)', ')'
            $newContent = $newContent -replace [regex]::Escape($old), $new
            Write-Host "  Fixing: Removed trailing space in path" -ForegroundColor Yellow
            $script:fixes++
        }
    }
    
    # Save if modified
    if ($newContent -ne $originalContent) {
        Set-Content -Path $file.FullName -Value $newContent -NoNewline
        Write-Host "  -> File updated!" -ForegroundColor Green
    }
}

Write-Host "`n==============================================" -ForegroundColor Cyan
Write-Host " SUMMARY" -ForegroundColor Cyan
Write-Host "==============================================" -ForegroundColor Cyan
Write-Host " Total fixes applied: $script:fixes" -ForegroundColor Green

if ($script:fixes -gt 0) {
    Write-Host "`n Review the changes with: git diff" -ForegroundColor Yellow
    Write-Host " If OK, commit with: git add _posts && git commit -m 'Fix image paths'" -ForegroundColor Yellow
}