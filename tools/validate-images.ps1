<#
.SYNOPSIS
    Valida que todas las imágenes referenciadas en los markdowns existan realmente
.DESCRIPTION
    Escanea todos los archivos .md en _posts y verifica que cada imagen
    referenciada con sintaxis ![]() tenga su archivo correspondiente en assets/
#>

$ErrorActionPreference = "Stop"
$script:errors = 0
$script:warnings = 0

Write-Host "`n==============================================" -ForegroundColor Cyan
Write-Host " IMAGE REFERENCE VALIDATOR" -ForegroundColor Cyan
Write-Host "==============================================`n" -ForegroundColor Cyan

# Get all markdown files (excluding _site)
$mdFiles = Get-ChildItem -Path "_posts" -Filter "*.md" -Recurse

foreach ($file in $mdFiles) {
    $content = Get-Content $file.FullName -Raw
    $lines = Get-Content $file.FullName
    
    # Extract all image references: ![alt](path)
    $matches = [regex]::Matches($content, '!\[([^\]]*)\]\(([^)]+)\)')
    
    foreach ($match in $matches) {
        $fullMatch = $match.Value
        $altText = $match.Groups[1].Value
        $imagePath = $match.Groups[2].Value
        
        # Clean image path - remove Jekyll attributes like {: .align-center}, {:.width=""}
        $imagePath = $imagePath -replace '\{.*\}', ''
        $imagePath = $imagePath.Trim()
        
        # Skip external URLs
        if ($imagePath -match '^https?://') {
            Write-Host "  [SKIP] External URL: $imagePath" -ForegroundColor Gray
            continue
        }
        
        # Convert to filesystem path
        # References can be:
        # 1. /assets/img/... -> assets/img/...
        # 2. /assets/images/... -> assets/images/... (old style)
        # 3. assets/img/... -> assets/img/...
        # 4. assets/images/... -> assets/images/... (old style)
        
        $fsPath = $imagePath -replace '^/', ''
        $fsPath = $fsPath -replace '/', '\'
        
        # Check if file exists
        $fullFsPath = Join-Path -Path (Get-Location) -ChildPath $fsPath
        
        if (Test-Path $fullFsPath) {
            Write-Host "  [OK] $imagePath" -ForegroundColor Green
        } else {
            Write-Host "  [MISSING] $imagePath" -ForegroundColor Red
            Write-Host "    Referenced in: $($file.Name)" -ForegroundColor Red
            Write-Host "    Expected path: $fullFsPath" -ForegroundColor Red
            
            # Try to suggest similar existing files
            $baseDir = Split-Path $fullFsPath -Parent
            $fileName = Split-Path $fullFsPath -Leaf
            
            if (Test-Path $baseDir) {
                $similarFiles = Get-ChildItem -Path $baseDir -Filter "*.png" -ErrorAction SilentlyContinue
                if ($similarFiles) {
                    Write-Host "    [HINT] Files in expected directory:" -ForegroundColor Yellow
                    foreach ($sf in $similarFiles) {
                        Write-Host "      - $($sf.Name)" -ForegroundColor Yellow
                    }
                }
            } else {
                Write-Host "    [HINT] Directory does not exist: $baseDir" -ForegroundColor Yellow
                # Try to find similar image folders
                $imgPattern = (Split-Path $baseDir -Leaf) -replace '-', '*'
                $baseImgPath = Join-Path (Get-Location) "assets\img"
                $similarDirs = Get-ChildItem -Path $baseImgPath -Directory | Where-Object { $_.Name -like "*$imgPattern*" }
                if ($similarDirs) {
                    Write-Host "    [HINT] Similar directories found:" -ForegroundColor Yellow
                    foreach ($sd in $similarDirs) {
                        Write-Host "      - $($sd.Name)" -ForegroundColor Yellow
                    }
                }
            }
            $script:errors++
        }
    }
}

Write-Host "`n==============================================" -ForegroundColor Cyan
Write-Host " RESULTS" -ForegroundColor Cyan
Write-Host "==============================================" -ForegroundColor Cyan

if ($script:errors -eq 0 -and $script:warnings -eq 0) {
    Write-Host "`n [SUCCESS] All image references are valid!" -ForegroundColor Green
    exit 0
} elseif ($script:errors -eq 0 -and $script:warnings -gt 0) {
    Write-Host "`n [WARNING] Found $script:warnings warning(s), but no broken references." -ForegroundColor Yellow
    exit 0
} else {
    Write-Host "`n [FAILURE] Found $script:errors broken image reference(s)!" -ForegroundColor Red
    Write-Host " [HINT] Run the fix script to attempt automatic corrections:" -ForegroundColor Yellow
    Write-Host "   .\tools\fix-image-paths.ps1`n" -ForegroundColor Yellow
    exit 1
}