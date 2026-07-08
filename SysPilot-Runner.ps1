# SysPilot-AI Complete Installer
Write-Host "========================================" -ForegroundColor Cyan
Write-Host "       SYSPILOT-AI INSTALLER" -ForegroundColor Cyan
Write-Host "========================================" -ForegroundColor Cyan
Write-Host ""

# Configuration
$exeUrl = "https://raw.githubusercontent.com/CoolSidOfficial/SysPilot-AI/main/syspilot.exe"
$exeName = "syspilot.exe"
$repoZipUrl = "https://github.com/CoolSidOfficial/SysPilot-AI/tree/main/tools"
$reportsFolder = "reports"

# Step 1: Download EXE
Write-Host "[1/4] Downloading syspilot.exe..." -ForegroundColor Yellow
try {
    Invoke-WebRequest -Uri $exeUrl -OutFile $exeName -ErrorAction Stop
    Write-Host "[OK] Download complete!" -ForegroundColor Green
} catch {
    Write-Host "[ERROR] Failed to download EXE!" -ForegroundColor Red
    Read-Host "Press Enter to exit"
    exit 1
}
Write-Host ""

# Step 2: Download and extract the entire repo to get the 'tools' folder
Write-Host "[2/4] Downloading tools folder (from repository)..." -ForegroundColor Yellow
try {
    $zipFile = "repo.zip"
    Invoke-WebRequest -Uri $repoZipUrl -OutFile $zipFile -ErrorAction Stop
    
    # Extract ZIP
    Expand-Archive -Path $zipFile -DestinationPath "." -Force
    
    # Move the 'tools' folder from the extracted repo to the current directory
    if (Test-Path "SysPilot-AI-main\tools") {
        # Remove existing 'tools' folder if it exists to avoid conflicts
        if (Test-Path "tools") {
            Remove-Item "tools" -Recurse -Force
        }
        Move-Item "SysPilot-AI-main\tools" "." -Force
        Write-Host "[OK] Tools folder downloaded and extracted!" -ForegroundColor Green
    } else {
        Write-Host "[WARNING] Tools folder not found in the repository!" -ForegroundColor Yellow
    }
    
    # Clean up the extracted repo folder and the ZIP file
    if (Test-Path "SysPilot-AI-main") {
        Remove-Item "SysPilot-AI-main" -Recurse -Force
    }
    if (Test-Path $zipFile) {
        Remove-Item $zipFile -Force
    }
} catch {
    Write-Host "[WARNING] Could not download or extract tools folder: $_" -ForegroundColor Yellow
}
Write-Host ""

# Step 3: Run the main executable
Write-Host "[3/4] Running syspilot.exe..." -ForegroundColor Yellow
if (Test-Path $exeName) {
    Start-Process -FilePath ".\$exeName" -Wait
    Write-Host "[OK] Execution complete!" -ForegroundColor Green
} else {
    Write-Host "[ERROR] syspilot.exe not found!" -ForegroundColor Red
    Read-Host "Press Enter to exit"
    exit 1
}
Write-Host ""

# Step 4: Cleanup and open reports folder
Write-Host "[4/4] Cleaning up and opening reports..." -ForegroundColor Yellow

# Delete the main EXE
if (Test-Path $exeName) {
    Remove-Item -Force $exeName
    Write-Host "[OK] EXE deleted" -ForegroundColor Green
}

# Delete the entire tools folder
if (Test-Path "tools") {
    Remove-Item "tools" -Recurse -Force
    Write-Host "[OK] Tools folder deleted" -ForegroundColor Green
}

# Create the reports folder if it doesn't exist, then open it
if (!(Test-Path $reportsFolder)) {
    New-Item -ItemType Directory -Path $reportsFolder | Out-Null
}
explorer $reportsFolder
Write-Host "[OK] Reports folder opened!" -ForegroundColor Green
Write-Host ""

Write-Host "All tasks completed successfully!" -ForegroundColor Cyan
Start-Sleep -Seconds 2