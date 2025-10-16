## -
## - Downloaded from micro-one.com
## - Operational Security
## -
## - Get-VTReport (v.2.1)
## - PowerShell script to check file hashes against VirusTotal database
## - Creation date        :: 04/03/2018
## - Last update on       :: 16/10/2025
## - Author               :: Micro-one (contact@micro-one.com)
## -
## ------

##
## ============================================================================
## CONFIGURATION - Edit these variables to customize the script
## ============================================================================
##

## --
## VirusTotal API Configuration
## --
$VTApiKey = "a9ee7d0a45436b42396199cd89a6a16d8f6cf2b00069ae68624db48c2c5bc62b"  # Your VirusTotal API key (get it from https://www.virustotal.com/gui/join-us)
$VTApiVersion = "v2"                             # API version (v2 or v3), tested in v2 only

## --
## File paths
## --
$HashListFile = ".\MD5_HashList.txt"            # Input file with hash list (one per line, support MD5, SHA1, SHA256)
$ResultFile = ".\VTReport_Result.csv"           # Output CSV file with results
$LogFile = ".\VTReport_Log.txt"                 # Log file path

## --
## API Rate Limiting
## --
## Free API: 4 requests per minute (15 seconds between requests)
## Premium API: Higher limits available
$sleepTime = 16                                  # Sleep time between requests (seconds)
$maxRetries = 3                                  # Maximum retry attempts on API errors

## --
## Display Configuration
## --
$colorPositive = "Magenta"                       # Color for files with detections
$colorNegative = "Green"                         # Color for clean files
$colorWarning = "Yellow"                         # Color for warnings
$showProgress = $true                            # Show progress bar

## --
## Detection Threshold
## --
$suspiciousThreshold = 2                         # Number of detections to consider suspicious
$maliciousThreshold = 10                         # Number of detections to consider malicious

##
## ============================================================================
## END OF CONFIGURATION - Do not edit below this line unless you know what you're doing
## ============================================================================
##

## --
## Set TLS 1.2 for secure connections
## --
[Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12

## --
## Initialize script
## --
$scriptStartTime = Get-Date
Write-Host "============================================" -ForegroundColor Cyan
Write-Host "  VirusTotal Hash Checker v2.0" -ForegroundColor Cyan
Write-Host "============================================" -ForegroundColor Cyan
Write-Host ""

## --
## Function to write to log file
## --
function Write-Log {
    param(
        [string]$Message,
        [string]$Level = "INFO"
    )
    $timestamp = Get-Date -Format "dd/MM/yyyy HH:mm:ss"
    $logMessage = "$timestamp :: $Level :: $Message"
    Add-Content -Path $LogFile -Value $logMessage
}

## --
## Function to validate API key
## --
function Test-VTApiKey {
    if ($VTApiKey -eq "YOUR_VIRUSTOTAL_API_KEY_HERE" -or [string]::IsNullOrWhiteSpace($VTApiKey)) {
        Write-Host "ERROR: Please configure your VirusTotal API key in the script!" -ForegroundColor Red
        Write-Host "Get your API key at: https://www.virustotal.com/gui/join-us" -ForegroundColor Yellow
        Write-Log "Script stopped - No valid API key configured" "ERROR"
        exit 1
    }
}

## --
## Function to validate hash format
## --
function Test-HashFormat {
    param([string]$Hash)
    
    $Hash = $Hash.Trim()
    
    # MD5: 32 hex characters
    if ($Hash -match '^[a-fA-F0-9]{32}$') {
        return @{Valid=$true; Type="MD5"}
    }
    # SHA1: 40 hex characters
    elseif ($Hash -match '^[a-fA-F0-9]{40}$') {
        return @{Valid=$true; Type="SHA1"}
    }
    # SHA256: 64 hex characters
    elseif ($Hash -match '^[a-fA-F0-9]{64}$') {
        return @{Valid=$true; Type="SHA256"}
    }
    else {
        return @{Valid=$false; Type="Unknown"}
    }
}

## --
## Function to submit hash to VirusTotal
## --
function Submit-VTHash {
    param(
        [string]$VThash,
        [int]$RetryCount = 0
    )
    
    try {
        $VTbody = @{
            resource = $VThash
            apikey = $VTApiKey
        }
        
        $VTresult = Invoke-RestMethod -Method GET -Uri 'https://www.virustotal.com/vtapi/v2/file/report' -Body $VTbody -ErrorAction Stop
        
        # Check for rate limit
        if ($VTresult.response_code -eq -2) {
            Write-Host "  Rate limit reached. Waiting 60 seconds..." -ForegroundColor Yellow
            Write-Log "Rate limit reached for hash: $VThash" "WARNING"
            Start-Sleep -Seconds 60
            return Submit-VTHash -VThash $VThash -RetryCount ($RetryCount + 1)
        }
        
        return $VTresult
    }
    catch {
        Write-Log "API error for hash ${VThash}: $($_.Exception.Message)" "ERROR"
        
        if ($RetryCount -lt $maxRetries) {
            Write-Host "  Error occurred. Retrying ($($RetryCount + 1)/$maxRetries)..." -ForegroundColor Yellow
            Start-Sleep -Seconds 5
            return Submit-VTHash -VThash $VThash -RetryCount ($RetryCount + 1)
        }
        else {
            Write-Host "  Failed after $maxRetries attempts." -ForegroundColor Red
            return $null
        }
    }
}

## --
## Function to determine threat level
## --
function Get-ThreatLevel {
    param([int]$Positives)
    
    if ($Positives -eq 0) {
        return @{Level="Clean"; Color=$colorNegative}
    }
    elseif ($Positives -lt $suspiciousThreshold) {
        return @{Level="Low"; Color=$colorWarning}
    }
    elseif ($Positives -lt $maliciousThreshold) {
        return @{Level="Suspicious"; Color=$colorPositive}
    }
    else {
        return @{Level="Malicious"; Color="Red"}
    }
}

## --
## Validate inputs
## --
Test-VTApiKey

if (-not (Test-Path $HashListFile)) {
    Write-Host "ERROR: Hash list file not found: $HashListFile" -ForegroundColor Red
    Write-Log "Hash list file not found: $HashListFile" "ERROR"
    exit 1
}

## --
## Initialize log file
## --
if (Test-Path $LogFile) {
    Write-Log "### New VirusTotal scan session started ###" "START"
} else {
    "### VirusTotal Hash Checker Log File ###" | Out-File -FilePath $LogFile -Encoding UTF8
    Write-Log "Log file created" "START"
}

## --
## Purge and initialize result file
## --
if (Test-Path $ResultFile) {
    Remove-Item $ResultFile
    Write-Host "Previous result file removed." -ForegroundColor Yellow
}

# CSV Header
$csvHeader = "Hash;Hash_Type;Scan_Date;Detections;Total_Engines;Detection_Rate;Threat_Level;Permalink"
$csvHeader | Out-File -FilePath $ResultFile -Encoding UTF8

Write-Log "Result file initialized: $ResultFile" "INFO"

## --
## Load hash list
## --
$hashList = Get-Content $HashListFile | Where-Object { $_.Trim() -ne "" }
$totalHashes = $hashList.Count

Write-Host "Loaded $totalHashes hashes from file." -ForegroundColor Cyan
Write-Host "API delay: $sleepTime seconds between requests" -ForegroundColor Cyan
Write-Host ""
Write-Log "Starting scan of $totalHashes hashes" "INFO"

## --
## Statistics counters
## --
$stats = @{
    Total = 0
    Clean = 0
    Suspicious = 0
    Malicious = 0
    NotFound = 0
    Errors = 0
}

## --
## Main processing loop
## --
$currentHash = 0

foreach ($hash in $hashList) {
    $currentHash++
    $hash = $hash.Trim()
    
    # Skip empty lines
    if ([string]::IsNullOrWhiteSpace($hash)) {
        continue
    }
    
    # Validate hash format
    $hashCheck = Test-HashFormat -Hash $hash
    if (-not $hashCheck.Valid) {
        Write-Host "[$currentHash/$totalHashes] INVALID HASH FORMAT: $hash" -ForegroundColor Red
        Write-Log "Invalid hash format: $hash" "ERROR"
        $stats.Errors++
        continue
    }
    
    # Show progress
    if ($showProgress) {
        $percentComplete = ($currentHash / $totalHashes) * 100
        Write-Progress -Activity "Scanning hashes on VirusTotal" -Status "Processing hash $currentHash of $totalHashes" -PercentComplete $percentComplete
    }
    
    Write-Host "[$currentHash/$totalHashes] Checking hash: " -NoNewline -ForegroundColor Cyan
    Write-Host $hash
    
    # Submit hash to VirusTotal
    $VTresult = Submit-VTHash -VThash $hash
    
    if ($null -eq $VTresult) {
        Write-Host "  ERROR: Unable to query VirusTotal API" -ForegroundColor Red
        $stats.Errors++
        continue
    }
    
    # Process results
    $stats.Total++
    
    if ($VTresult.response_code -eq 0) {
        # Hash not found in VT database
        Write-Host "  Status      : " -NoNewline -ForegroundColor Cyan
        Write-Host "NOT FOUND IN DATABASE" -ForegroundColor Yellow
        Write-Log "Hash not found: $hash" "INFO"
        $stats.NotFound++
        
        $csvLine = "$hash;$($hashCheck.Type);N/A;0;0;0%;Not Found;N/A"
        $csvLine | Out-File -FilePath $ResultFile -Append -Encoding UTF8
    }
    elseif ($VTresult.response_code -eq 1) {
        # Hash found - process results
        $VTpct = if ($VTresult.total -gt 0) {
            [math]::Round(($VTresult.positives / $VTresult.total) * 100, 2)
        } else { 0 }
        
        $threatInfo = Get-ThreatLevel -Positives $VTresult.positives
        
        # Update statistics
        if ($VTresult.positives -eq 0) { $stats.Clean++ }
        elseif ($VTresult.positives -lt $maliciousThreshold) { $stats.Suspicious++ }
        else { $stats.Malicious++ }
        
        # Display results
        Write-Host "  Scan Date   : " -NoNewline -ForegroundColor Cyan
        Write-Host $VTresult.scan_date
        
        Write-Host "  Detections  : " -NoNewline -ForegroundColor Cyan
        Write-Host "$($VTresult.positives)/$($VTresult.total) " -NoNewline -ForegroundColor $threatInfo.Color
        Write-Host "($VTpct%)" -ForegroundColor $threatInfo.Color
        
        Write-Host "  Threat Level: " -NoNewline -ForegroundColor Cyan
        Write-Host $threatInfo.Level -ForegroundColor $threatInfo.Color
        
        Write-Host "  Permalink   : " -NoNewline -ForegroundColor Cyan
        Write-Host $VTresult.permalink
        
        # Log results
        Write-Log "Hash: $hash | Detections: $($VTresult.positives)/$($VTresult.total) | Level: $($threatInfo.Level)" "INFO"
        
        # Write to CSV
        $csvLine = "$hash;$($hashCheck.Type);$($VTresult.scan_date);$($VTresult.positives);$($VTresult.total);$VTpct%;$($threatInfo.Level);$($VTresult.permalink)"
        $csvLine | Out-File -FilePath $ResultFile -Append -Encoding UTF8
    }
    
    Write-Host ""
    
    # Sleep to respect API rate limits (except for last hash)
    if ($currentHash -lt $totalHashes) {
        Start-Sleep -Seconds $sleepTime
    }
}

## --
## Display final statistics
## --
$scriptEndTime = Get-Date
$duration = $scriptEndTime - $scriptStartTime

Write-Host "============================================" -ForegroundColor Cyan
Write-Host "  SCAN COMPLETE - STATISTICS" -ForegroundColor Cyan
Write-Host "============================================" -ForegroundColor Cyan
Write-Host ""
Write-Host "Total hashes processed : " -NoNewline -ForegroundColor Cyan
Write-Host $stats.Total

Write-Host "Clean files            : " -NoNewline -ForegroundColor Cyan
Write-Host $stats.Clean -ForegroundColor $colorNegative

Write-Host "Suspicious files       : " -NoNewline -ForegroundColor Cyan
Write-Host $stats.Suspicious -ForegroundColor $colorWarning

Write-Host "Malicious files        : " -NoNewline -ForegroundColor Cyan
Write-Host $stats.Malicious -ForegroundColor Red

Write-Host "Not found in database  : " -NoNewline -ForegroundColor Cyan
Write-Host $stats.NotFound -ForegroundColor Yellow

Write-Host "Errors                 : " -NoNewline -ForegroundColor Cyan
Write-Host $stats.Errors -ForegroundColor Red

Write-Host ""
Write-Host "Duration               : " -NoNewline -ForegroundColor Cyan
Write-Host "$($duration.Hours)h $($duration.Minutes)m $($duration.Seconds)s"

Write-Host ""
Write-Host "Results saved to       : " -NoNewline -ForegroundColor Cyan
Write-Host $ResultFile -ForegroundColor Green

Write-Host "Log file saved to      : " -NoNewline -ForegroundColor Cyan
Write-Host $LogFile -ForegroundColor Green

Write-Host ""
Write-Host "============================================" -ForegroundColor Cyan

## --
## Log final statistics
## --
Write-Log "Scan completed - Total: $($stats.Total) | Clean: $($stats.Clean) | Suspicious: $($stats.Suspicious) | Malicious: $($stats.Malicious) | Not Found: $($stats.NotFound) | Errors: $($stats.Errors)" "INFO"
Write-Log "Duration: $($duration.ToString())" "INFO"
Write-Log "### Scan session ended ###" "END"

## --
## End of script
##
