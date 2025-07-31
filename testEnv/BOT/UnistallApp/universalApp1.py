import os
import subprocess
import tempfile
from cw_rpa import Logger, Input


class PCAppStoreCleaner:
    def __init__(self):
        self.name = "PCAppStore"
        self.log_path = r"C:\Temp\pcappstore_cleanup.txt"
        self.marker_path = r"C:\Temp\PCAppStore_Removal_Activity.txt"
        self.logger = Logger()

        os.makedirs(os.path.dirname(self.log_path), exist_ok=True)
        open(self.log_path, "w", encoding="utf-8").close()

    def _log(self, message):
        self.logger.info(message)
        with open(self.log_path, "a", encoding="utf-8") as f:
            f.write(message + "\n")

    def _read_log(self):
        if os.path.exists(self.log_path):
            with open(self.log_path, "r", encoding="utf-8") as f:
                return f.read()
        return ""

    def _was_action_performed(self):
        return os.path.exists(self.marker_path)

    def _run_powershell_cleanup(self):
        ps_script = r'''
$MarkerFile = "C:\Temp\PCAppStore_Removal_Activity.txt"
if (!(Test-Path "C:\Temp")) { New-Item -Path "C:\Temp" -ItemType Directory -Force | Out-Null }
if (Test-Path $MarkerFile) { Remove-Item $MarkerFile -Force -ErrorAction SilentlyContinue }

function Mark-Cleanup { Add-Content -Path $MarkerFile -Value "cleaned" }

$UserProfiles = Get-ChildItem "C:\Users\" -Directory

foreach ($User in $UserProfiles) {
    $TargetFolder = "$($User.FullName)\pcappstore"
    $DesktopShortcut = "$($User.FullName)\Desktop\PC App Store.lnk"

    if (Test-Path $TargetFolder) {
        Write-Host "Attempting to delete: $TargetFolder"
        try {
            takeown /F $TargetFolder /R /D Y
            icacls $TargetFolder /grant Administrators:F /T /C
            $Processes = Get-Process | Where-Object { $_.ProcessName -match "pcappstore|watchdog" }

            foreach ($Process in $Processes) {
                Write-Host "Terminating process: $($Process.ProcessName)"
                Stop-Process -Id $Process.Id -Force -ErrorAction SilentlyContinue
            }

            Start-Sleep -Seconds 2
            Remove-Item -Path $TargetFolder -Recurse -Force -Confirm:$false -ErrorAction Stop
            Write-Host "Successfully removed: $TargetFolder"
            Mark-Cleanup
        } catch {
            Write-Host "Error removing: $TargetFolder"
        }
    } else {
        Write-Host "Folder not found: $TargetFolder"
    }

    if (Test-Path $DesktopShortcut) {
        Write-Host "Deleting desktop shortcut: $DesktopShortcut"
        Remove-Item -Path $DesktopShortcut -Force -ErrorAction SilentlyContinue
        Mark-Cleanup
    }
}

Write-Host "Scanning registry for PCAppStore uninstall keys..."
$UserSIDs = Get-ChildItem "Registry::HKEY_USERS" | Select-Object -ExpandProperty PSChildName

foreach ($SID in $UserSIDs) {
    $UninstallKey = "Registry::HKEY_USERS\$SID\Software\Microsoft\Windows\CurrentVersion\Uninstall\PCAppStore"
    if (Test-Path $UninstallKey) {
        try {
            Remove-Item -Path $UninstallKey -Recurse -Force -ErrorAction Stop
            Write-Host "Successfully deleted uninstall key under $SID"
            Mark-Cleanup
        } catch {
            Write-Host "Failed to delete uninstall key: $UninstallKey"
        }
    }
}

Write-Host "Removing startup entries for pcappstore, pcappstoreupdater, and watchdog..."
foreach ($SID in $UserSIDs) {
    $StartupPath = "Registry::HKEY_USERS\$SID\Software\Microsoft\Windows\CurrentVersion\Run"
    foreach ($Key in @("pcappstore", "pcappstoreupdater", "watchdog")) {
        if (Get-ItemProperty -Path $StartupPath -Name $Key -ErrorAction SilentlyContinue) {
            Write-Host "Removing startup entry: $Key from $StartupPath"
            Remove-ItemProperty -Path $StartupPath -Name $Key -Force -ErrorAction SilentlyContinue
            Mark-Cleanup
        }
    }
}

Write-Host "PCAppStore cleanup process completed."
        '''

        try:
            process = subprocess.Popen(
                ["powershell.exe", "-NoProfile", "-NonInteractive", "-Command", ps_script],
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True
            )
            stdout, stderr = process.communicate()

            if stdout:
                for line in stdout.strip().splitlines():
                    self._log(f"[STDOUT] {line}")

            if stderr:
                for line in stderr.strip().splitlines():
                    self._log(f"[STDERR] {line}")

            return process.returncode == 0

        except Exception as e:
            self._log(f"[ERROR] PowerShell execution failed: {e}")
            return False

    def clean(self):
        self._log("Starting PCAppStore Cleanup via PowerShell Script")
        ran_ok = self._run_powershell_cleanup()
        action_taken = self._was_action_performed()
        log = self._read_log()

        if ran_ok and action_taken:
            status = "succeeded"
            message = f"{self.name} cleaned up successfully."
        elif ran_ok and not action_taken:
            status = "failed"
            message = f"No {self.name} components were found."
        else:
            status = "partial"
            message = f"{self.name} cleanup encountered errors."

        try:
            self.logger.info(f"{self.name}: {message}")
        except Exception as e:
            self._log(f"[ERROR] Final logging failed: {e}")

        self._log("Completed PCAppStore Cleanup")
        return log, action_taken, status, message

class WaveBrowserCleaner:
    def __init__(self):
        self.name = "Wave Browser"
        self.log_path = "C:\\Temp\\wave_cleanup.txt"
        self.logger = Logger()
        os.makedirs(os.path.dirname(self.log_path), exist_ok=True)
        open(self.log_path, "w", encoding="utf-8").close()

    def _log(self, msg):
        self.logger.info(msg)
        with open(self.log_path, "a", encoding="utf-8") as f:
            f.write(msg + "\n")

    def _read_log(self):
        if os.path.exists(self.log_path):
            with open(self.log_path, "r", encoding="utf-8") as f:
                return f.read()
        return ""

    def _run_powershell_script(self):
        powershell_script = r"""$LogFile = "C:\Temp\WavesorRemediationLog.txt"

function Write-Log {
    param([string]$message)
    Add-Content -Path $LogFile -Value "$(Get-Date -Format 'yyyy-MM-dd HH:mm:ss') - $message"
}

function Delete-FileWithLog {
    param(
        [string]$path,
        [switch]$force
    )

    if (Test-Path -Path $path) {
        try {
            Remove-Item -Path $path -Force:$force -ErrorAction Stop
            Write-Log "Deleted: $path"
            Write-Output "Deleted: $path"
        }
        catch {
			$errorMsg = $_.Exception.Message
            $errorDetails = $_.Exception.ToString()
            Write-Log "Error deleting directory: $path"
            Write-Log "Error message: $errorMsg"
            Write-Log "Error details: $errorDetails"
            Write-Output "Error deleting directory: $path"
            Write-Output "Error message: $errorMsg"
            Write-Output "Error details: $errorDetails"
            Write-Log "Deletion unsuccessful: $path"
            Write-Output "Deletion unsuccessful: $path"
			
        }
    }
    else {
        Write-Log "File does not exist: $path"
        Write-Output "File does not exist: $path"
    }
}

function Delete-FolderWithLog {
    param(
        [string]$path,
        [switch]$force
    )

    if (Test-Path -Path $path) {
        try {
            Remove-Item -Path $path -Force:$force -Recurse -ErrorAction Stop
            Write-Log "Deleted Folder: $path"
            Write-Output "Deleted Folder: $path"
        }
        catch {
            Write-Log "Folder deletion unsuccessful: $path"
            Write-Output "Folder deletion unsuccessful: $path"
        }
    }
    else {
        Write-Log "Folder does not exist: $path"
        Write-Output "Folder does not exist: $path"
    }
}

# WaveBrowser SHA1 Hash Extraction Script

function Get-ExecutableHashes {
    param(
        [string]$Path,
        [string]$Context = ""
    )
    
    if (-not (Test-Path $Path)) {
        Write-Log "Path not found: $Path"
        return
    }
    
    Write-Log "Scanning executables in: $Path"
    if ($Context) {
        Write-Host "Scanning executables in: $Path" -ForegroundColor Yellow
    }
    
    try {
        $Executables = Get-ChildItem -Path $Path -Filter "*.exe" -File -Recurse -ErrorAction SilentlyContinue
        
        if ($Executables.Count -eq 0) {
            Write-Log "No executables found in: $Path"
            return
        }
        
        foreach ($Exe in $Executables) {
            try {
                $Hash = Get-FileHash -Path $Exe.FullName -Algorithm SHA1 -ErrorAction Stop
                $LogMessage = if ($Context) {
                     "$Context | File: $($Exe.Name) | Path: $($Exe.FullName) | SHA1: $($Hash.Hash)"
                 } else {
                     "File: $($Exe.Name) | SHA1: $($Hash.Hash)"
                 }
                
                Write-Log $LogMessage
                Write-Host "  File: $($Exe.Name) | SHA1: $($Hash.Hash)" -ForegroundColor Green
            } catch {
                Write-Log "Failed to get hash for: $($Exe.FullName) - $_"
                Write-Host "  Failed to get hash for: $($Exe.Name)" -ForegroundColor Red
            }
        }
    } catch {
        Write-Log "Error scanning directory $Path`: $_"
        Write-Host "Error scanning directory: $Path" -ForegroundColor Red
    }
}

# Main execution
Write-Log "Starting SHA1 hash extraction for WaveBrowser..."
Write-Host "Extracting SHA1 hashes before uninstall and cleanup..." -ForegroundColor Cyan

# System-wide installation paths
$SystemPaths = @(
    "C:\Program Files\WaveBrowser",
    "C:\Program Files\Wave Browser",
    "C:\Program Files\Wavesor Software",
    "C:\Program Files\Wavesor",
    "C:\Program Files\WebNavigatorBrowser",
    "C:\Program Files (x86)\WaveBrowser",
    "C:\Program Files (x86)\Wave Browser",
    "C:\Program Files (x86)\WebNavigatorBrowser",
    "C:\Program Files (x86)\Wavesor Software",
    "C:\Program Files (x86)\Wavesor"
)

Write-Log "Scanning system-wide installations..."
foreach ($Path in $SystemPaths) {
    Get-ExecutableHashes -Path $Path
}

# User-specific installations
Write-Log "Scanning user directories..."
Write-Host "Scanning user directories..." -ForegroundColor Cyan

try {
    $UserProfiles = Get-ChildItem -Path "C:\Users" -ErrorAction Stop |
                    Where-Object { $_.PSIsContainer } |
                    Select-Object -ExpandProperty Name
} catch {
    Write-Log "Error accessing user profiles: $_"
    Write-Host "Error accessing user profiles directory" -ForegroundColor Red
    return
}

$UserPathTemplates = @(
    "\Wavesor Software",
    "\Wavesor",
    "\WaveBrowser",
    "\Wave Browser",
	"\WebNavigatorBrowser",
    "\AppData\Local\WaveBrowser",
    "\AppData\Local\Wave Browser",
    "\AppData\Local\Wavesor Software",
    "\AppData\Local\Wavesor",
	"\AppData\Local\WebNavigatorBrowser",
    "\AppData\Local\Programs\WaveBrowser",
    "\AppData\Local\Programs\Wave Browser",
    "\AppData\Local\Programs\Wavesor Software",
    "\AppData\Local\Programs\Wavesor",
    "\AppData\Local\Programs\WebNavigatorBrowser",
    "\AppData\Roaming\WaveBrowser",
    "\AppData\Roaming\Wave Browser",
    "\AppData\Roaming\Wavesor Software"
    "\AppData\Roaming\Wavesor"
	"\AppData\Roaming\WebNavigatorBrowser",
	"\Downloads\Wave Browser*.exe"
	"\Downloads\WebNavigatorBrowser*.exe"
)

foreach ($User in $UserProfiles) {
    foreach ($Template in $UserPathTemplates) {
        $UserPath = "C:\Users\$User$Template"
        Get-ExecutableHashes -Path $UserPath -Context "User: $User"
    }
}

Write-Log "SHA1 hash extraction completed."
Write-Host "SHA1 hash extraction completed." -ForegroundColor Green

Write-Log "Starting graceful uninstall process for WaveBrowser..."

# Registry paths for uninstall entries
$UninstallKeys = @(
    "HKLM:\Software\Microsoft\Windows\CurrentVersion\Uninstall",
    "HKLM:\Software\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall",
    "HKCU:\Software\Microsoft\Windows\CurrentVersion\Uninstall",
    "HKCU:\Software\Wow6432Node\Microsoft\Windows\CurrentVersion\Uninstall"
)

$UninstallSuccess = $false
$UninstallKeyFound = $false
$FoundApps = @()

# Function to perform silent uninstallation
function Silent-Uninstall {
    param (
        [string]$UninstallString,
        [string]$AppName
    )
    
    if ($UninstallString) {
        Write-Log "Attempting uninstall for $AppName"
        
        # Try different silent parameters based on installer type
        $SilentParams = @("--force-uninstall")
        
        foreach ($param in $SilentParams) {
            try {
                Write-Log "Trying uninstall with parameter: $param"
                
                # Check if uninstaller is an MSI
                if ($UninstallString -match "msiexec") {
                    # MSI uninstall
                    $msiArgs = "/x", "/quiet", "/norestart"
                    if ($UninstallString -match "{[A-Fa-f0-9\-]{36}}") {
                        $productCode = [regex]::Match($UninstallString, "{[A-Fa-f0-9\-]{36}}").Value
                        Write-Log "MSI uninstall for product code: $productCode"
                        Start-Process -FilePath "msiexec.exe" -ArgumentList $msiArgs + $productCode -Wait -NoNewWindow -ErrorAction Stop
                    } else {
                        Start-Process -FilePath "msiexec.exe" -ArgumentList $UninstallString.Replace("msiexec.exe", "").Trim(), "/quiet", "/norestart" -Wait -NoNewWindow -ErrorAction Stop
                    }
                } else {
                    # Regular executable uninstall
                    if ($UninstallString.Contains('"')) {
                        # Handle quoted paths
                        $exePath = ($UninstallString -split '"')[1]
                        $args = ($UninstallString -split '"')[2].Trim()
                        Start-Process -FilePath $exePath -ArgumentList "$args $param" -Wait -NoNewWindow -ErrorAction Stop
                    } else {
                        # Simple path
                        $parts = $UninstallString -split ' ', 2
                        $exePath = $parts[0]
                        $existingArgs = if ($parts.Length -gt 1) { $parts[1] } else { "" }
                        Start-Process -FilePath $exePath -ArgumentList "$existingArgs $param" -Wait -NoNewWindow -ErrorAction Stop
                    }
                }
                
                Write-Log "$AppName uninstalled successfully with parameter: $param" -Level "SUCCESS"
                Write-Host "$AppName uninstalled successfully." -ForegroundColor Green
                return $true
                
            } catch {
                Write-Log "Uninstall attempt with $param failed: $_" -Level "WARN"
                continue
            }
        }
        
        Write-Log "All silent uninstall attempts failed for $AppName" -Level "ERROR"
        return $false
    } else {
        Write-Log "No uninstall string provided for $AppName" -Level "ERROR"
        return $false
    }
}

# Check all registry uninstall locations for WaveBrowser
foreach ($KeyPath in $UninstallKeys) {
    try {
        Write-Log "Checking registry path: $KeyPath"
        
        $FoundKeys = Get-ChildItem -Path $KeyPath -ErrorAction SilentlyContinue |
                     Where-Object {
                         $displayName = $_.GetValue("DisplayName")
                        $displayName -and (
                            $displayName -match "(?i)wavebrowser" -or 
                            $displayName -match "(?i)wave browser" -or
                            $displayName -match "(?i)WebNavigatorBrowser"
                        )
                    }
        
        foreach ($AppKey in $FoundKeys) {
            $UninstallKeyFound = $true
            $DisplayName = $AppKey.GetValue("DisplayName")
            $UninstallString = $AppKey.GetValue("UninstallString")
            $QuietUninstallString = $AppKey.GetValue("QuietUninstallString")
            
            Write-Log "Found application: $DisplayName in $KeyPath"
            Write-Host "Found application: $DisplayName" -ForegroundColor Yellow
            
            # Store found app info
            $FoundApps += @{
                Name = $DisplayName
                UninstallString = $UninstallString
                QuietUninstallString = $QuietUninstallString
                RegistryPath = $AppKey.PSPath
            }
            
            # Try quiet uninstall string first if available
            $uninstallAttempted = $false
            if ($QuietUninstallString) {
                Write-Log "Attempting quiet uninstall for: $DisplayName"
                $UninstallSuccess = Silent-Uninstall -UninstallString $QuietUninstallString -AppName $DisplayName
                $uninstallAttempted = $true
            }
            
            # If quiet uninstall failed or wasn't available, try regular uninstall string
            if (-not $UninstallSuccess -and $UninstallString) {
                Write-Log "Attempting regular uninstall for: $DisplayName"
                $UninstallSuccess = Silent-Uninstall -UninstallString $UninstallString -AppName $DisplayName
                $uninstallAttempted = $true
            }
            
            if (-not $uninstallAttempted) {
                Write-Log "No uninstall string found for: $DisplayName" -Level "WARN"
            }
            
            # Small delay between uninstalls
            Start-Sleep -Seconds 2
        }
    } catch {
        Write-Log "Error checking registry path $KeyPath`: $_" -Level "ERROR"
    }
}

# Output results
Write-Log "Graceful uninstall summary:"
Write-Host "`nGraceful Uninstall Summary:" -ForegroundColor Cyan

if ($UninstallKeyFound) {
    Write-Host "Found Applications:" -ForegroundColor Yellow
    foreach ($app in $FoundApps) {
        Write-Host "  - $($app.Name)" -ForegroundColor White
    }
    
    if ($UninstallSuccess) {
        Write-Log "At least one graceful uninstall was successful!" -Level "SUCCESS"
        Write-Host " Graceful uninstall completed successfully!" -ForegroundColor Green
    } else {
        Write-Log "All graceful uninstall attempts FAILED. Proceeding with forced cleanup." -Level "ERROR"
        Write-Host " Graceful uninstall FAILED. Proceeding with forced cleanup." -ForegroundColor Red
    }
} else {
    Write-Log "No WaveBrowser uninstall entries found in registry." -Level "WARN"
    Write-Host "! No WaveBrowser applications found in uninstall registry." -ForegroundColor Yellow
    Write-Host "  Proceeding directly to forced cleanup..." -ForegroundColor Yellow
}

Get-Process wavebrowser -ErrorAction SilentlyContinue | Stop-Process -Force
Get-Process SWUpdater -ErrorAction SilentlyContinue | Stop-Process -Force
Start-Sleep -Seconds 2

$userList = Get-Item C:\Users\* | Select-Object -ExpandProperty Name

foreach ($user in $userList) {
    if ($user -notlike "*Public*") {
        $filePaths = @(
            "C:\users\$user\downloads\Wave Browser*.exe",
            "C:\users\$user\appdata\roaming\microsoft\windows\start menu\programs\WaveBrowser.lnk",
            "C:\USERS\$user\APPDATA\ROAMING\MICROSOFT\INTERNET EXPLORER\QUICK LAUNCH\WAVEBROWSER.LNK",
            "C:\USERS\$user\DESKTOP\WAVEBROWSER.LNK"
        )

        $folderPaths = @(
            "C:\users\$user\Wavesor Software",
            "C:\users\$user\WebNavigatorBrowser",
            "C:\users\$user\appdata\local\WaveBrowser",
            "C:\users\$user\appdata\local\Temp\Wave",
            "C:\users\$user\appdata\local\WebNavigatorBrowser"
        )
        

        foreach ($filePath in $filePaths) {
            Delete-FileWithLog -path $filePath -Force
        }


        foreach ($folderPath in $folderPaths) {
            Delete-FolderWithLog -path $folderPath -Force
        }


        $oneDriveFolders = Get-ChildItem -Path "C:\Users\$user" -Directory -Recurse -Filter "*OneDrive*" |
            Where-Object { $_.Name -like "*OneDrive*" }

        foreach ($oneDriveFolder in $oneDriveFolders) {
            $waveBrowserOneDriveLnkPaths = Get-ChildItem -Path $oneDriveFolder.FullName -File -Recurse -Filter "WaveBrowser.lnk" |
                Where-Object { $_.Directory.FullName -like "*OneDrive*" }

            foreach ($waveBrowserOneDriveLnkPath in $waveBrowserOneDriveLnkPaths) {
                Delete-FileWithLog -path $waveBrowserOneDriveLnkPath.FullName -Force
            }
        }
# Define task name match pattern
$taskPattern = "Wavesor|SWUpdaterCore|WaveBrowser"

# Find tasks matching the pattern
$tasks = Get-ScheduledTask | Where-Object {$_.TaskName -match $taskPattern}

if ($tasks) {
    foreach ($task in $tasks) {
        Write-Log -Message "Found and removing: $($task.TaskName)"
        Write-Host "Found and removing: $($task.TaskName)"
        $task | Unregister-ScheduledTask -Confirm:$false
    }
} else {
    Write-Log -Message "No tasks found matching '$taskPattern'"
    Write-Host "No tasks found matching '$taskPattern'"
}
}
}
Write-Log "Script execution completed. Log file written to $LogFile"
Write-Host 'Script execution completed. Log file written to $LogFile'"""

        try:
            with tempfile.NamedTemporaryFile(delete=False, suffix=".ps1", mode="w", encoding="utf-8") as temp_script:
                temp_script.write(powershell_script)
                temp_script_path = temp_script.name

            command = ["powershell.exe", "-NoProfile", "-ExecutionPolicy", "Bypass", "-File", temp_script_path]
            process = subprocess.Popen(command, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
            stdout, stderr = process.communicate()

            if stdout:
                for line in stdout.strip().splitlines():
                    self._log(f"[STDOUT] {line}")
            if stderr:
                for line in stderr.strip().splitlines():
                    self._log(f"[STDERR] {line}")

            os.remove(temp_script_path)
            return process.returncode == 0
        except Exception as e:
            self._log(f"[ERROR] Failed to run PowerShell script: {str(e)}")
            return False

    def clean(self):
        self._log("Starting Wave Browser Cleanup via PowerShell Script")
        success = self._run_powershell_script()
        log = self._read_log()

        if success:
            status = "succeeded"
            message = f"{self.name} cleaned up successfully."
        else:
            if "error" in log.lower() or "[stderr]" in log.lower():
                status = "partial"
                message = f"{self.name} partially removed. Some errors occurred. See log for details."
            else:
                status = "failed"
                message = f"No {self.name} components found or script execution failed."

        try:
            self.logger.info(f"{self.name}: {message}")
        except Exception as e:
            self._log(f"[ERROR] Final logging failed: {e}")

        self._log("Completed Wave Browser Cleanup")
        return log, success, status, message

class ShiftBrowserCleaner:
    def __init__(self):
        self.logger = Logger()

    def clean(self):
        temp_script_path = None
        try:
            powershell_script = r"""
$LogFile = "C:\ShiftBrowser_Removal_Log.txt"
$SomethingFound = $false

function Write-Log {
    param ($Message)
    $entry = "$(Get-Date): $Message"
    Add-Content -Path $LogFile -Value $entry
    Write-Output $entry
}

Write-Log "Starting Shift Browser cleanup process..."

$ShiftPaths = @(
    "C:\Program Files (x86)\Shift",
    "C:\Program Files\Shift"
)

Write-Log "Extracting SHA1 hashes before uninstall and cleanup..."
foreach ($ShiftPath in $ShiftPaths) {
    if (Test-Path $ShiftPath) {
        $SomethingFound = $true
        Write-Log "Scanning executables in: $ShiftPath"
        $Executables = Get-ChildItem -Path $ShiftPath -Filter "*.exe" -File
        foreach ($Exe in $Executables) {
            $Hash = Get-FileHash -Path $Exe.FullName -Algorithm SHA1
            Write-Log "File: $($Exe.Name) | SHA1 Hash: $($Hash.Hash)"
        }
    } else {
        Write-Log "Shift folder not found at: $ShiftPath"
    }
}

Write-Log "Scanning user AppData directories for SHA1 hashes..."
$UserProfiles = Get-ChildItem -Path "C:\Users" | Select-Object -ExpandProperty Name
$AdditionalShiftPaths = @(
    "C:\Users\{0}\AppData\Local\Programs\Shift",
    "C:\Users\{0}\AppData\Local\Shift",
    "C:\Users\{0}\AppData\Roaming\Shift",
    "C:\Users\{0}\Shift"
)

foreach ($User in $UserProfiles) {
    if ($User -ne "Public") {
        foreach ($ShiftPathTemplate in $AdditionalShiftPaths) {
            $ShiftPath = $ShiftPathTemplate -f $User
            if (Test-Path $ShiftPath) {
                $SomethingFound = $true
                Write-Log "Scanning executables in: $ShiftPath"
                $Executables = Get-ChildItem -Path $ShiftPath -Filter "*.exe" -File
                foreach ($Exe in $Executables) {
                    $Hash = Get-FileHash -Path $Exe.FullName -Algorithm SHA1
                    Write-Log "File: $($Exe.Name) | SHA1 Hash: $($Hash.Hash)"
                }
            } else {
                Write-Log "Shift folder not found for user: $User at $ShiftPath"
            }
        }
    }
}

$UninstallKeys = @(
    "HKLM:\Software\Microsoft\Windows\CurrentVersion\Uninstall",
    "HKLM:\Software\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall",
    "HKCU:\Software\Microsoft\Windows\CurrentVersion\Uninstall",
    "HKCU:\Software\Wow6432Node\Microsoft\Windows\CurrentVersion\Uninstall"
)

$UninstallSuccess = $false
$UninstallKeyFound = $false

function Silent-Uninstall {
    param ($UninstallString)
    if ($UninstallString) {
        Write-Log "Attempting silent uninstall using: $UninstallString /SILENT"
        try {
            Start-Process -FilePath $UninstallString -ArgumentList "/SILENT" -Wait -NoNewWindow -ErrorAction Stop
            Write-Log "Shift Browser uninstalled successfully."
            return $true
        } catch {
            Write-Log "Silent uninstall failed. Proceeding with forced removal."
            return $false
        }
    } else {
        return $false
    }
}

foreach ($KeyPath in $UninstallKeys) {
    $ShiftKey = Get-ChildItem -Path $KeyPath -ErrorAction SilentlyContinue | 
                Where-Object { $_.GetValue("DisplayName") -eq "Shift" }
    if ($ShiftKey) {
        $SomethingFound = $true
        $UninstallKeyFound = $true
        Write-Log "Uninstall key found in: $KeyPath"
        $UninstallSuccess = Silent-Uninstall $ShiftKey.GetValue("UninstallString")
        break
    }
}

if ($UninstallKeyFound) {
    if ($UninstallSuccess) {
        Write-Log "Graceful uninstall was successful!"
    } else {
        Write-Log "Graceful uninstall **FAILED**. Proceeding with cleanup."
    }
} else {
    Write-Log "No uninstall key found. Skipping uninstallation."
}

$ShiftProcesses = @("shift", "ShiftUpdater")
foreach ($Process in $ShiftProcesses) {
    $RunningProcess = Get-Process -Name $Process -ErrorAction SilentlyContinue
    if ($RunningProcess) {
        $SomethingFound = $true
        Write-Log "Terminating process: $Process"
        Stop-Process -Name $Process -Force -ErrorAction SilentlyContinue
    }
}

Start-Sleep -Seconds 5

foreach ($ShiftPath in $ShiftPaths) {
    if (Test-Path $ShiftPath) {
        $SomethingFound = $true
        Write-Log "Attempting to remove Shift installation folder: $ShiftPath"
        Remove-Item -Path $ShiftPath -Recurse -Force -ErrorAction SilentlyContinue
        if (Test-Path $ShiftPath) {
            Write-Log "FAILED: Shift folder still exists at $ShiftPath"
        } else {
            Write-Log "SUCCESS: Shift folder successfully removed from $ShiftPath"
        }
    } else {
        Write-Log "No Shift folder found at $ShiftPath"
    }
}

foreach ($User in $UserProfiles) {
    $ShiftPaths = @(
        "C:\Users\$User\AppData\Local\ShiftData",
        "C:\Users\$User\AppData\Local\Programs\Shift",
        "C:\Users\$User\AppData\Local\Shift",
        "C:\Users\$User\AppData\Roaming\Shift",
        "C:\Users\$User\Shift"
    )
    foreach ($ShiftPath in $ShiftPaths) {
        if (Test-Path $ShiftPath) {
            $SomethingFound = $true
            Write-Log "Attempting to remove Shift folder for user: $User at $ShiftPath"
            Remove-Item -Path $ShiftPath -Recurse -Force -ErrorAction SilentlyContinue
            if (Test-Path $ShiftPath) {
                Write-Log "FAILED: Shift folder still exists for user: $User at $ShiftPath"
            } else {
                Write-Log "SUCCESS: Shift folder successfully removed for user: $User at $ShiftPath"
            }
        } else {
            Write-Log "No Shift folder found for user: $User at $ShiftPath"
        }
    }
}

if ($SomethingFound) {
    Write-Output "FOUND_COMPONENTS"
} else {
    Write-Output "NO_COMPONENTS_FOUND"
}

Write-Log "Shift Browser cleanup process completed!"
"""

            with tempfile.NamedTemporaryFile(delete=False, suffix=".ps1", mode="w", encoding="utf-8") as temp_script:
                temp_script.write(powershell_script)
                temp_script_path = temp_script.name

            result = subprocess.run(
                ["powershell.exe", "-ExecutionPolicy", "Bypass", "-File", temp_script_path],
                capture_output=True,
                text=True,
                check=True
            )

            output_lines = result.stdout.strip().splitlines()
            for line in output_lines:
                self.logger.info(line)

            status = "succeeded" if any("FOUND_COMPONENTS" in line for line in output_lines) else "failed"
            return ("\n".join(output_lines), "clean", status, "")

        except subprocess.CalledProcessError as e:
            self.logger.error(f"PowerShell script failed: {e.stderr}")
            return (e.stderr, "clean", "failed", "")
        except Exception as ex:
            self.logger.error(f"Unexpected error: {str(ex)}")
            return (str(ex), "clean", "failed", "")
        finally:
            if temp_script_path and os.path.exists(temp_script_path):
                os.remove(temp_script_path)
                self.logger.debug(f"Deleted temp script: {temp_script_path}")

class OneStartOneLaunchCleaner:
    def __init__(self):
        self.name = "OneStart/OneLaunch"
        self.logger = Logger()
        self.log_path = r"C:\Temp\onestart_cleanup.txt"
        self.marker_file = r"C:\Temp\OneStartOneLaunch_Removal_Activity.txt"
        self.ps_log_file = r"C:\Temp\OneStart_OneLaunch_Removal.log"

        os.makedirs(os.path.dirname(self.log_path), exist_ok=True)
        open(self.log_path, "w", encoding="utf-8").close()

    def _log(self, msg: str):
        self.logger.info(msg)
        with open(self.log_path, "a", encoding="utf-8") as f:
            f.write(msg + "\n")

    def _read_file(self, file_path):
        if os.path.exists(file_path):
            with open(file_path, "r", encoding="utf-8") as f:
                return f.read()
        return ""

    def _run_ps_script(self):
        powershell_script = r'''# OneStart/OneLaunch Complete Removal Script - Fixed
# Run as Administrator

Write-Host "OneStart/OneLaunch Complete Removal Script" -ForegroundColor Cyan
Write-Host "==========================================" -ForegroundColor Cyan

function Write-Log {
    param([string]$Message, [string]$Level = "INFO")
    $timestamp = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
    
    $LogFile = "C:\OneStart_OneLaunch_Removal.log"
    $LogEntry = "[$timestamp] [$Level] $Message"
    
    try {
        $LogEntry | Out-File -FilePath $LogFile -Append -Encoding UTF8 -ErrorAction SilentlyContinue
    } catch {
        # Silently continue if logging fails
    }
}

# OneStart/OneLaunch SHA1 Hash Extraction Script

function Get-ExecutableHashes {
    param(
        [string]$Path,
        [string]$Context = ""
    )
    
    if (-not (Test-Path $Path)) {
        Write-Log "Path not found: $Path"
        return
    }
    
    Write-Log "Scanning executables in: $Path"
    if ($Context) {
        Write-Host "Scanning executables in: $Path" -ForegroundColor Yellow
    }
    
    try {
        $Executables = Get-ChildItem -Path $Path -Filter "*.exe" -File -Recurse -ErrorAction SilentlyContinue
        
        if ($Executables.Count -eq 0) {
            Write-Log "No executables found in: $Path"
            return
        }
        
        foreach ($Exe in $Executables) {
            try {
                $Hash = Get-FileHash -Path $Exe.FullName -Algorithm SHA1 -ErrorAction Stop
                $LogMessage = if ($Context) { 
                    "$Context | File: $($Exe.Name) | Path: $($Exe.FullName) | SHA1: $($Hash.Hash)" 
                } else { 
                    "File: $($Exe.Name) | SHA1: $($Hash.Hash)" 
                }
                
                Write-Log $LogMessage
                Write-Host "  File: $($Exe.Name) | SHA1: $($Hash.Hash)" -ForegroundColor Green
            } catch {
                Write-Log "Failed to get hash for: $($Exe.FullName) - $_"
                Write-Host "  Failed to get hash for: $($Exe.Name)" -ForegroundColor Red
            }
        }
    } catch {
        Write-Log "Error scanning directory $Path`: $_"
        Write-Host "Error scanning directory: $Path" -ForegroundColor Red
    }
}

# Main execution
Write-Log "Starting SHA1 hash extraction for OneStart/OneLaunch..."
Write-Host "Extracting SHA1 hashes before uninstall and cleanup..." -ForegroundColor Cyan

# System-wide installation paths
$SystemPaths = @(
    "C:\Program Files (x86)\OneStart",
    "C:\Program Files\OneStart",
    "C:\Program Files (x86)\OneLaunch",
    "C:\Program Files\OneLaunch"
    "C:\Program Files\OneLaunch.ai"
    "C:\Program Files\OneStart.ai"
)

Write-Log "Scanning system-wide installations..."
foreach ($Path in $SystemPaths) {
    Get-ExecutableHashes -Path $Path
}

# User-specific installations
Write-Log "Scanning user directories..."
Write-Host "Scanning user directories..." -ForegroundColor Cyan

try {
    $UserProfiles = Get-ChildItem -Path "C:\Users" -ErrorAction Stop | 
                   Where-Object { $_.PSIsContainer } | 
                   Select-Object -ExpandProperty Name
} catch {
    Write-Log "Error accessing user profiles: $_"
    Write-Host "Error accessing user profiles directory" -ForegroundColor Red
    return
}

$UserPathTemplates = @(
    "\OneStart",
    "\OneLaunch",
    "\OneStart.ai",
    "\OneLaunch.ai",
    "\AppData\Local\Programs\OneStart",
    "\AppData\Local\Programs\OneLaunch", 
    "\AppData\Local\OneStart",
    "\AppData\Local\OneLaunch",
    "\AppData\Local\OneStart.ai",
    "\AppData\Local\OneLaunch.ai",
    "\AppData\Roaming\OneStart",
    "\AppData\Roaming\OneLaunch"
    "\AppData\Roaming\OneStart.ai",
    "\AppData\Roaming\OneLaunch.ai"
)

foreach ($User in $UserProfiles) {
    foreach ($Template in $UserPathTemplates) {
        $UserPath = "C:\Users\$User$Template"
        Get-ExecutableHashes -Path $UserPath -Context "User: $User"
    }
}

Write-Log "SHA1 hash extraction completed."
Write-Host "SHA1 hash extraction completed." -ForegroundColor Green

Write-Log "Starting graceful uninstall process for OneStart/OneLaunch..."

# Registry paths for uninstall entries
$UninstallKeys = @(
    "HKLM:\Software\Microsoft\Windows\CurrentVersion\Uninstall",
    "HKLM:\Software\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall",
    "HKCU:\Software\Microsoft\Windows\CurrentVersion\Uninstall",
    "HKCU:\Software\Wow6432Node\Microsoft\Windows\CurrentVersion\Uninstall"
)

$UninstallSuccess = $false
$UninstallKeyFound = $false
$FoundApps = @()

# Function to perform silent uninstallation
function Silent-Uninstall {
    param (
        [string]$UninstallString,
        [string]$AppName
    )
    
    if ($UninstallString) {
        Write-Log "Attempting uninstall for $AppName"
        
        # Try different silent parameters based on installer type
        $SilentParams = @("--force-uninstall")
        
        foreach ($param in $SilentParams) {
            try {
                Write-Log "Trying uninstall with parameter: $param"
                
                # Check if uninstaller is an MSI
                if ($UninstallString -match "msiexec") {
                    # MSI uninstall
                    $msiArgs = "/x", "/quiet", "/norestart"
                    if ($UninstallString -match "{[A-Fa-f0-9\-]{36}}") {
                        $productCode = [regex]::Match($UninstallString, "{[A-Fa-f0-9\-]{36}}").Value
                        Write-Log "MSI uninstall for product code: $productCode"
                        Start-Process -FilePath "msiexec.exe" -ArgumentList $msiArgs + $productCode -Wait -NoNewWindow -ErrorAction Stop
                    } else {
                        Start-Process -FilePath "msiexec.exe" -ArgumentList $UninstallString.Replace("msiexec.exe", "").Trim(), "/quiet", "/norestart" -Wait -NoNewWindow -ErrorAction Stop
                    }
                } else {
                    # Regular executable uninstall
                    if ($UninstallString.Contains('"')) {
                        # Handle quoted paths
                        $exePath = ($UninstallString -split '"')[1]
                        $args = ($UninstallString -split '"')[2].Trim()
                        Start-Process -FilePath $exePath -ArgumentList "$args $param" -Wait -NoNewWindow -ErrorAction Stop
                    } else {
                        # Simple path
                        $parts = $UninstallString -split ' ', 2
                        $exePath = $parts[0]
                        $existingArgs = if ($parts.Length -gt 1) { $parts[1] } else { "" }
                        Start-Process -FilePath $exePath -ArgumentList "$existingArgs $param" -Wait -NoNewWindow -ErrorAction Stop
                    }
                }
                
                Write-Log "$AppName uninstalled successfully with parameter: $param" -Level "SUCCESS"
                Write-Host "$AppName uninstalled successfully." -ForegroundColor Green
                return $true
                
            } catch {
                Write-Log "Uninstall attempt with $param failed: $_" -Level "WARN"
                continue
            }
        }
        
        Write-Log "All silent uninstall attempts failed for $AppName" -Level "ERROR"
        return $false
    } else {
        Write-Log "No uninstall string provided for $AppName" -Level "ERROR"
        return $false
    }
}

# Check all registry uninstall locations for OneStart/OneLaunch
foreach ($KeyPath in $UninstallKeys) {
    try {
        Write-Log "Checking registry path: $KeyPath"
        
        $FoundKeys = Get-ChildItem -Path $KeyPath -ErrorAction SilentlyContinue | 
                    Where-Object { 
                        $displayName = $_.GetValue("DisplayName")
                        $displayName -and (
                            $displayName -match "(?i)onestart" -or 
                            $displayName -match "(?i)onelaunch" -or
                            $displayName -match "(?i)one start" -or
                            $displayName -match "(?i)one launch"
                        )
                    }
        
        foreach ($AppKey in $FoundKeys) {
            $UninstallKeyFound = $true
            $DisplayName = $AppKey.GetValue("DisplayName")
            $UninstallString = $AppKey.GetValue("UninstallString")
            $QuietUninstallString = $AppKey.GetValue("QuietUninstallString")
            
            Write-Log "Found application: $DisplayName in $KeyPath"
            Write-Host "Found application: $DisplayName" -ForegroundColor Yellow
            
            # Store found app info
            $FoundApps += @{
                Name = $DisplayName
                UninstallString = $UninstallString
                QuietUninstallString = $QuietUninstallString
                RegistryPath = $AppKey.PSPath
            }
            
            # Try quiet uninstall string first if available
            $uninstallAttempted = $false
            if ($QuietUninstallString) {
                Write-Log "Attempting quiet uninstall for: $DisplayName"
                $UninstallSuccess = Silent-Uninstall -UninstallString $QuietUninstallString -AppName $DisplayName
                $uninstallAttempted = $true
            }
            
            # If quiet uninstall failed or wasn't available, try regular uninstall string
            if (-not $UninstallSuccess -and $UninstallString) {
                Write-Log "Attempting regular uninstall for: $DisplayName"
                $UninstallSuccess = Silent-Uninstall -UninstallString $UninstallString -AppName $DisplayName
                $uninstallAttempted = $true
            }
            
            if (-not $uninstallAttempted) {
                Write-Log "No uninstall string found for: $DisplayName" -Level "WARN"
            }
            
            # Small delay between uninstalls
            Start-Sleep -Seconds 2
        }
    } catch {
        Write-Log "Error checking registry path $KeyPath`: $_" -Level "ERROR"
    }
}

# Output results
Write-Log "Graceful uninstall summary:"
Write-Host "`nGraceful Uninstall Summary:" -ForegroundColor Cyan

if ($UninstallKeyFound) {
    Write-Host "Found Applications:" -ForegroundColor Yellow
    foreach ($app in $FoundApps) {
        Write-Host "  - $($app.Name)" -ForegroundColor White
    }
    
    if ($UninstallSuccess) {
        Write-Log "At least one graceful uninstall was successful!" -Level "SUCCESS"
        Write-Host " Graceful uninstall completed successfully!" -ForegroundColor Green
    } else {
        Write-Log "All graceful uninstall attempts FAILED. Proceeding with forced cleanup." -Level "ERROR"
        Write-Host " Graceful uninstall FAILED. Proceeding with forced cleanup." -ForegroundColor Red
    }
} else {
    Write-Log "No OneStart/OneLaunch uninstall entries found in registry." -Level "WARN"
    Write-Host "! No OneStart/OneLaunch applications found in uninstall registry." -ForegroundColor Yellow
    Write-Host "  Proceeding directly to forced cleanup..." -ForegroundColor Yellow
}


function Stop-ProcessesSafely {
    param([string[]]$ProcessNames)
    
    foreach ($processName in $ProcessNames) {
        try {
            $processes = Get-Process -Name $processName -ErrorAction SilentlyContinue
            if ($processes) {
                Write-Log "Stopping $($processes.Count) instance(s) of $processName"
                foreach ($process in $processes) {
                    try {
                        Stop-Process -InputObject $process -Force
                        Write-Log "Successfully stopped process $processName (PID: $($process.Id))" -Level "SUCCESS"
                    } catch {
                        Write-Log "Failed to stop process $processName (PID: $($process.Id)): $_" -Level "ERROR"
                    }
                }
            }
        } catch {
            Write-Log "Error checking for process $processName`: $_" -Level "ERROR"
        }
    }
}

function Remove-FilesAndFolders {
    param([string[]]$Paths)
    
    foreach ($path in $Paths) {
        try {
            $expandedPath = [Environment]::ExpandEnvironmentVariables($path)
            
            if (Test-Path $expandedPath) {
                Write-Log "Removing: $expandedPath"
                Remove-Item -Path $expandedPath -Recurse -Force -ErrorAction Stop
                
                if (-not (Test-Path $expandedPath)) {
                    Write-Log "Successfully removed: $expandedPath" -Level "SUCCESS"
                } else {
                    Write-Log "Failed to remove: $expandedPath" -Level "ERROR"
                }
            } else {
                Write-Log "Path does not exist: $expandedPath" -Level "WARN"
            }
        } catch {
            Write-Log "Error removing $path`: $_" -Level "ERROR"
        }
    }
}

function Remove-RegistryProperty {
    param(
        [string]$Path,
        [string]$PropertyName
    )
    
    try {
        if (Test-Path $Path) {
            $property = Get-ItemProperty -Path $Path -Name $PropertyName -ErrorAction SilentlyContinue
            if ($property) {
                Remove-ItemProperty -Path $Path -Name $PropertyName -ErrorAction Stop
                Write-Log "Removed registry property: $Path\$PropertyName" -Level "SUCCESS"
            }
        }
    } catch {
        Write-Log "Failed to remove registry property $Path\$PropertyName`: $_" -Level "ERROR"
    }
}

function Remove-RegistryKey {
    param([string]$Path)
    
    try {
        if (Test-Path $Path) {
            Write-Log "Removing registry key: $Path"
            Remove-Item -Path $Path -Recurse -Force -ErrorAction Stop
            Write-Log "Successfully removed registry key: $Path" -Level "SUCCESS"
        }
    } catch {
        Write-Log "Failed to remove registry key $Path`: $_" -Level "ERROR"
    }
}

# Step 1: Stop OneStart/OneLaunch processes
Write-Log "Step 1: Stopping OneStart/OneLaunch processes..."

$valid_path = @(
    "C:\Users\*\OneStart\*",
    "C:\Users\*\OneLaunch\*",
    "C:\Users\*\OneStart.ai\*",
    "C:\Users\*\OneLaunch.ai\*",
    "C:\Users\*\AppData\Local\Programs\OneStart\*",
    "C:\Users\*\AppData\Local\Programs\OneLaunch\*",
    "C:\Users\*\AppData\Local\OneStart\*",
    "C:\Users\*\AppData\Local\OneLaunch\*",
    "C:\Users\*\AppData\Local\OneStart.ai\*",
    "C:\Users\*\AppData\Local\OneLaunch.ai\*",
    "C:\Users\*\AppData\Roaming\OneStart\*",
    "C:\Users\*\AppData\Roaming\OneLaunch\*",
    "C:\Users\*\AppData\Roaming\OneStart.ai\*",
    "C:\Users\*\AppData\Roaming\OneLaunch.ai\*"
)

$process_names = @("OneStart", "onelaunch", "onelaunchtray", "chromium")

foreach ($proc in $process_names) {
    $OL_processes = Get-Process | Where-Object { $_.Name -like $proc }
    if ($OL_processes.Count -eq 0) {
        Write-Log "No $proc processes were found."
    } else {
        Write-Log "Found $($OL_processes.Count) $proc process(es). Checking file paths..."
        foreach ($process in $OL_processes) {
            $path = $process.Path
            $pathMatches = $false
            
            # Check if process path matches any of our valid patterns
            foreach ($pattern in $valid_path) {
                if ($path -like $pattern) {
                    $pathMatches = $true
                    break
                }
            }
            
            if ($pathMatches) {
                try {
                    Stop-Process -InputObject $process -Force
                    Write-Log "$proc process file path matches and has been stopped." -Level "SUCCESS"
                } catch {
                    Write-Log "Failed to stop $proc process: $_" -Level "ERROR"
                }
            } else {
                Write-Log "$proc file path doesn't match valid path - process not stopped."
            }
        }
    }
}

# Additional process cleanup
Stop-ProcessesSafely -ProcessNames @("onelaunch", "onelaunchtray", "chromium", "OneStart")

Start-Sleep -Seconds 2

# Step 2: Remove files and folders
Write-Log "Step 2: Removing files and folders..."

$file_paths = @(
    "\OneStart",
    "\OneLaunch",
    "\OneStart.ai",
    "\OneLaunch.ai",
    "\AppData\Local\Programs\OneStart",
    "\AppData\Local\Programs\OneLaunch", 
    "\AppData\Local\OneStart",
    "\AppData\Local\OneLaunch",
    "\AppData\Local\OneStart.ai",
    "\AppData\Local\OneLaunch.ai",
    "\AppData\Roaming\OneStart",
    "\AppData\Roaming\OneLaunch"
    "\AppData\Roaming\OneStart.ai",
    "\AppData\Roaming\OneLaunch.ai"
)

foreach ($folder in (Get-ChildItem C:\Users -ErrorAction SilentlyContinue)) {
    foreach ($fpath in $file_paths) {
        $path = Join-Path -Path $folder.FullName -ChildPath $fpath
        Write-Log "Checking path: $path"
        
        if (Test-Path $path) {
            try {
                Remove-Item -Path $path -Recurse -Force -ErrorAction Stop
                if (-not (Test-Path $path)) {
                    Write-Log "$path has been deleted." -Level "SUCCESS"
                } else {
                    Write-Log "$path could not be deleted." -Level "ERROR"
                }
            } catch {
                Write-Log "Error deleting $path`: $_" -Level "ERROR"
            }
        } else {
            Write-Log "$path does not exist."
        }
    }
}

# Step 3: Remove registry entries from user hives
Write-Log "Step 3: Removing registry entries from user hives..."

$reg_paths = @("\software\OneStart.ai")

foreach ($registry_hive in (Get-ChildItem registry::hkey_users -ErrorAction SilentlyContinue)) {
    foreach ($regpath in $reg_paths) {
        $path = $registry_hive.pspath + $regpath
        if (Test-Path $path) {
            try {
                Remove-Item -Path $path -Recurse -Force -ErrorAction Stop
                Write-Log "$path has been removed." -Level "SUCCESS"
            } catch {
                Write-Log "Failed to remove $path`: $_" -Level "ERROR"
            }
        }
    }
}

# Step 4: Remove registry properties from Run keys
Write-Log "Step 4: Removing startup registry properties..."

$reg_properties = @("OneStartBar", "OneStartBarUpdate", "OneStartUpdate", "OneLaunch", "OneLaunchChromium", "OneLaunchUpdater", "OneStart")

foreach ($registry_hive in (Get-ChildItem registry::hkey_users -ErrorAction SilentlyContinue)) {
    foreach ($property in $reg_properties) {
        $path = $registry_hive.pspath + "\software\microsoft\windows\currentversion\run"
        if (Test-Path $path) {
            $reg_key = Get-Item $path -ErrorAction SilentlyContinue
            if ($reg_key) {
                $prop_value = $reg_key.GetValueNames() | Where-Object { $_ -like $property }
                if ($prop_value) {
                    try {
                        Remove-ItemProperty $path $prop_value -ErrorAction Stop
                        Write-Log "$path\$prop_value registry property value has been removed." -Level "SUCCESS"
                    } catch {
                        Write-Log "Failed to remove $path\$prop_value`: $_" -Level "ERROR"
                    }
                }
            }
        }
    }
}

# Step 5: Remove OneStart/OneLaunch uninstall registry keys
Write-Log "Step 5: Removing OneStart/OneLaunch uninstall registry keys..."

# Registry paths for uninstall entries (32-bit and 64-bit)
$UninstallKeyPaths = @(
    "HKLM:\Software\Microsoft\Windows\CurrentVersion\Uninstall",
    "HKLM:\Software\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall",
    "HKCU:\Software\Microsoft\Windows\CurrentVersion\Uninstall",
    "HKCU:\Software\Wow6432Node\Microsoft\Windows\CurrentVersion\Uninstall"
)

$UninstallKeysFound = 0
$UninstallKeysRemoved = 0

foreach ($KeyPath in $UninstallKeyPaths) {
    try {
        Write-Log "Checking uninstall registry path: $KeyPath"
        
        if (Test-Path $KeyPath) {
            $FoundKeys = Get-ChildItem -Path $KeyPath -ErrorAction SilentlyContinue | 
                        Where-Object { 
                            $displayName = $_.GetValue("DisplayName")
                            $displayName -and (
                                $displayName -match "(?i)onestart" -or 
                                $displayName -match "(?i)onelaunch" -or
                                $displayName -match "(?i)one start" -or
                                $displayName -match "(?i)one launch"
                            )
                        }
            
            foreach ($AppKey in $FoundKeys) {
                $UninstallKeysFound++
                $DisplayName = $AppKey.GetValue("DisplayName")
                $UninstallString = $AppKey.GetValue("UninstallString")
                
                Write-Log "Found uninstall key: $DisplayName at $($AppKey.PSPath)"
                
                try {
                    Remove-Item -Path $AppKey.PSPath -Recurse -Force -ErrorAction Stop
                    $UninstallKeysRemoved++
                    Write-Log "Successfully removed uninstall key: $DisplayName" -Level "SUCCESS"
                } catch {
                    Write-Log "Failed to remove uninstall key $DisplayName`: $_" -Level "ERROR"
                }
            }
        } else {
            Write-Log "Registry path not found: $KeyPath"
        }
    } catch {
        Write-Log "Error checking registry path $KeyPath`: $_" -Level "ERROR"
    }
}

# Also check user registry hives (HKU)
Write-Log "Checking user registry hives for OneStart/OneLaunch uninstall keys..."

try {
    $UserHives = Get-ChildItem -Path "Registry::HKEY_USERS" -ErrorAction SilentlyContinue | 
                Where-Object { $_.Name -match "S-1-5-21-\d+-\d+-\d+-\d+$" }
    
    foreach ($UserHive in $UserHives) {
        $UserUninstallPath = "$($UserHive.PSPath)\Software\Microsoft\Windows\CurrentVersion\Uninstall"
        
        if (Test-Path $UserUninstallPath) {
            $UserFoundKeys = Get-ChildItem -Path $UserUninstallPath -ErrorAction SilentlyContinue | 
                            Where-Object { 
                                $displayName = $_.GetValue("DisplayName")
                                $displayName -and (
                                    $displayName -match "(?i)onestart" -or 
                                    $displayName -match "(?i)onelaunch" -or
                                    $displayName -match "(?i)one start" -or
                                    $displayName -match "(?i)one launch"
                                )
                            }
            
            foreach ($UserAppKey in $UserFoundKeys) {
                $UninstallKeysFound++
                $DisplayName = $UserAppKey.GetValue("DisplayName")
                
                Write-Log "Found user uninstall key: $DisplayName at $($UserAppKey.PSPath)"
                
                try {
                    Remove-Item -Path $UserAppKey.PSPath -Recurse -Force -ErrorAction Stop
                    $UninstallKeysRemoved++
                    Write-Log "Successfully removed user uninstall key: $DisplayName" -Level "SUCCESS"
                } catch {
                    Write-Log "Failed to remove user uninstall key $DisplayName`: $_" -Level "ERROR"
                }
            }
        }
    }
} catch {
    Write-Log "Error checking user registry hives: $_" -Level "ERROR"
}

Write-Log "Uninstall registry cleanup completed. Found: $UninstallKeysFound, Removed: $UninstallKeysRemoved"

# Step 6: Remove scheduled tasks
Write-Log "Step 6: Removing scheduled tasks..."

# Remove OneStart/OneLaunch/ChromiumLaunch scheduled tasks
Write-Log "Scanning for OneStart/OneLaunch/ChromiumLaunch scheduled tasks..."
Write-Host "Scanning for OneStart/OneLaunch/ChromiumLaunch scheduled tasks..." -ForegroundColor Cyan

try {
    # Get all scheduled tasks and filter for ones containing onestart, onelaunch, or chromiumlaunch
    $TasksToRemove = Get-ScheduledTask | Where-Object { 
        $_.TaskName -match "(?i)onestart" -or 
        $_.TaskName -match "(?i)onelaunch" -or
        $_.TaskName -match "(?i)chromiumlaunch"
    }
    
    if ($TasksToRemove.Count -eq 0) {
        Write-Log "No OneStart/OneLaunch/ChromiumLaunch scheduled tasks found."
        Write-Host "No OneStart/OneLaunch/ChromiumLaunch scheduled tasks found." -ForegroundColor Green
    } else {
        Write-Log "Found $($TasksToRemove.Count) OneStart/OneLaunch/ChromiumLaunch scheduled task(s):"
        Write-Host "Found $($TasksToRemove.Count) OneStart/OneLaunch/ChromiumLaunch scheduled task(s):" -ForegroundColor Yellow
        
        foreach ($Task in $TasksToRemove) {
            Write-Log "  - Task Name: $($Task.TaskName) | Path: $($Task.TaskPath) | State: $($Task.State)"
            Write-Host "  - $($Task.TaskName)" -ForegroundColor White
            
            try {
                Unregister-ScheduledTask -TaskName $Task.TaskName -Confirm:$false -ErrorAction Stop
                Write-Log "Successfully removed scheduled task: $($Task.TaskName)" -Level "SUCCESS"
                Write-Host "     Removed successfully" -ForegroundColor Green
            } catch {
                Write-Log "Failed to remove scheduled task $($Task.TaskName): $_" -Level "ERROR"
                Write-Host "     Failed to remove: $_" -ForegroundColor Red
            }
        }
    }
} catch {
    Write-Log "Error scanning for scheduled tasks: $_" -Level "ERROR"
    Write-Host "Error scanning for scheduled tasks: $_" -ForegroundColor Red
}

Write-Log "Scheduled task cleanup completed."

# Step 7: Remove additional files per user
Write-Log "Step 7: Removing additional files per user..."

$user_list = Get-Item C:\users\* -ErrorAction SilentlyContinue | Select-Object Name -ExpandProperty Name

foreach ($user in $user_list) {
    Write-Log "Processing user: $user"
    
    # Remove OneLaunch installers
    try {
        $installers = @(Get-ChildItem C:\users\$user -Recurse -Filter "OneLaunch*.exe" -ErrorAction SilentlyContinue | ForEach-Object { $_.FullName })
        foreach ($install in $installers) {
            if (Test-Path -Path $install) {
                Remove-Item $install -ErrorAction SilentlyContinue
                if (-not (Test-Path -Path $install)) {
                    Write-Log "Removed installer: $install" -Level "SUCCESS"
                } else {
                    Write-Log "Failed to remove: $install" -Level "ERROR"
                }
            }
        }
    } catch {
        Write-Log "Error searching for installers for user $user`: $_" -Level "ERROR"
    }
    
    # Remove shortcuts
    $shortcuts = @(
        "C:\Users\$user\AppData\Roaming\Microsoft\Windows\Start Menu\Programs\Startup\OneLaunch.lnk",
        "C:\Users\$user\AppData\Roaming\Microsoft\Windows\Start Menu\Programs\Startup\OneLaunchChromium.lnk",
        "C:\Users\$user\AppData\Roaming\Microsoft\Windows\Start Menu\Programs\Startup\OneLaunchUpdater.lnk",
        "C:\Users\$user\desktop\OneLaunch.lnk"
    )
    
    foreach ($shortcut in $shortcuts) {
        if (Test-Path -Path $shortcut) {
            try {
                Remove-Item $shortcut -ErrorAction Stop
                Write-Log "Removed shortcut: $shortcut" -Level "SUCCESS"
            } catch {
                Write-Log "Failed to remove OneLaunch shortcut: $shortcut - $_" -Level "ERROR"
            }
        }
    }
    
    # Remove local paths (Fixed variable name)
    $localPaths = @(
        "C:\Users\$user\appdata\local\OneLaunch",
        "C:\Users\$user\appdata\Roaming\Microsoft\Windows\Start Menu\Programs\OneLaunch"
        "C:\Users\$user\onestart.ai"
        "C:\Users\$user\onelaunch.ai"
        "C:\Users\$user\onestart"
        "C:\Users\$user\onelaunch"
    )
    
    foreach ($localPath in $localPaths) {
        if (Test-Path -Path $localPath) {
            try {
                Remove-Item $localPath -Force -Recurse -ErrorAction Stop
                Write-Log "Removed local path: $localPath" -Level "SUCCESS"
            } catch {
                Write-Log "Failed to remove OneLaunch path: $localPath - $_" -Level "ERROR"
            }
        }
    }
}

# Step 8: Remove user-specific registry entries
Write-Log "Step 8: Removing user-specific registry entries..."

$sid_list = Get-Item -Path "Registry::HKU\S-*" -ErrorAction SilentlyContinue | 
           Select-String -Pattern "S-\d-(?:\d+-){5,14}\d+" | 
           ForEach-Object { $_.ToString().Trim() }

foreach ($sid in $sid_list) {
    if ($sid -notlike "*_Classes*") {
        Write-Log "Processing SID: $sid"
        
        # Remove uninstall key
        $uninstallKey = "Registry::$sid\Software\Microsoft\Windows\CurrentVersion\Uninstall\{4947c51a-26a9-4ed0-9a7b-c21e5ae0e71a}_is1"
        Remove-RegistryKey -Path $uninstallKey
        
        # Remove run keys
        $runKeys = @("OneLaunch", "OneLaunchChromium", "OneLaunchUpdater", "OneStart")
        foreach ($key in $runKeys) {
            $keypath = "Registry::$sid\Software\Microsoft\Windows\CurrentVersion\Run"
            Remove-RegistryProperty -Path $keypath -PropertyName $key
        }
        
        # Remove misc keys
        $miscKeys = @("OneLaunchHTML_.pdf", "OneLaunch")
        $miscPaths = @(
            "Registry::$sid\SOFTWARE\Microsoft\Windows\CurrentVersion\ApplicationAssociationToasts",
            "Registry::$sid\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\FeatureUsage\AppBadgeUpdated",
            "Registry::$sid\SOFTWARE\RegisteredApplications"
        )
        
        foreach ($miscPath in $miscPaths) {
            foreach ($key in $miscKeys) {
                Remove-RegistryProperty -Path $miscPath -PropertyName $key
            }
        }
        
        # Remove registry paths
        $paths = @(
            "Registry::$sid\Software\OneLaunch",
            "Registry::$sid\SOFTWARE\Classes\OneLaunchHTML"
        )
        foreach ($path in $paths) {
            Remove-RegistryKey -Path $path
        }
    }
}

# Step 9: Remove task files
Write-Log "Step 9: Removing task files..."

$tasks = @("OneLaunchLaunchTask", "ChromiumLaunchTask", "OneLaunchUpdateTask")
foreach ($task in $tasks) {
    $taskPath = "C:\windows\system32\tasks\$task"
    if (Test-Path $taskPath) {
        try {
            Remove-Item $taskPath -ErrorAction Stop
            Write-Log "Removed task file: $taskPath" -Level "SUCCESS"
        } catch {
            Write-Log "Failed to remove OneLaunch task: $taskPath - $_" -Level "ERROR"
        }
    }
}

# Step 10: Remove task cache registry keys
Write-Log "Step 10: Removing task cache registry keys..."

$taskCacheKeys = @(
    "Registry::HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Schedule\TaskCache\TREE\OneLaunchLaunchTask",
    "Registry::HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Schedule\TaskCache\TREE\ChromiumLaunchTask",
    "Registry::HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Schedule\TaskCache\TREE\OneLaunchUpdateTask"
)
foreach ($taskCacheKey in $taskCacheKeys) {
    Remove-RegistryKey -Path $taskCacheKey
}

# Step 11: Remove trace cache registry keys
Write-Log "Step 11: Removing trace cache registry keys..."

$traceCacheKeys = @(
    "Registry::HKLM\SOFTWARE\Microsoft\Tracing\onelaunch_RASMANCS",
    "Registry::HKLM\SOFTWARE\Microsoft\Tracing\onelaunch_RASAPI32",
	"Registry::HKLM\SOFTWARE\Microsoft\Tracing\OneStart_RASAPI32",
	"Registry::HKLM\SOFTWARE\Microsoft\Tracing\OneStart_RASMANCS"

)
foreach ($traceCacheKey in $traceCacheKeys) {
    Remove-RegistryKey -Path $traceCacheKey
}

# Final cleanup - Stop any remaining processes
Write-Log "Final cleanup: Stopping any remaining processes..."
Stop-ProcessesSafely -ProcessNames @("onelaunch", "onelaunchtray", "chromium", "OneStart")

Write-Log "OneStart/OneLaunch removal process completed!" -Level "SUCCESS"
Write-Host "`nRECOMMENDATION: Please restart your computer to ensure all changes take effect." -ForegroundColor Yellow

# Summary
Write-Host "`nRemoval Summary:" -ForegroundColor Cyan
Write-Host "- Processes stopped" -ForegroundColor Green
Write-Host "- Files and folders removed" -ForegroundColor Green
Write-Host "- Registry entries cleaned" -ForegroundColor Green
Write-Host "- Startup entries removed" -ForegroundColor Green
Write-Host "- Scheduled tasks removed" -ForegroundColor Green
Write-Host "- User-specific data cleaned" -ForegroundColor Green
Write-Host "- Task cache cleared" -ForegroundColor Green'''

        try:
            with tempfile.NamedTemporaryFile(delete=False, suffix=".ps1", mode="w", encoding="utf-8") as f:
                f.write(powershell_script)
                script_path = f.name

            result = subprocess.run(
                ["powershell.exe", "-NoProfile", "-ExecutionPolicy", "Bypass", "-File", script_path],
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True
            )

            for line in result.stdout.strip().splitlines():
                self._log(f"[STDOUT] {line}")
            for line in result.stderr.strip().splitlines():
                self._log(f"[STDERR] {line}")

            os.remove(script_path)
            return result.returncode == 0
        except Exception as e:
            self._log(f"[ERROR] Failed to execute PowerShell: {e}")
            return False

    def _was_cleanup_performed(self):
        return os.path.exists(self.marker_file)

    def clean(self):
        self._log("Starting OneStart/OneLaunch Cleanup via PowerShell Script")
        success = self._run_ps_script()
        action_performed = self._was_cleanup_performed()

        status = "succeeded" if success and action_performed else ("failed" if success and not action_performed else "partial")
        message = (
            f"{self.name} cleaned successfully." if status == "succeeded" else
            f"No {self.name} components found." if status == "failed" else
            f"{self.name} partially cleaned with errors or nothing found."
        )

        try:
            self.logger.info(f"{self.name}: {message}")
        except Exception as e:
            self._log(f"[ERROR] Failed to log result: {str(e)}")

        self._log("Completed OneStart/OneLaunch Cleanup")
        return self._read_file(self.log_path), action_performed, status, message

def run_bulk_uninstaller():
    logger = Logger()
    input_provider = Input()

    cleaners = {
        "shiftbrowser": ShiftBrowserCleaner(),
        "wavebrowser": WaveBrowserCleaner(),
        "pcappstore": PCAppStoreCleaner(),
        "onestart" : OneStartOneLaunchCleaner()
    }

    logs_by_app = {}
    status_by_app = {}
    message_by_app = {}

    try:
        input_list = input_provider.get_value("UninstallAppNames_1750856640900")
        app_names_raw = eval(input_list)
        if not isinstance(app_names_raw, list):
            raise ValueError("Expected a list of app names.")
        
        app_names = [app.lower().replace(" ", "") for app in app_names_raw]

        for app in app_names:

            cleaner = cleaners.get(app)
            if cleaner:
                logger.info(f"Running cleaner for: {app}")
                log_text, action, status, _ = cleaner.clean()
                logs_by_app[app] = log_text
                status_by_app[app] = f"{app} : No {app} components were found." if status != "succeeded" else f"{app} : uninstalled successfully"
                message_by_app[app] = f"Could not uninstall {app}, please see the logs for more details." if status != "succeeded" else f"{app} components were removed successfully; see logs for details."
            else:
                logger.warning(f"No cleaner defined for: {app}")
                logs_by_app[app] = f"No cleaner available for: {app}"
                status_by_app[app] = f"{app} : Could not uninstall {app}; no cleaner available"
                message_by_app[app] = f"Could not uninstall {app}, please see the logs for more details."

    except Exception as e:
        error_msg = f"BulkUninstaller : failed to execute. Reason: {str(e)}"
        logger.error(error_msg)
        message_by_app["BulkUninstaller"] = error_msg
        status_by_app["BulkUninstaller"] = "BulkUninstaller : failed"
        logs_by_app["BulkUninstaller"] = error_msg

    status_values = list(message_by_app.values())
    if all("removed successfully" in s for s in status_values):
        overall_status = "Success"
    elif any("removed successfully" in s for s in status_values):
        overall_status = "Partial Success"
    else:
        overall_status = "Failed"

    try:
        for app in status_by_app:
            status = message_by_app.get(app, "")
            msg = status_by_app[app]

            # logger.info(f"-- Summary for {app} --\nStatus: {status}\nLog:\n{logs_by_app[app]}")

        if "removed successfully" in status:
            logger.result_success_message(msg)
        else:
            logger.result_failed_message(msg)
            
        print(msg)
        print(status)
        print(overall_status)
        print(logs_by_app)

        logger.result_data({
            "overall_status": overall_status,
            "status": status_by_app,
            "status_message": message_by_app,
            "logs": logs_by_app
        })

    except Exception as e:
        logger.error(f"[ERROR] Logging results failed in BulkUninstaller: {e}")
        logger.result_failed_message(str(e))

if __name__ == "__main__":
    run_bulk_uninstaller()
