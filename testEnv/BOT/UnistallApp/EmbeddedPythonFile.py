import subprocess
import tempfile
import os
from cw_rpa import Logger, Input

logger = Logger()

POWERSHELL_SCRIPT = r"""
$LogFile = "C:\Temp\PCAppStore_Removal_Log.txt"

function Write-Log {
    param ($Message)
    Add-Content -Path $LogFile -Value "$(Get-Date): $Message"
}

Write-Log "Starting PC App Store cleanup process..."
Write-Host "Starting PC App Store cleanup process..."

$PCAppStorePaths = @(
    "$Env:ProgramFiles\PC App Store",
    "$Env:ProgramFiles(x86)\PC App Store"
)

$ProcessName = "pcappstore"
if (Get-Process -Name $ProcessName -ErrorAction SilentlyContinue) {
    Stop-Process -Name $ProcessName -Force
    Write-Log "Stopped process: $ProcessName"
    Write-Host "Stopped process: $ProcessName"
}

foreach ($path in $PCAppStorePaths) {
    if (Test-Path $path) {
        try {
            Remove-Item -Path $path -Recurse -Force
            Write-Log "Removed directory: $path"
            Write-Host "Removed directory: $path"
        } catch {
            Write-Log "Failed to remove directory: $path - $_"
            Write-Host "Failed to remove directory: $path - $_"
        }
    }
}

$RegistryPaths = @(
    "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\PC App Store",
    "HKLM:\SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall\PC App Store"
)

foreach ($regPath in $RegistryPaths) {
    if (Test-Path $regPath) {
        try {
            Remove-Item -Path $regPath -Recurse -Force
            Write-Log "Removed registry key: $regPath"
            Write-Host "Removed registry key: $regPath"
        } catch {
            Write-Log "Failed to remove registry key: $regPath - $_"
            Write-Host "Failed to remove registry key: $regPath - $_"
        }
    }
}

Write-Log "PC App Store cleanup completed."
Write-Host "PC App Store cleanup completed."
"""

def run_embedded_powershell_script():
    temp_script_path = None
    try:
        input = Input.get_value("UninstallAppNames_1750856640900")
        with tempfile.NamedTemporaryFile(delete=False, suffix=".ps1", mode="w", encoding="utf-8") as temp_script:
            temp_script.write(POWERSHELL_SCRIPT)
            temp_script_path = temp_script.name

        logger.info("Executing embedded PowerShell cleanup script...")

        result = subprocess.run(
            ["powershell.exe", "-ExecutionPolicy", "Bypass", "-File", temp_script_path],
            capture_output=True,
            text=True,
            check=True
        )

        logger.debug(f"STDOUT:\n{result.stdout}")
        if result.stderr:
            logger.warning(f"STDERR:\n{result.stderr}")

        logger.result_success_message("PowerShell script executed successfully.")

    except subprocess.CalledProcessError as e:
        logger.result_failed_message(f"PowerShell script failed with exit code {e.returncode}. Error: {e.stderr}")

    except Exception as ex:
        logger.result_failed_message(f"Unexpected error during PowerShell execution: {str(ex)}")

    finally:
        if temp_script_path and os.path.exists(temp_script_path):
            os.remove(temp_script_path)
            logger.debug(f"Temporary script deleted: {temp_script_path}")

if __name__ == "__main__":
    run_embedded_powershell_script()