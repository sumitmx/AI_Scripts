import os
import subprocess
import time
import winreg
from cw_rpa import Logger 

logger = Logger() 

def run_powershell_command(command):
    process = subprocess.Popen(["powershell.exe", "-Command", command], stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    stdout, stderr = process.communicate()
    return stdout.decode(), stderr.decode()

def delete_user_folder(user_folder):
    target_folder = os.path.join(user_folder, "pcappstore")
    desktop_shortcut = os.path.join(user_folder, "Desktop", "PC App Store.lnk")

    if os.path.exists(target_folder):
        logger.info(f"Attempting to delete: {target_folder}")

        try:
            run_powershell_command(f"takeown /F '{target_folder}' /R /D Y")
            run_powershell_command(f"icacls '{target_folder}' /grant Administrators:F /T /C")

            processes = run_powershell_command("Get-Process | Where-Object { $_.ProcessName -match 'pcappstore|watchdog' } | Select-Object -ExpandProperty Id")[0].strip().split()
            for pid in processes:
                if pid:
                    logger.info(f"Terminating process: {pid}")
                    run_powershell_command(f"Stop-Process -Id {pid} -Force -ErrorAction SilentlyContinue")

            time.sleep(3)

            run_powershell_command(f"Remove-Item -Path '{target_folder}' -Recurse -Force -Confirm:$false -ErrorAction Stop")
            logger.info(f"Successfully removed: {target_folder}")

        except Exception as e:
            logger.error(f"Final attempt failed: {target_folder} could not be removed. Error: {str(e)}")
    else:
        logger.warning(f"Folder not found for user: {user_folder}")

    if os.path.exists(desktop_shortcut):
        logger.info(f"Deleting desktop shortcut: {desktop_shortcut}")
        os.remove(desktop_shortcut)

def delete_registry_key(path):
    try:
        with winreg.OpenKey(winreg.HKEY_USERS, path, 0, winreg.KEY_ALL_ACCESS) as key:
            winreg.DeleteKey(key, "Software\\Microsoft\\Windows\\CurrentVersion\\Uninstall\\PCAppStore")
            logger.info(f"Successfully deleted uninstall key: {path}")
    except FileNotFoundError:
        logger.warning(f"Uninstall key not found: {path}")
    except Exception as e:
        logger.error(f"Failed to remove uninstall key: {path}. Error: {str(e)}")

def remove_startup_entries(sid):
    startup_path = f"Software\\Microsoft\\Windows\\CurrentVersion\\Run"
    keys_to_remove = ["pcappstore", "pcappstoreupdater", "watchdog"]

    for key in keys_to_remove:
        try:
            with winreg.OpenKey(winreg.HKEY_USERS, f"{sid}\\{startup_path}", 0, winreg.KEY_ALL_ACCESS) as reg_key:
                winreg.DeleteValue(reg_key, key)
                logger.info(f"Removing startup entry: {key} from {startup_path}")
        except FileNotFoundError:
            logger.warning(f"Startup entry not found: {key}")
        except Exception as e:
            logger.error(f"Failed to remove startup entry: {key}. Error: {str(e)}")

def main():
    logger.info("Getting all user directories under C:\\Users")
    user_profiles = [os.path.join("C:\\Users", user) for user in os.listdir("C:\\Users") if os.path.isdir(os.path.join("C:\\Users", user))]

    for user in user_profiles:
        delete_user_folder(user)

    logger.info("Scanning registry for PCAppStore uninstall keys...")
    
    try:
        with winreg.OpenKey(winreg.HKEY_USERS, "") as users_key:
            for i in range(0, winreg.QueryInfoKey(users_key)[0]):
                sid = winreg.EnumKey(users_key, i)
                uninstall_key = f"{sid}\\Software\\Microsoft\\Windows\\CurrentVersion\\Uninstall\\PCAppStore"
                delete_registry_key(uninstall_key)
    except Exception as e:
        logger.error(f"Failed to access HKEY_USERS: {str(e)}")

    logger.info("Removing startup entries for pcappstore, pcappstoreupdater, and watchdog from all users...")
    
    try:
        with winreg.OpenKey(winreg.HKEY_USERS, "") as users_key:
            for i in range(0, winreg.QueryInfoKey(users_key)[0]):
                sid = winreg.EnumKey(users_key, i)
                remove_startup_entries(sid)
    except Exception as e:
        logger.error(f"Failed to access HKEY_USERS: {str(e)}")

    logger.info("Cleanup process completed!")

if __name__ == "__main__":
    main()
