import os
import subprocess
import hashlib
import winreg
from pathlib import Path
from cw_rpa import Logger, Input

class ShiftBrowserCleaner:
    def __init__(self):
        self.name = "Shift Browser"
        self.log_path = "C:\\Temp\\shift_cleanup.txt"
        self.logger = Logger()
        os.makedirs(os.path.dirname(self.log_path), exist_ok=True)
        open(self.log_path, "w", encoding="utf-8").close()

    def _log(self, msg):
        self.logger.info(msg)
        with open(self.log_path, "a", encoding="utf-8") as f:
            f.write(msg + "\n")

    def _read_log(self):
        with open(self.log_path, "r", encoding="utf-8") as f:
            return f.read()

    def _hash_executables(self, shift_paths):
        action = False
        for path in shift_paths:
            if os.path.exists(path):
                self._log(f"Scanning executables in: {path}")
                for root, dirs, files in os.walk(path):
                    for file in files:
                        if file.endswith(".exe"):
                            try:
                                file_path = os.path.join(root, file)
                                hash_sha1 = hashlib.sha1()
                                with open(file_path, 'rb') as f:
                                    while chunk := f.read(8192):
                                        hash_sha1.update(chunk)
                                self._log(f"File: {file} | SHA1 Hash: {hash_sha1.hexdigest()}")
                                action = True
                            except Exception as e:
                                self._log(f"Error hashing file {file_path}: {e}")
            else:
                self._log(f"Shift folder not found at: {path}")
        return action

    def _hash_user_executables(self, user_profiles):
        action = False
        for user in user_profiles:
            user_path = f"C:\\Users\\{user}\\AppData\\Local\\Programs\\Shift"
            if os.path.exists(user_path):
                self._log(f"Scanning executables in: {user_path}")
                for root, dirs, files in os.walk(user_path):
                    for file in files:
                        if file.endswith(".exe"):
                            try:
                                file_path = os.path.join(root, file)
                                hash_sha1 = hashlib.sha1()
                                with open(file_path, 'rb') as f:
                                    while chunk := f.read(8192):
                                        hash_sha1.update(chunk)
                                self._log(f"File: {file} | SHA1 Hash: {hash_sha1.hexdigest()}")
                                action = True
                            except Exception as e:
                                self._log(f"Error hashing file {file_path}: {e}")
            else:
                self._log(f"Shift folder not found for user: {user} at {user_path}")
        return action

    def _check_registry_keys(self):
        action = False
        uninstall_paths = [
            (winreg.HKEY_LOCAL_MACHINE, r"SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Uninstall"),
            (winreg.HKEY_LOCAL_MACHINE, r"SOFTWARE\\WOW6432Node\\Microsoft\\Windows\\CurrentVersion\\Uninstall"),
            (winreg.HKEY_CURRENT_USER, r"Software\\Microsoft\\Windows\\CurrentVersion\\Uninstall"),
            (winreg.HKEY_CURRENT_USER, r"Software\\Wow6432Node\\Microsoft\\Windows\\CurrentVersion\\Uninstall")
        ]

        for root, path in uninstall_paths:
            try:
                with winreg.OpenKey(root, path) as uninstall_key:
                    for i in range(0, winreg.QueryInfoKey(uninstall_key)[0]):
                        try:
                            subkey_name = winreg.EnumKey(uninstall_key, i)
                            with winreg.OpenKey(uninstall_key, subkey_name) as subkey:
                                display_name = winreg.QueryValueEx(subkey, "DisplayName")[0]
                                if "Shift" in display_name:
                                    self._log(f"Uninstall key found in: {path} -> {display_name}")
                                    action = True
                        except Exception:
                            continue
            except Exception as e:
                self._log(f"Error accessing registry {path}: {e}")

        if not action:
            self._log("No uninstall key found.")
        return action

    def _terminate_processes(self, process_list):
        action = False
        for process in process_list:
            try:
                result = subprocess.run(f"taskkill /f /im {process}.exe", shell=True, capture_output=True, text=True)
                if "SUCCESS" in result.stdout.upper():
                    self._log(f"Terminated process: {process}")
                    action = True
            except Exception as e:
                self._log(f"Error terminating process {process}: {e}")
        return action

    def _cleanup_paths(self, paths):
        action = False
        for path in paths:
            if os.path.exists(path):
                self._log(f"Attempting to remove Shift folder: {path}")
                try:
                    os.rmdir(path)
                    self._log(f"SUCCESS: Removed {path}")
                    action = True
                except Exception as e:
                    self._log(f"FAILED: Could not remove {path} - Error: {e}")
            else:
                self._log(f"No Shift folder found at {path}")
        return action

    def clean(self):
        self._log("Starting Shift Browser Cleanup")
        action = False
        shift_paths = [
            "C:\\Program Files (x86)\\Shift",
            "C:\\Program Files\\Shift"
        ]
        user_profiles = [name for name in os.listdir("C:\\Users") if os.path.isdir(os.path.join("C:\\Users", name))]
        user_paths = [
            f"C:\\Users\\{user}\\AppData\\Local\\ShiftData" for user in user_profiles
        ] + [
            f"C:\\Users\\{user}\\AppData\\Local\\Programs\\Shift" for user in user_profiles
        ]

        action |= self._hash_executables(shift_paths)
        action |= self._hash_user_executables(user_profiles)
        action |= self._check_registry_keys()
        action |= self._terminate_processes(["shift", "ShiftUpdater"])
        action |= self._cleanup_paths(shift_paths + user_paths)

        self._log("Completed Shift Browser Cleanup")
        status = "succeeded" if action else "failed"
        message = "Shift Browser cleaned up successfully." if action else "No Shift Browser components were found."

        try:
            if action:
                # self.logger.result_success_message(f"{self.name}: {message}")
                self.logger.info(f"{self.name}: {message}")

            else:
                # self.logger.result_failed_message(f"{self.name}: {message}")
                self.logger.info(f"{self.name}: {message}")
        except Exception as e:
            self._log(f"[ERROR] Failed to log result message: {e}")

        return self._read_log(), action, status, message

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

    def _hash_executables(self, paths):
        action = False
        for path in paths:
            if os.path.exists(path):
                self._log(f"Scanning: {path}")
                for exe in Path(path).rglob("*.exe"):
                    try:
                        sha1 = hashlib.sha1()
                        with open(exe, "rb") as f:
                            while chunk := f.read(4096):
                                sha1.update(chunk)
                        self._log(f"{exe} SHA1: {sha1.hexdigest()}")
                        action = True
                    except Exception as e:
                        self._log(f"Error hashing {exe}: {e}")
            else:
                self._log(f"Path not found: {path}")
        return action

    def _silent_uninstall(self, app_name):
        try:
            self._log(f"Trying to uninstall {app_name} via WMIC...")
            command = f'wmic product where "name like \'%{app_name}%\'" call uninstall /nointeractive'
            result = subprocess.run(command, shell=True, capture_output=True, text=True)

            if "no instance(s) available" in result.stdout.lower():
                self._log(f"[INFO] No matching application found for '{app_name}' via WMIC.")
                return False
            elif "ReturnValue = 0" in result.stdout:
                self._log(f"[SUCCESS] Uninstalled {app_name}")
                self._log(result.stdout)
                return True
            else:
                self._log(f"[WARNING] Uninstall may have failed for {app_name}")
                self._log(result.stdout + result.stderr)
                return False
        except Exception as e:
            self._log(f"[ERROR] Failed to uninstall {app_name}: {e}")
            return False

    def _read_log(self):
        with open(self.log_path, "r", encoding="utf-8") as f:
            return f.read()

    def clean(self):
        self._log("Starting Wave Browser Cleanup")
        system_paths = [
            "C:\\Program Files\\WaveBrowser",
            "C:\\Program Files (x86)\\WaveBrowser",
            "C:\\Program Files\\Wavesor Software",
            "C:\\Program Files (x86)\\Wavesor Software",
            "C:\\Program Files\\Wave Browser",
            "C:\\Program Files (x86)\\Wave Browser",
            "C:\\Program Files\\WebNavigatorBrowser",
            "C:\\Program Files (x86)\\WebNavigatorBrowser"
        ]
        user_profiles = [u for u in os.listdir("C:\\Users")]
        user_templates = [
            "\\AppData\\Local\\Programs\\WaveBrowser",
            "\\AppData\\Local\\Programs\\Wavesor Software",
            "\\AppData\\Roaming\\WaveBrowser",
            "\\AppData\\Local\\WaveBrowser"
        ]
        user_paths = [f"C:\\Users\\{u}{template}" for u in user_profiles for template in user_templates]

        action = False
        action |= self._hash_executables(system_paths + user_paths)
        action |= self._silent_uninstall("Wave Browser")

        self._log("Completed Wave Browser Cleanup")
        status = "succeeded" if action else "failed"
        message = "Wave Browser cleaned up successfully." if action else "No Wave Browser components were found."

        try:
            if action:
                # self.logger.result_success_message(f"{self.name}: {message}")
                self.logger.info(f"{self.name}: {message}")
            else:
                # self.logger.result_failed_message(f"{self.name}: {message}")
                self.logger.info(f"{self.name}: {message}")
        except Exception as e:
            self._log(f"[ERROR] Failed to log result message: {e}")

        return self._read_log(), action, status, message

class BulkUninstaller:
    def __init__(self):
        self.logger = Logger()
        self.input = Input()
        self.cleaners = {
            "Shift Browser": ShiftBrowserCleaner(),
            "Wave Browser": WaveBrowserCleaner()
        }
        self.logs_by_app = {}
        self.status_by_app = {}
        self.message_by_app = {}

    def run(self):
        try:
            # app_names = self.input.get_value("UninstallAppNames_1750856640900")
            # input_list = "['Shift Browser']"
            input_list = self.input.get_value("UninstallAppNames_1750856640900")
            app_names = eval(input_list)
            if not isinstance(app_names, list):
                raise ValueError("Expected a list of app names.")

            for app in app_names:
                cleaner = self.cleaners.get(app)
                if cleaner:
                    self.logger.info(f"Running cleaner for: {app}")
                    log_text, action, status, _ = cleaner.clean()
                    self.logs_by_app[app] = log_text
                    self.status_by_app[app] = f"{app} : No {app} components were found." if status != "succeeded" else f"{app} : uninstalled successfully"
                    self.message_by_app[app] = f"Could not uninstall {app} please see the logs for more details" if status != "succeeded" else f"{app} components were removed successfully; see logs for details."
                else:
                    self.logger.warning(f"No cleaner defined for: {app}")
                    self.logs_by_app[app] = f"No cleaner available for: {app}"
                    self.status_by_app[app] = f"{app} : Could not uninstall {app} please see the logs for more details"
                    self.message_by_app[app] = f"Could not uninstall {app} please see the logs for more details"
        except Exception as e:
            self.status_by_app["BulkUninstaller"] = "BulkUninstaller : failed to get uninstalled successfully"
            self.message_by_app["BulkUninstaller"] = "BulkUninstaller cleanup failed"

        # Determine overall status
        status_values = list(self.message_by_app.values())
        if all("removed successfully" in s for s in status_values):
            overall_status = "Success"
        elif any("removed successfully" in s for s in status_values):
            overall_status = "Partial Success"
        else:
            overall_status = "Failed"

        try:
            for app in self.status_by_app:
                status = self.message_by_app.get(app, "")
                msg = self.status_by_app[app]
                if "removed successfully" in status:
                    self.logger.result_success_message(msg)
                else:
                    self.logger.result_failed_message(msg)
        except Exception as e:
            self.logger.info(f"[ERROR] BulkUninstaller result logging failed: {e}")

        self.logger.result_data({
            "overall_status": overall_status,
            "status": self.status_by_app,
            "status_message": self.message_by_app,
            "logs": self.logs_by_app
        })

if __name__ == "__main__":
    BulkUninstaller().run()