"""
SentinelGrid Defense - Desktop Shortcut Installer
Creates a native Windows Desktop shortcut with custom icon and app-mode launcher.
"""
import os
import sys
import subprocess

def get_desktop_paths():
    desktops = []
    
    # 1. Standard userprofile Desktop
    userprofile = os.environ.get("USERPROFILE", "C:\\Users\\Sumit")
    standard_desktop = os.path.join(userprofile, "Desktop")
    if os.path.exists(standard_desktop):
        desktops.append(standard_desktop)

    # 2. OneDrive Desktop (Common on Windows 10/11)
    onedrive_desktop = os.path.join(userprofile, "OneDrive", "Desktop")
    if os.path.exists(onedrive_desktop) and onedrive_desktop not in desktops:
        desktops.append(onedrive_desktop)

    # 3. Query via PowerShell to be 100% sure
    try:
        ps_out = subprocess.check_output(
            ["powershell", "-NoProfile", "-Command", "[Environment]::GetFolderPath('Desktop')"],
            text=True
        ).strip()
        if ps_out and os.path.exists(ps_out) and ps_out not in desktops:
            desktops.append(ps_out)
    except Exception:
        pass

    return desktops

def create_shortcut_powershell(target_path, arguments, icon_location, working_dir, shortcut_path, description):
    ps_script = f"""
    $WshShell = New-Object -ComObject WScript.Shell
    $Shortcut = $WshShell.CreateShortcut("{shortcut_path}")
    $Shortcut.TargetPath = "{target_path}"
    $Shortcut.Arguments = '{arguments}'
    $Shortcut.WorkingDirectory = "{working_dir}"
    $Shortcut.IconLocation = "{icon_location}"
    $Shortcut.Description = "{description}"
    $Shortcut.Save()
    """
    cmd = ["powershell", "-NoProfile", "-Command", ps_script]
    result = subprocess.run(cmd, capture_output=True, text=True)
    return result.returncode == 0

def main():
    workspace = os.path.dirname(os.path.abspath(__file__))
    launcher_pyw = os.path.join(workspace, "launch_app.pyw")
    ico_path = os.path.join(workspace, "sentinelgrid.ico")
    
    py_dir = os.path.dirname(sys.executable)
    pythonw_path = os.path.join(py_dir, "pythonw.exe")
    if not os.path.exists(pythonw_path):
        pythonw_path = sys.executable

    desktops = get_desktop_paths()
    print(f"Detected Desktop locations: {desktops}")

    for desktop in desktops:
        lnk_path = os.path.join(desktop, "SentinelGrid Defense.lnk")
        args_str = f'"{launcher_pyw}"'
        icon_loc = f"{ico_path},0"
        
        success = create_shortcut_powershell(
            target_path=pythonw_path,
            arguments=args_str,
            icon_location=icon_loc,
            working_dir=workspace,
            shortcut_path=lnk_path,
            description="SentinelGrid Defense - AI Endpoint Security Suite"
        )
        if success and os.path.exists(lnk_path):
            print(f"[SUCCESS] Created Desktop Shortcut: {lnk_path}")
        else:
            print(f"[FAIL] Could not create shortcut at: {lnk_path}")

    # Also create a handy .bat in the workspace and on Desktop
    bat_content = f"""@echo off
title SentinelGrid Defense Launcher
start "" "{pythonw_path}" "{launcher_pyw}"
exit
"""
    workspace_bat = os.path.join(workspace, "Launch_SentinelGrid.bat")
    with open(workspace_bat, "w") as f:
        f.write(bat_content)
    print(f"[SUCCESS] Created workspace launcher script: {workspace_bat}")

if __name__ == "__main__":
    main()
