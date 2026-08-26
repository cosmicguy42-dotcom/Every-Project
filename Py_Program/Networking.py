import subprocess
import shutil
import sys


total_gb = shutil.disk_usage("/").total / (1024**3)
free_gb = shutil.disk_usage("/").free / (1024**3)
Ydck = shutil.which("docker")

if not Ydck:
    confirm = input("Docker not installed \n Do you whant to install docker Y/N:  ").strip().upper()
    
    if confirm == "Y":
        subprocess.run(["sudo", "pacman", "-S", "docker", "--noconfirm"], capture_output = True, text = True)

    elif confirm == "N":
        print("Installation cancelled")

    else:
        raise ValueError("Input Error")

else:
    print(f"docker is installed: {subprocess.run(['docker', 'info'], capture_output = True, text = True)}")        



print(f"Disk Usage: Total = {total_gb:.2f} GB | Free = {free_gb:.2f} GB")