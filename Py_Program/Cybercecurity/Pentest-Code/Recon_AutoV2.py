import sys
import shutil 
import subprocess

ip = input("Select ip: ")

jls_extract_var = "docker"
r = subprocess.run(["sudo", "dnf", "install", jls_extract_var], capture_output = True, text = True)

print(r.stdout)




