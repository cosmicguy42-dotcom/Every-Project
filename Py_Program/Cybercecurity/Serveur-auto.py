
import shutil
import sys 
import subprocess

#ip = input("Select Program: ")

data_program = ["docker", "kubernetes", "nmap"]


print(data_program[2])


for i in data_program:

    program = data_program[i]

    dockins = shutil.which(program)

    if not dockins:
        resp = str(input(f"{program} is not install\nDo you whant to install docker: Y/N: ").upper())

        if resp == "Y":
            r = subprocess.run(["sudo", "dnf", "install", program, "--nocomfirm"], capture_output = True, text = True)
            pritn(r.stdout)

        elif resp == "N":
            print("Installation cancelled")


    else:
        print(f"{program} is installed")

