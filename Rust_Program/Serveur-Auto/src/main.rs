use std::process::Command;


fn main() 
{

    let dat = [
        "docker", "nmap", "ghidra"
    ];

    for program in dat 
    {
        println!("Program to install {}", program);

        let p = Command::new("/usr/bin/dnf")
            .args(["install", program, "-y"])
            .output()
            .expect("Failed to execute the install");


        let pstr = String::from_utf8_lossy(&p.stdout);
        let perr = String::from_utf8_lossy(&p.stderr);

        println!("{}", pstr);

        if !p.status.success() 
        {
            println!("Error while installing: {}\n\n{}", program, perr);
        }
    }
}
