use std::process::Command;
use std::env;



fn scan(ip: &str)
{
    let sc = Command::new("namp")
        .args([
            "-p",
            "80",
            ip
        ])
        .output()
        .expect("Couldn't execute nmap");

    let result = String::from_utf8_lossy(&sc.stdout);


    if result.contains("filtered") 
    {
        let inv_sc = Command::new("nmap")
            .args([
                "-sV",
                "-Pn",
                "-T4",
                "--script", "vuln",
                ip
            ])
            .output()
            .expect("Couldn't do a scan");

        let result = String::from_utf8_lossy(&inv_sc.stdout);
        println!("{}", result);
    }

    else 
    {
        let nor_sc = Command::new("namp")
            .args([
                "-T5",
                "--script", "vuln",
                ip
            ])
            .output()
            .expect("Couldn't do a scan");

            let result = String::from_utf8_lossy(&nor_sc.stdout);
            println!("{}", result);
    }


}


fn main()
{

    println!(r#"
 .S_sSSs     .S_SsS_S.    .S_SSSs     .S_sSSs    
 .SS~YS%%b   .SS~S*S~SS.  .SS~SSSSS   .SS~YS%%b   
 S%S   `S%b  S%S `Y' S%S  S%S   SSSS  S%S   `S%b  
 S%S    S%S  S%S     S%S  S%S    S%S  S%S    S%S  
 S%S    d*S  S%S     S%S  S%S SSSS%S  S%S    d*S  
 S&S   .S*S  S&S     S&S  S&S  SSS%S  S&S   .S*S  
 S&S_sdSSS   S&S     S&S  S&S    S&S  S&S_sdSSS   
 S&S~YSY%b   S&S     S&S  S&S    S&S  S&S~YSSY    
 S*S   `S%b  S*S     S*S  S*S    S&S  S*S         
 S*S    S%S  S*S     S*S  S*S    S*S  S*S         
 S*S    S&S  S*S     S*S  S*S    S*S  S*S         
 S*S    SSS  SSS     S*S  SSS    S*S  S*S         
 SP                  SP          SP   SP          
 Y                   Y           Y    Y           
"#);

    println!("[+] Please enter an IP: ");

    let buffer: Vec<String> = env::args().collect();
    if buffer.len() < 2 
    {
        eprintln!("usage: Ip-Sniff <Ip>");
        return;
    }

    if &buffer[1] == "-sn"
    { 
        println!("\n[+] Starting a network Scan [+]\n");
    
        println!("=================================");
        println!("====NOT WORKING RIGHT NOW========");
        println!("=================================");
    }

    else if &buffer[1] == "help" 
    {
        eprintln!("[===] COMMANDS WORKING RIGHT NOW [===]\n");
        eprintln!("\n[-UP-] help ---> Get a list of the commands with their status");
        eprintln!("[-DOWN-] -sn ---> Scan local network for any ip");
        eprintln!("[-UP-] <ip> ---> Scan for the firewall then do a smart scan ");

    }
    
    
    else { scan(&buffer[1]); }


}
