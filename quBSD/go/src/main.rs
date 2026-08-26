use std::{io, env};
use std::io::stdin;
use std::process::Command;
use std::path::Path;

fn main() -> io::Result<()>
{
    loop
    {
        let mut buffer = String::new();
        let stdin = stdin();
        stdin.read_line(&mut buffer);
    
        let input = buffer.trim();
        
        if input.starts_with("go") 
        {
            if let Some(folder) = input.split_whitespace().nth(1) 
            {
            
                let fpath = Path::new(folder);
                assert!(env::set_current_dir(fpath).is_ok());
            
                let dir = Command::new("pwd").output().expect("Error Failed to print the directory");
                println!("changed directory to {}", String::from_utf8_lossy(&dir.stdout));
            }
        }
    } 
}
