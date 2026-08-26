use std::io;
use rand::Rng;

fn encryption(fpath: &str, etxt: Vec<u8>) 
{
    let mut encdat = Vec::new();
    let mut gnr = rand::thread_rng();
    
    let mut fkey = Vec::new();
    for index in 0..etxt.len()
    {
        let roct: u8 = gnr.gen();
        

        encdat.push(roct ^ etxt[index]);
        fkey.push(roct)
    }

    std::fs::write("Decryption-Key.md", fkey).unwrap();
    std::fs::write("secret_enc.md", encdat).unwrap();
    // std::fs::remove_file(efile).unwrap();   ||| j'attend pour faire des delet 
    println!("File Encrypted");
}

fn main() 
{
    let file = "secret.md";
    let txt = std::fs::read(file).unwrap();

    
    println!("Size of secret.md -> {}", txt.len());
    println!("\n The content of secret.md: \n{:?}", txt);

    println!("\n\n====================================================\n\n");

    encryption(file, txt);
}
