

fn encryption(efile: &str, etxt: Vec<u8>, ekey: &[u8]) 
{

    let mut encdat = Vec::new();
    for (index, octet) in etxt.iter().enumerate()
    {
        encdat.push(octet ^ ekey[index % ekey.len()]);
    }

    std::fs::write("Encry.md", encdat).unwrap(); 
    std::fs::write("Key.md", ekey).unwrap();
    // std::fs::remove_file(efile).unwrap();   ||| j'attend pour faire des delet 
    println!("File Encrypted");
}

fn main() 
{
    let file = "test.md";


    let txt = std::fs::read(file)
        .expect("\nError: No file Found");

    let key = b"RUST";

    
    println!("Size of secret.md -> {}", txt.len());
    println!("\n The content of secret.md: \n{:?}", txt);

    println!("\n\n====================================================\n\n");

    encryption(&file, txt, key);
}

