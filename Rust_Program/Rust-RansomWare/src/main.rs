use std::fs;
use rand::RngExt;
use std::path::{Path, PathBuf};

fn encryption(fpath: PathBuf, etxt: Vec<u8>) -> std::io::Result<()>
{
    let mut encdat = Vec::with_capacity(etxt.len());        
    let mut gnr = rand::rng();
    let mut fkey = Vec::with_capacity(etxt.len());



    for byte in etxt 
    {
        let roct: u8 = gnr.random();
    
        encdat.push(roct ^ byte);
        fkey.push(roct);
    }

    let fsys = fpath.file_name().unwrap().to_string_lossy(); 
    let penc = format!("{}.enc", fsys);
    let pkey = format!("{}.key", fsys);


    fs::write(&pkey, fkey)?;
    fs::write(&penc, encdat)?;
    fs::remove_file(&fpath)?;                          

    Ok(())
}


fn main() -> Result<(), Box<dyn std::error::Error>>
{
    let rfile = Path::new("./Test");

    for element in fs::read_dir(rfile)? 
    {

        let element = element?;
        let fpath = element.path();



        if fpath.is_file() 
        {
            println!("file detected: {:?}", fpath);
        

            let txt = std::fs::read(&fpath)?;    

            if let Err(e) = encryption(fpath, txt)
            {
                eprintln!("Error while encypting file: {}", e);
            }
        }
    }
    Ok(())
}

