use std::fs;
use std::path::Path;

fn rfile() -> std::io::Result<()>
{
    let file = Path::new("Test_Folder");

    for element in fs::read_dir(file)? 
    {

        let element = element?;
        let fpath = element.path();



        if fpath.is_file() 
        {
            println!("file detected: {:?}", fpath);
        

        let txt = std::fs::read_to_string(&fpath).unwrap();


        println!("Size of {:?} -> {}", element, txt.len());
        println!("\n The content of {:?}: \n{}", element, txt);


        println!("\n\n===================================================================\n\n");
    
        }
    }

    Ok(())
}

fn main() 
{
    rfile().unwrap();
}
