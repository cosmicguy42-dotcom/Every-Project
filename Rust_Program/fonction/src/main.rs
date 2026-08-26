use std::io;

fn clc(nbr: i32) -> bool
{
    nbr % 3 == 0 && nbr %5 == 0
}
fn encry(xkey: u8) 
{
    print!("Message: ");

    let mut input = String::new();
    io::stdin()
        .read_line(&mut input)
        .expect("Error while reading input");
    

    print!("\nEncrypted message: ");

    for b in input.trim().bytes() 
    {
        let xor = b ^ xkey;
        print!("{}", xor);
    }
    print!("\n")
}

fn main() 
{
    let key = 33;
    let x = 90;
    if clc(x) 
    {
        println!("{} is a multiple of 3 and 5", x);
    }
    else 
    {
        println!("{} is not a multiple of 3 and 5", x)
    }
    encry(key);

}
