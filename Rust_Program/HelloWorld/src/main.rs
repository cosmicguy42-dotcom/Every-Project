
fn main() 
{
    let x = 5;
    let h = String::from("Klemen");
    let mut z = 67;
    println!("\nFirst z = {}", z);
    
    if z > 50 {
        println!("z was {} and now 12 digit lower", z);
        let lowerz = z / 2;
        println!("Now z = {}", lowerz);
    }
    else if z == 50 {
        println!("z = 50");
    }
    else {
        println!("z was {} and now 45", z);
        z = 45;
        println!("Z = 45");
    }
    println!("Hello {}, {} and new z, {}\n", x, h, z);


    for i in 1..=5 {
            if i >= 5 {
            println!("Happy New Year!!!")
        }
        else {
            println!("\nNew year in {}", i);
        }
    }
}
