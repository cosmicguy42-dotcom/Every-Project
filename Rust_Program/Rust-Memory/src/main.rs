use num_bigint::BigRng010;
use num_bigint::BigUint;

fn main() {
    let mut gnr = rand::rng();
    let a = BigUint::from(2u32);
    let max = &a.pow(256) - &a.pow(32) - &BigUint::from(977u32);

    let d = gnr.gen_biguint_range(&BigUint::ZERO, &max);

    println!("\n{}", d);
}
