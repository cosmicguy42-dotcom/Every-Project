fn main() {
    println!("cargo:rerun-if-changed=native/src/ouija_secure_mem.c");
    println!("cargo:rerun-if-changed=native/include/ouija_core.h");
    println!("cargo:rerun-if-changed=native/asm/ouija_crypto_x86_64.s");

    let mut build = cc::Build::new();
    build
        .file("native/src/ouija_secure_mem.c")
        .file("native/asm/ouija_crypto_x86_64.s")
        .include("native/include")
        .opt_level(3)
        .flag("-fstack-protector-strong")
        .flag("-D_FORTIFY_SOURCE=2")
        .flag("-fPIE");

    // Compile native C and ASM into static library
    build.compile("ouija_native_core");

    println!("cargo:rustc-link-lib=static=ouija_native_core");
}
