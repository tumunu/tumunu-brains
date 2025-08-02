use rustc_version::version;

fn main() {
    println!("cargo:rerun-if-changed=build.rs");
    
    if let Ok(ver) = version() {
        println!("cargo:rustc-env=RUSTC_VERSION={}", ver);
    }
}