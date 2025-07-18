fn main() {
    // Tree-sitter language parsers are linked automatically by the crates
    println!("cargo:rerun-if-changed=build.rs");
}