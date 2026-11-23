//! Embeds the K9 program icon.
fn main() {
    println!("cargo:rerun-if-changed=build.rs");
    k9_res::embed_icon();
}
