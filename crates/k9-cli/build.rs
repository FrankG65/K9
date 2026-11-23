//! Embeds a Common-Controls-6 manifest so the native Meldefenster
//! (TaskDialogIndirect) is available in this program, and the K9 program icon.
fn main() {
    println!("cargo:rerun-if-changed=build.rs");
    k9_res::embed_icon();
    println!("cargo:rustc-link-arg-bins=/MANIFEST:EMBED");
    println!("cargo:rustc-link-arg-bins=/MANIFESTDEPENDENCY:type='win32' name='Microsoft.Windows.Common-Controls' version='6.0.0.0' processorArchitecture='*' publicKeyToken='6595b64144ccf1df' language='*'");
}