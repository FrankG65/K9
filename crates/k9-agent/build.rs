//! Embeds a Common-Controls-6 manifest so the native Meldefenster
//! (TaskDialogIndirect) is available in this program, and the K9 program icon.
//! Also the build time and commit for the version tooltip in the dashboard.
fn main() {
    println!("cargo:rerun-if-changed=build.rs");
    // 1 = program icon, 2..5 = tray icon by state (normal, new finding, critical, service stopped).
    k9_res::embed_icons(&[(1, "k9.ico"), (2, "k9-tray-normal.ico"), (3, "k9-tray-warnung.ico"), (4, "k9-tray-kritisch.ico"), (5, "k9-tray-gestoppt.ico")]);
    build_info();
    println!("cargo:rustc-link-arg-bins=/MANIFEST:EMBED");
    println!("cargo:rustc-link-arg-bins=/MANIFESTDEPENDENCY:type='win32' name='Microsoft.Windows.Common-Controls' version='6.0.0.0' processorArchitecture='*' publicKeyToken='6595b64144ccf1df' language='*'");
}
/// K9_BUILD_TIME (local time) and K9_COMMIT: the short commit only if the working tree has no
/// uncommitted changes to tracked files, otherwise empty (the build is then not exactly that commit).
/// Runs again after every commit or checkout (HEAD and branch refs are watched).
fn build_info() {
    let root = std::path::PathBuf::from(std::env::var("CARGO_MANIFEST_DIR").unwrap()).join("..").join("..");
    for p in [".git/HEAD", ".git/refs/heads", ".git/packed-refs"] {
        println!("cargo:rerun-if-changed={}", root.join(p).display());
    }
    let git = |args: &[&str]| {
        std::process::Command::new("git")
            .args(args)
            .current_dir(&root)
            .output()
            .ok()
            .filter(|o| o.status.success())
            .map(|o| String::from_utf8_lossy(&o.stdout).trim().to_string())
    };
    let clean = git(&["status", "--porcelain", "--untracked-files=no"]).is_some_and(|s| s.is_empty());
    let commit = if clean { git(&["rev-parse", "--short", "HEAD"]).unwrap_or_default() } else { String::new() };
    println!("cargo:rustc-env=K9_COMMIT={commit}");
    println!("cargo:rustc-env=K9_BUILD_TIME={}", chrono::Local::now().format("%d.%m.%Y %H:%M"));
}
