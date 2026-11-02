// Windows (MSVC): иконка в exe — готовый ресурс assets/pass2fa.res (см. tools/gen-win-icon.sh),
// link.exe принимает .res напрямую, rc.exe/Windows SDK не нужны. Остальные платформы — ничего.
fn main() {
    println!("cargo:rerun-if-changed=assets/pass2fa.res");
    let os = std::env::var("CARGO_CFG_TARGET_OS").unwrap_or_default();
    let env = std::env::var("CARGO_CFG_TARGET_ENV").unwrap_or_default();
    if os == "windows" && env == "msvc" {
        let res = std::path::Path::new(&std::env::var("CARGO_MANIFEST_DIR").unwrap()).join("assets").join("pass2fa.res");
        println!("cargo:rustc-link-arg-bins={}", res.display());
    }
}
