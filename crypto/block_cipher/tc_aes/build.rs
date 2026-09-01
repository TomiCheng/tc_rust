//! Sets the `aes_ni` cfg when the AES-NI backend can be compiled in.
//!
//! Whether that backend exists depends on the target architecture *and* on a
//! feature, which is a condition `#[cfg]` cannot express on its own. Deriving
//! it once here keeps `#[cfg(aes_ni)]` short at each of its use sites.

fn main() {
    println!("cargo::rerun-if-changed=build.rs");
    println!("cargo::rustc-check-cfg=cfg(aes_ni)");

    let forced_portable = std::env::var_os("CARGO_FEATURE_FORCE_PORTABLE_AES").is_some();
    let arch = std::env::var("CARGO_CFG_TARGET_ARCH").unwrap_or_default();

    if !forced_portable && matches!(arch.as_str(), "x86" | "x86_64") {
        println!("cargo::rustc-cfg=aes_ni");
    }
}
