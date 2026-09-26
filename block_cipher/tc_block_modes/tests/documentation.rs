//! Every public type and method, and every trait method a mode or container
//! implements, documents its timing.

/// 掃描需要標明時間性質的宣告前綴。
const DECLARATIONS: &[&str] = &[
    "pub struct ",
    "pub fn ",
    "pub const fn ",
    "pub(crate) fn ",
    "fn init(",
    "fn process_block(",
    "fn block_size(",
    "fn fmt(",
    "fn underlying_cipher(",
    "fn is_partial_block_okay(",
    "fn reset(",
    "fn key(",
    "fn iv(",
    "fn zeroize(",
    "fn increment_be(",
];

fn missing_timing_docs(source: &str) -> (usize, Vec<String>) {
    let mut docs = String::new();
    let mut attribute_depth = 0_i32;
    let mut checked = 0;
    let mut missing = Vec::new();
    for line in source.lines().map(str::trim) {
        // 測試模組裡的輔助型別不在契約內。
        if line == "#[cfg(test)]" {
            break;
        }
        if let Some(comment) = line.strip_prefix("///") {
            docs.push_str(comment);
            docs.push('\n');
            continue;
        }
        if line.starts_with("#[") || attribute_depth > 0 {
            attribute_depth += line.chars().filter(|&c| c == '[').count() as i32;
            attribute_depth -= line.chars().filter(|&c| c == ']').count() as i32;
            continue;
        }
        if line.is_empty() || line.starts_with("//") {
            continue;
        }
        if DECLARATIONS.iter().any(|prefix| line.starts_with(prefix)) {
            checked += 1;
            let docs = docs.to_ascii_lowercase();
            if docs.contains("constant time") == docs.contains("variable time") {
                missing.push(line.to_owned());
            }
        }
        docs.clear();
    }
    (checked, missing)
}

#[test]
fn the_scanner_requires_exactly_one_timing_classification_on_each_declaration() {
    let fixture = "\
/// Constant time.
pub struct Documented {}
pub struct Undocumented {}
/// VARIABLE TIME.
#[inline]
pub fn accepted() {}
/// Constant time and variable time.
fn init() {}
fn process_block() {}
/// Constant time when the engine's is.
fn reset() {}
fn zeroize() {}
impl Trait for Type {
    fn drop() {}
}
#[cfg(test)]
mod tests {
    fn key() {}
}
";
    let (checked, missing) = missing_timing_docs(fixture);
    assert_eq!(checked, 7);
    assert_eq!(
        missing,
        [
            "pub struct Undocumented {}",
            "fn init() {}",
            "fn process_block() {}",
            "fn zeroize() {}",
        ]
    );
}

#[test]
fn every_public_api_and_implemented_trait_method_has_an_unambiguous_timing_doc() {
    for (name, source) in [
        ("cbc/fixed_mode.rs", include_str!("../src/cbc/fixed_mode.rs")),
        ("cbc/mode.rs", include_str!("../src/cbc/mode.rs")),
        ("cfb/fixed_mode.rs", include_str!("../src/cfb/fixed_mode.rs")),
        ("cfb/mode.rs", include_str!("../src/cfb/mode.rs")),
        ("ctr.rs", include_str!("../src/ctr.rs")),
        ("ctr/fixed_mode.rs", include_str!("../src/ctr/fixed_mode.rs")),
        ("ctr/mode.rs", include_str!("../src/ctr/mode.rs")),
        ("ecb.rs", include_str!("../src/ecb.rs")),
        ("ofb/fixed_mode.rs", include_str!("../src/ofb/fixed_mode.rs")),
        ("ofb/mode.rs", include_str!("../src/ofb/mode.rs")),
        (
            "error/block_mode_error.rs",
            include_str!("../src/error/block_mode_error.rs"),
        ),
        (
            "error/block_mode_init_error.rs",
            include_str!("../src/error/block_mode_init_error.rs"),
        ),
        (
            "params/key_with_iv_fixed.rs",
            include_str!("../src/params/key_with_iv_fixed.rs"),
        ),
        (
            "params/key_with_iv_owned.rs",
            include_str!("../src/params/key_with_iv_owned.rs"),
        ),
        (
            "params/key_with_iv_ref.rs",
            include_str!("../src/params/key_with_iv_ref.rs"),
        ),
        (
            "traits/block_cipher_mode.rs",
            include_str!("../src/traits/block_cipher_mode.rs"),
        ),
        ("traits/iv.rs", include_str!("../src/traits/iv.rs")),
    ] {
        let (checked, missing) = missing_timing_docs(source);
        assert!(checked > 0, "no declarations scanned in {name}");
        assert!(
            missing.is_empty(),
            "missing timing docs in {name}: {missing:?}"
        );
    }
}
