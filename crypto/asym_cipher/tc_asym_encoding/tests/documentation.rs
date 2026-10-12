//! Every public type and method, every method an encoding implements, and
//! every helper on a secret path documents its timing.

/// Declaration prefixes whose doc comments must state their timing.
const DECLARATIONS: &[&str] = &[
    "pub struct ",
    "pub fn ",
    "pub const fn ",
    "pub(super) fn ",
    "pub(super) const fn ",
    "fn init(",
    "fn input_block_size(",
    "fn output_block_size(",
    "fn process_block(",
    "fn fmt(",
    "fn encode(",
    "fn decode(",
    "fn decode_or_random(",
    "fn decode_whole",
    "fn fill_non_zero(",
    "fn check(",
    "fn check_of_length(",
];

fn missing_timing_docs(source: &str) -> (usize, Vec<String>) {
    let mut docs = String::new();
    let mut attribute_depth = 0_i32;
    let mut checked = 0;
    let mut missing = Vec::new();
    for line in source.lines().map(str::trim) {
        // Helpers inside test modules are not part of the contract.
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
pub struct Documented;
pub struct Undocumented;
/// VARIABLE TIME.
#[inline]
pub fn accepted() {}
/// Constant time and variable time.
fn check() {}
fn decode_whole<X>() {}
/// Constant time.
fn fmt() {}
impl Trait for Type {
    fn drop() {}
}
#[cfg(test)]
mod tests {
    fn check() {}
}
";
    let (checked, missing) = missing_timing_docs(fixture);
    assert_eq!(checked, 6);
    assert_eq!(
        missing,
        [
            "pub struct Undocumented;",
            "fn check() {}",
            "fn decode_whole<X>() {}",
        ]
    );
}

#[test]
fn every_public_api_and_secret_path_has_an_unambiguous_timing_doc() {
    for (name, source) in [
        ("error.rs", include_str!("../src/error.rs")),
        (
            "pkcs1_encoding/encoder.rs",
            include_str!("../src/pkcs1_encoding/encoder.rs"),
        ),
        (
            "pkcs1_encoding/fixed.rs",
            include_str!("../src/pkcs1_encoding/fixed.rs"),
        ),
        (
            "pkcs1_encoding/heap.rs",
            include_str!("../src/pkcs1_encoding/heap.rs"),
        ),
    ] {
        let (checked, missing) = missing_timing_docs(source);
        assert!(checked > 0, "no declarations scanned in {name}");
        assert!(
            missing.is_empty(),
            "missing timing docs in {name}: {missing:?}"
        );
    }
}
