//! Every public type and method, every method an encoding implements, and
//! every helper it runs documents its timing.

/// Declaration prefixes whose doc comments must state their timing.
const DECLARATIONS: &[&str] = &[
    "pub struct ",
    "pub fn ",
    "pub const fn ",
    "fn init(",
    "fn input_block_size(",
    "fn output_block_size(",
    "fn process_block(",
    "fn fmt(",
    "fn encode(",
    "fn decode(",
    "fn shadow(",
    "fn subtract_from(",
    "fn to_be_bytes",
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
            // Lines join with a space, so that a classification may wrap.
            docs.push_str(comment.trim());
            docs.push(' ');
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
fn shadow() {}
fn to_be_bytes<T>() {}
/// Wrapped, constant
/// time.
fn fmt() {}
impl Trait for Type {
    fn drop() {}
}
#[cfg(test)]
mod tests {
    fn shadow() {}
}
";
    let (checked, missing) = missing_timing_docs(fixture);
    assert_eq!(checked, 6);
    assert_eq!(
        missing,
        [
            "pub struct Undocumented;",
            "fn shadow() {}",
            "fn to_be_bytes<T>() {}",
        ]
    );
}

#[test]
fn every_public_api_and_secret_path_has_an_unambiguous_timing_doc() {
    for (name, source) in [
        ("error.rs", include_str!("../src/error.rs")),
        (
            "iso9796d1_encoding.rs",
            include_str!("../src/iso9796d1_encoding.rs"),
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
