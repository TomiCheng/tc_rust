//! Every engine API and crate-visible algorithm helper documents its timing.

fn missing_timing_docs(source: &str) -> (usize, Vec<String>) {
    let mut docs = String::new();
    let mut attribute_depth = 0_i32;
    let mut checked = 0;
    let mut missing = Vec::new();
    for line in source.lines().map(str::trim) {
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
        let engine_type = line.strip_prefix("pub struct ").is_some_and(|rest| {
            rest.split(|c: char| !c.is_ascii_alphanumeric() && c != '_')
                .next()
                .is_some_and(|name| name.ends_with("Engine"))
        });
        if engine_type
            || line.starts_with("pub fn ")
            || line.starts_with("pub const fn ")
            || line.starts_with("pub(crate) fn ")
            || line.starts_with("pub(crate) const fn ")
            || line.starts_with("pub(super) fn ")
            || line.starts_with("pub(super) const fn ")
            || line.starts_with("fn init")
            || line.starts_with("fn process_block(")
            || line.starts_with("fn block_size(")
            || line.starts_with("fn fmt(")
        {
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
pub struct SampleEngine {}
pub const fn new() {}
/// VARIABLE TIME.
#[inline]
pub fn accepted() {}
/// Constant time and variable time.
fn init() {}
fn process_block() {}
/// Constant time.
fn block_size() {}
fn fmt() {}
/// Constant time.
pub(crate) fn helper() {}
pub struct Parameters {}
";
    let (checked, missing) = missing_timing_docs(fixture);
    assert_eq!(checked, 8);
    assert_eq!(
        missing,
        [
            "pub const fn new() {}",
            "fn init() {}",
            "fn process_block() {}",
            "fn fmt() {}",
        ]
    );
}

#[test]
fn every_engine_api_and_crate_visible_helper_has_an_unambiguous_timing_doc() {
    for (name, source) in [
        ("cipher.rs", include_str!("../src/cipher.rs")),
        ("rc5_32_engine.rs", include_str!("../src/rc5_32_engine.rs")),
        ("rc5_64_engine.rs", include_str!("../src/rc5_64_engine.rs")),
        ("params.rs", include_str!("../src/params.rs")),
    ] {
        let (checked, missing) = missing_timing_docs(source);
        assert!(checked > 0, "no declarations scanned in {name}");
        assert!(
            missing.is_empty(),
            "missing timing docs in {name}: {missing:?}"
        );
    }
}
