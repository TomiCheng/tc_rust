//! 每個公開方法與 crate 內輔助函式的 doc 都標明常數時間或變動時間，二選一。

fn checked(line: &str) -> bool {
    [
        "pub fn ",
        "pub(crate) fn ",
        "pub const fn ",
        "pub(crate) const fn ",
    ]
    .iter()
    .any(|prefix| line.starts_with(prefix))
}

fn missing_timing_docs(source: &str) -> (usize, Vec<String>) {
    let mut docs = String::new();
    let mut attribute_depth = 0_i32;
    let mut count = 0;
    let mut missing = Vec::new();
    for line in source.lines().map(str::trim) {
        if let Some(comment) = line.strip_prefix("///") {
            docs.push_str(comment.trim());
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
        if checked(line) {
            count += 1;
            if docs.contains("常數時間") == docs.contains("變動時間") {
                missing.push(line.to_owned());
            }
        }
        docs.clear();
    }
    (count, missing)
}

#[test]
fn every_public_method_and_helper_states_constant_or_variable_time() {
    for (name, source, minimum) in [
        (
            "brainpool_named_curve.rs",
            include_str!("../src/brainpool_named_curve.rs"),
            5,
        ),
        ("hex.rs", include_str!("../src/hex.rs"), 1),
    ] {
        let (count, missing) = missing_timing_docs(source);
        assert!(count >= minimum, "only {count} methods scanned in {name}");
        assert!(
            missing.is_empty(),
            "missing timing docs in {name}: {missing:?}"
        );
    }
}
