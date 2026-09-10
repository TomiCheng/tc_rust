//! 公開原語必須交代時間性質，並提供可編譯的使用範例。

fn missing_public_docs(source: &str) -> (usize, Vec<String>) {
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
        if line.starts_with("pub fn ") || line.starts_with("pub const ") {
            checked += 1;
            if !(docs.contains("常數時間") || docs.contains("變動時間"))
                || !docs.contains("# Examples")
            {
                missing.push(line.to_owned());
            }
        }
        docs.clear();
    }
    (checked, missing)
}

#[test]
fn every_public_primitive_documents_its_timing_and_has_an_example() {
    // const fn 也必須被檢查，不能誤用前一個項目的文件。
    let incomplete = "/// 常數時間\n/// # Examples\npub const SIZE: usize = 32;\n\
                      pub const fn precompute() {}";
    let (checked, missing) = missing_public_docs(incomplete);
    assert_eq!(checked, 2);
    assert_eq!(missing, ["pub const fn precompute() {}"]);

    for (name, source) in [
        ("x25519.rs", include_str!("../src/x25519.rs")),
        ("x448.rs", include_str!("../src/x448.rs")),
    ] {
        let (checked, missing) = missing_public_docs(source);
        assert!(checked > 0, "no public declarations scanned in {name}");
        assert!(
            missing.is_empty(),
            "missing API docs in {name}: {missing:?}"
        );
    }
}
