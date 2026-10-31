const METHODS: [&str; 10] = [
    "fmt",
    "init",
    "max_signature_size",
    "update",
    "generate_signature",
    "verify_signature",
    "reset",
    "generate",
    "signature_block",
    "write_be",
];

fn checked(line: &str) -> bool {
    if line.starts_with("pub fn ") || line.starts_with("pub(crate) fn ") {
        return true;
    }
    line.strip_prefix("fn ")
        .and_then(|rest| rest.split(['(', '<']).next())
        .is_some_and(|name| METHODS.contains(&name))
}

fn missing_timing_docs(source: &str) -> (usize, Vec<String>) {
    let mut docs = String::new();
    let mut attribute_depth = 0_i32;
    let mut count = 0;
    let mut missing = Vec::new();
    let mut in_tests = false;
    for line in source.lines().map(str::trim) {
        if line == "mod tests {" {
            in_tests = true;
        }
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
        if !in_tests && checked(line) {
            count += 1;
            if docs.contains("常數時間") == docs.contains("變動時間") {
                missing.push(line.to_owned());
            }
        }
        docs.clear();
    }
    (count, missing)
}

/// 只掃描 PSS 與 X9.31 的檔案；`RsaDigestSigner` 早於這個慣例，doc 是英文。
#[test]
fn every_public_method_and_helper_states_constant_or_variable_time() {
    for (name, source, minimum) in [
        ("pss_signer.rs", include_str!("../src/pss_signer.rs"), 12),
        (
            "mask_generator.rs",
            include_str!("../src/mask_generator.rs"),
            4,
        ),
        ("pss_error.rs", include_str!("../src/pss_error.rs"), 1),
        ("x931_signer.rs", include_str!("../src/x931_signer.rs"), 10),
        ("x931_error.rs", include_str!("../src/x931_error.rs"), 1),
        ("iso_trailers.rs", include_str!("../src/iso_trailers.rs"), 1),
    ] {
        let (count, missing) = missing_timing_docs(source);
        assert!(count >= minimum, "only {count} methods scanned in {name}");
        assert!(
            missing.is_empty(),
            "missing timing docs in {name}: {missing:?}"
        );
    }
}
