const METHODS: [&str; 10] = [
    "encoded_len",
    "decoded_len",
    "encode",
    "decode",
    "encode_to_vec",
    "decode_to_vec",
    "encode_to",
    "decode_to",
    "encode_from",
    "decode_from",
];

fn checked(line: &str) -> bool {
    if line.starts_with("pub fn ") || line.starts_with("fn fmt(") {
        return true;
    }
    line.strip_prefix("fn ")
        .and_then(|rest| rest.split('(').next())
        .is_some_and(|name| METHODS.contains(&name))
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
fn every_public_method_states_constant_or_variable_time() {
    for (name, source, minimum) in [
        (
            "traits/encoder.rs",
            include_str!("../src/traits/encoder.rs"),
            10,
        ),
        (
            "errors/encoder_error.rs",
            include_str!("../src/errors/encoder_error.rs"),
            1,
        ),
        ("hex/encoder.rs", include_str!("../src/hex/encoder.rs"), 5),
        (
            "base64/encoder.rs",
            include_str!("../src/base64/encoder.rs"),
            5,
        ),
    ] {
        let (count, missing) = missing_timing_docs(source);
        assert!(count >= minimum, "only {count} methods scanned in {name}");
        assert!(
            missing.is_empty(),
            "missing timing docs in {name}: {missing:?}"
        );
    }
}
