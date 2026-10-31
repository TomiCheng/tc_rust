const METHODS: [&str; 13] = [
    "fmt",
    "init",
    "drop",
    "is_private_key",
    "generate_key_pair",
    "encapsulation_length",
    "secret_length",
    "encapsulate",
    "decapsulate",
    "mul_mont",
    "matrix",
    "sample_ntt",
    "noise_vector",
];

fn checked(line: &str) -> bool {
    if line.starts_with("pub fn ")
        || line.starts_with("pub const fn ")
        || line.starts_with("pub(crate) fn ")
        || line.starts_with("pub(crate) const fn ")
    {
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

#[test]
fn every_public_method_and_helper_states_constant_or_variable_time() {
    for (name, source, minimum) in [
        ("cbd.rs", include_str!("../src/cbd.rs"), 2),
        ("engine.rs", include_str!("../src/engine.rs"), 5),
        ("error.rs", include_str!("../src/error.rs"), 1),
        ("indcpa.rs", include_str!("../src/indcpa.rs"), 7),
        ("kem.rs", include_str!("../src/kem.rs"), 10),
        (
            "key_pair_generator.rs",
            include_str!("../src/key_pair_generator.rs"),
            5,
        ),
        ("keys.rs", include_str!("../src/keys.rs"), 14),
        ("ntt.rs", include_str!("../src/ntt.rs"), 4),
        ("params.rs", include_str!("../src/params.rs"), 9),
        ("poly.rs", include_str!("../src/poly.rs"), 18),
        ("poly_vec.rs", include_str!("../src/poly_vec.rs"), 13),
        ("reduce.rs", include_str!("../src/reduce.rs"), 3),
    ] {
        let (count, missing) = missing_timing_docs(source);
        assert!(count >= minimum, "only {count} methods scanned in {name}");
        assert!(
            missing.is_empty(),
            "missing timing docs in {name}: {missing:?}"
        );
    }
}
