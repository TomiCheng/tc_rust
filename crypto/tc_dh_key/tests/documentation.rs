const METHODS: [&str; 9] = [
    "fmt",
    "drop",
    "eq",
    "init",
    "generate_key_pair",
    "private_value",
    "public_value",
    "has_any_small_factors_safe",
    "rounds",
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

#[test]
fn every_public_method_and_helper_states_constant_or_variable_time() {
    for (name, source, minimum) in [
        ("error.rs", include_str!("../src/error.rs"), 1),
        (
            "key_pair_generator.rs",
            include_str!("../src/key_pair_generator.rs"),
            4,
        ),
        ("math.rs", include_str!("../src/math.rs"), 3),
        (
            "parameters_generator.rs",
            include_str!("../src/parameters_generator.rs"),
            5,
        ),
        (
            "params/key_generation_params.rs",
            include_str!("../src/params/key_generation_params.rs"),
            3,
        ),
        (
            "params/parameters.rs",
            include_str!("../src/params/parameters.rs"),
            14,
        ),
        (
            "params/private_key.rs",
            include_str!("../src/params/private_key.rs"),
            4,
        ),
        (
            "params/public_key.rs",
            include_str!("../src/params/public_key.rs"),
            4,
        ),
        (
            "params/validation_parameters.rs",
            include_str!("../src/params/validation_parameters.rs"),
            3,
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
