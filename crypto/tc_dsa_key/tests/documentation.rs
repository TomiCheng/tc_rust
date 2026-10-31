const METHODS: [&str; 21] = [
    "fmt",
    "init",
    "generate_key_pair",
    "eq",
    "drop",
    "is_private_key",
    "hash",
    "fips186_2",
    "fips186_3",
    "verifiable_generator",
    "candidate_p",
    "unverifiable_generator",
    "is_prime",
    "rounds",
    "parameters",
    "big",
    "power_of_two",
    "increment",
    "naf_weight",
    "random_bits",
    "random_in_range",
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
        ("math.rs", include_str!("../src/math.rs"), 3),
        (
            "key_pair_generator.rs",
            include_str!("../src/key_pair_generator.rs"),
            3,
        ),
        (
            "parameters_generator.rs",
            include_str!("../src/parameters_generator.rs"),
            15,
        ),
        (
            "params/parameters.rs",
            include_str!("../src/params/parameters.rs"),
            8,
        ),
        (
            "params/validation_parameters.rs",
            include_str!("../src/params/validation_parameters.rs"),
            6,
        ),
        (
            "params/public_key.rs",
            include_str!("../src/params/public_key.rs"),
            5,
        ),
        (
            "params/private_key.rs",
            include_str!("../src/params/private_key.rs"),
            6,
        ),
        (
            "params/key_generation_params.rs",
            include_str!("../src/params/key_generation_params.rs"),
            3,
        ),
        (
            "params/generation_params.rs",
            include_str!("../src/params/generation_params.rs"),
            6,
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
