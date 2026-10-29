const METHODS: [&str; 4] = ["read", "write", "flush", "drop"];

fn checked(line: &str) -> bool {
    if line.starts_with("pub fn ") {
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
fn every_public_method_states_constant_or_variable_time() {
    for (name, source, minimum) in [
        ("adler32.rs", include_str!("../src/adler32.rs"), 2),
        (
            "deflate_options.rs",
            include_str!("../src/deflate_options.rs"),
            4,
        ),
        (
            "inflate_options.rs",
            include_str!("../src/inflate_options.rs"),
            2,
        ),
        ("zlib_reader.rs", include_str!("../src/zlib_reader.rs"), 5),
        ("zlib_writer.rs", include_str!("../src/zlib_writer.rs"), 5),
    ] {
        let (count, missing) = missing_timing_docs(source);
        assert!(count >= minimum, "only {count} methods scanned in {name}");
        assert!(
            missing.is_empty(),
            "missing timing docs in {name}: {missing:?}"
        );
    }
}
