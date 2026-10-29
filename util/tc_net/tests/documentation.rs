fn missing_timing_docs(source: &str) -> (usize, Vec<String>) {
    let mut docs = String::new();
    let mut count = 0;
    let mut missing = Vec::new();
    for line in source.lines().map(str::trim) {
        if let Some(comment) = line.strip_prefix("///") {
            docs.push_str(comment.trim());
            continue;
        }
        if line.is_empty() || line.starts_with("//") || line.starts_with("#[") {
            continue;
        }
        if line.starts_with("pub fn ") {
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
fn every_public_function_states_constant_or_variable_time() {
    let (count, missing) = missing_timing_docs(include_str!("../src/ip_address.rs"));
    assert_eq!(count, 6);
    assert!(missing.is_empty(), "missing timing docs: {missing:?}");
}
