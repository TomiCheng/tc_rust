//! 文件宣告須與公開的整數型別清單一致，包含停用 alloc 時未編譯的型別。

#[test]
fn the_crate_overview_counts_and_names_every_exported_integer_type() {
    let source = include_str!("../src/lib.rs");
    let overview = source
        .split("//! # Widths")
        .next()
        .expect("crate overview precedes width guidance");
    // 下面的解析只認 `pub use foo::Bar;` 這種單一形式。改用大括號匯出時，
    // 尾綴比對會取到 `{A, B}` 而靜靜漏掉那些型別 —— 測試照樣通過卻不再檢查
    // 任何東西，所以先在這裡擋住。
    for line in source
        .lines()
        .filter_map(|line| line.strip_prefix("pub use "))
    {
        let Some(open) = line.find('{') else { continue };
        // 比對項目尾綴而不是整行是否含子字串：`ParseBigIntError` 含 `BigInt`，
        // 但它不是整數型別。
        let braced = line[open + 1..].trim_end_matches(&['}', ';'][..]);
        assert!(
            !braced
                .split(',')
                .map(str::trim)
                .any(|item| item.ends_with("BigUint") || item.ends_with("BigInt")),
            "整數型別改用大括號匯出，解析要跟著擴充：{line}"
        );
    }

    let integers: Vec<_> = source
        .lines()
        .filter_map(|line| line.strip_prefix("pub use "))
        .filter_map(|line| line.strip_suffix(';'))
        .filter_map(|line| line.rsplit("::").next())
        .filter(|name| name.ends_with("BigUint") || name.ends_with("BigInt"))
        .collect();

    assert!(!integers.is_empty());
    assert_eq!(
        integers.len() % 2,
        0,
        "integer types are signed/unsigned pairs"
    );
    let heading = format!(
        "//! {} 個小端序大整數型別，分成 {} 對。",
        integers.len(),
        integers.len() / 2
    );
    assert!(overview.lines().any(|line| line == heading));
    for name in integers {
        assert!(overview.contains(name), "missing overview for {name}");
    }
}
