//! 解碼時略過的空白，照 BC 的 `Ignore`：`\n`、`\r`、`\t` 與空格。

/// 變動時間：依字元值分支；只用在空白這種公開的排版結構上。
pub(crate) const fn is_whitespace(c: u8) -> bool {
    matches!(c, b'\n' | b'\r' | b'\t' | b' ')
}
