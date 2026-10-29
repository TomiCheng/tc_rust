use std::fmt;

/// PEM 物件裡的一行標頭，例如 `Proc-Type: 4,ENCRYPTED`。標頭是公開資訊。
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub struct PemHeader {
    name: String,
    value: String,
}

impl PemHeader {
    /// 常數時間：只搬移字串，不檢查內容。
    pub fn new(name: impl Into<String>, value: impl Into<String>) -> Self {
        Self {
            name: name.into(),
            value: value.into(),
        }
    }

    /// 常數時間。
    pub fn name(&self) -> &str {
        &self.name
    }

    /// 常數時間。
    pub fn value(&self) -> &str {
        &self.value
    }
}

impl fmt::Display for PemHeader {
    /// 寫成 `name:value`，與 BC 的 `ToString()` 相同。
    /// 變動時間：輸出長度依內容而定，只能用於公開值。
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}:{}", self.name, self.value)
    }
}
