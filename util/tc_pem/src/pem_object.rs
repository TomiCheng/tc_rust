use std::fmt;

use tc_zeroize::Zeroize;

use crate::{PemGenerationError, PemHeader, PemObjectGenerator};

/// 一個 PEM 物件：型別（`BEGIN` 後面的名稱）、標頭與解碼後的內容。
///
/// 內容可能是私鑰，drop 時清除；`Debug` 只印出內容長度。
#[derive(Clone)]
pub struct PemObject {
    pem_type: String,
    headers: Vec<PemHeader>,
    content: Vec<u8>,
}

impl PemObject {
    /// 沒有標頭的物件。
    /// 常數時間：只搬移欄位，不檢查內容。
    pub fn new(pem_type: impl Into<String>, content: Vec<u8>) -> Self {
        Self {
            pem_type: pem_type.into(),
            headers: Vec::new(),
            content,
        }
    }

    /// 換上 `headers`，對應 BC 帶標頭的建構式。
    /// 常數時間：只搬移欄位，不檢查內容。
    pub fn with_headers(mut self, headers: Vec<PemHeader>) -> Self {
        self.headers = headers;
        self
    }

    /// 常數時間。
    pub fn pem_type(&self) -> &str {
        &self.pem_type
    }

    /// 常數時間。
    pub fn headers(&self) -> &[PemHeader] {
        &self.headers
    }

    /// 常數時間。
    pub fn content(&self) -> &[u8] {
        &self.content
    }
}

impl PemObjectGenerator for PemObject {
    /// 回傳自己的複本，對應 BC 的 `Generate() => this`。
    /// 常數時間：只複製欄位。
    fn generate(&self) -> Result<PemObject, PemGenerationError> {
        Ok(self.clone())
    }
}

impl fmt::Debug for PemObject {
    /// 變動時間：只輸出公開的型別、標頭與內容長度，不輸出內容。
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("PemObject")
            .field("pem_type", &self.pem_type)
            .field("headers", &self.headers)
            .field("content_len", &self.content.len())
            .finish()
    }
}

impl Drop for PemObject {
    /// 常數時間：清除內容。
    fn drop(&mut self) {
        self.content.zeroize();
    }
}
