//! Base64 編碼，對應 BC 的 `Base64`、`Base64Encoder` 與 `UrlBase64Encoder`，
//! 另有 BC 沒有的 RFC 4648 base64url 與無填充形式。

mod encoder;

pub use encoder::{Base64, DEFAULT, RFC4648_URL, RFC4648_URL_NO_PAD, URL};
