//! 本 crate 對外的行為契約。

mod decode;
mod encode;

pub use decode::TryDecode;
pub use encode::TryEncode;
