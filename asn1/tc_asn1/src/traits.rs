//! 本 crate 對外的行為契約。

mod decode;
mod encode;

pub use decode::{Decode, DecodeConstructed, DecodeContent, DecodeInner};
pub use encode::{Encode, EncodeContent, EncodeTagged};
