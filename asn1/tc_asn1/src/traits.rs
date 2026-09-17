//! 本 crate 對外的行為契約。

mod decode;
pub(crate) mod encode;

pub use decode::{Decode, DecodeConstructed, DecodeContent, DecodeInner};
pub use encode::{Encode, EncodeContent, EncodeTagged};
