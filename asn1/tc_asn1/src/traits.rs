//! 本 crate 對外的行為契約。

mod decode;
mod encode;

pub use decode::{Decode, DecodeContent};
pub use encode::Encode;
pub(crate) use encode::{len_octets, write_len};
