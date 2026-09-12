//! 本 crate 對外的行為契約。

mod decode;
mod encode;

pub use decode::{Decode, DecodeConstructed, DecodeContent};
pub use encode::{Encode, EncodeContent};
pub(crate) use encode::{default_encode, default_encoded_len};
pub(crate) use encode::{len_octets, write_len};
