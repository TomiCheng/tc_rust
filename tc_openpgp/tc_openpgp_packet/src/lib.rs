//! OpenPGP 封包層，對應 Bouncy Castle 的 `Org.BouncyCastle.Bcpg`。
//!
//! 本 crate 使用標準函式庫；封包讀寫介面採用 [`std::io::Read`] 與 [`std::io::Write`]。

mod body_length;
mod encoding_config;
mod hash_algorithm_tag;
mod packet;
mod packet_header;
mod packet_tag;
mod packets;
mod pgp_reader;
mod pgp_writer;
mod signature_type_id;
mod public_key_algorithm_tag;
mod traits;
mod unknown_packet;

pub use body_length::BodyLength;
pub use encoding_config::{EncodingConfig, PacketHeaderFormat};
pub use hash_algorithm_tag::HashAlgorithmTag;
pub use packet::Packet;
pub use packet_header::PacketHeader;
pub use packet_tag::PacketTag;
pub use packets::{LiteralData, LiteralDataFormat};
pub use pgp_reader::PgpReader;
pub use pgp_writer::{PgpBodyWriter, PgpWriter};
pub use signature_type_id::SignatureTypeId;
pub use public_key_algorithm_tag::PublicKeyAlgorithmTag;
pub use traits::{PgpRead, PgpWrite};
pub use unknown_packet::UnknownPacket;
