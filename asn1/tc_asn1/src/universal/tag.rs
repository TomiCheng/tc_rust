//! X.680 通用型別的識別位元組。號碼都在 30 以下，所以各是一個位元組。

pub const BOOLEAN: &[u8] = &[0x01];
pub const INTEGER: &[u8] = &[0x02];
pub const BIT_STRING: &[u8] = &[0x03];
pub const OCTET_STRING: &[u8] = &[0x04];
pub const NULL: &[u8] = &[0x05];
pub const OBJECT_IDENTIFIER: &[u8] = &[0x06];
pub const ENUMERATED: &[u8] = &[0x0A];
pub const UTF8_STRING: &[u8] = &[0x0C];
pub const SEQUENCE: &[u8] = &[0x30];
pub const SET: &[u8] = &[0x31];
pub const PRINTABLE_STRING: &[u8] = &[0x13];
pub const TELETEX_STRING: &[u8] = &[0x14];
pub const IA5_STRING: &[u8] = &[0x16];
pub const UTC_TIME: &[u8] = &[0x17];
pub const GENERALIZED_TIME: &[u8] = &[0x18];
pub const UNIVERSAL_STRING: &[u8] = &[0x1C];
pub const BMP_STRING: &[u8] = &[0x1E];
