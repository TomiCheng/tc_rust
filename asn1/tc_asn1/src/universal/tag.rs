//! X.680 通用型別的識別位元組；號碼 31 以上使用高號碼形式。

pub const BOOLEAN: &[u8] = &[0x01];
pub const INTEGER: &[u8] = &[0x02];
pub const BIT_STRING: &[u8] = &[0x03];
pub const OCTET_STRING: &[u8] = &[0x04];
pub const NULL: &[u8] = &[0x05];
pub const OBJECT_IDENTIFIER: &[u8] = &[0x06];
pub const OBJECT_DESCRIPTOR: &[u8] = &[0x07];
/// 永遠是 constructed：`[UNIVERSAL 8] IMPLICIT SEQUENCE`。
pub const EXTERNAL: &[u8] = &[0x28];
pub const REAL: &[u8] = &[0x09];
pub const ENUMERATED: &[u8] = &[0x0A];
/// constructed 的 EMBEDDED PDV 關聯 SEQUENCE。
pub const EMBEDDED_PDV: &[u8] = &[0x2B];
pub const UTF8_STRING: &[u8] = &[0x0C];
pub const RELATIVE_OID: &[u8] = &[0x0D];
pub const TIME: &[u8] = &[0x0E];
pub const SEQUENCE: &[u8] = &[0x30];
pub const SET: &[u8] = &[0x31];
pub const NUMERIC_STRING: &[u8] = &[0x12];
pub const PRINTABLE_STRING: &[u8] = &[0x13];
pub const TELETEX_STRING: &[u8] = &[0x14];
pub const VIDEOTEX_STRING: &[u8] = &[0x15];
pub const IA5_STRING: &[u8] = &[0x16];
pub const UTC_TIME: &[u8] = &[0x17];
pub const GENERALIZED_TIME: &[u8] = &[0x18];
pub const GRAPHIC_STRING: &[u8] = &[0x19];
pub const VISIBLE_STRING: &[u8] = &[0x1A];
pub const GENERAL_STRING: &[u8] = &[0x1B];
pub const UNIVERSAL_STRING: &[u8] = &[0x1C];
pub const CHARACTER_STRING: &[u8] = &[0x3D];
pub const BMP_STRING: &[u8] = &[0x1E];
/// 高號碼形式的 UNIVERSAL 31；不是 constructed 的 SET。
pub const DATE: &[u8] = &[0x1F, 0x1F];
pub const TIME_OF_DAY: &[u8] = &[0x1F, 0x20];
pub const DATE_TIME: &[u8] = &[0x1F, 0x21];
pub const DURATION: &[u8] = &[0x1F, 0x22];
pub const OID_IRI: &[u8] = &[0x1F, 0x23];
pub const RELATIVE_OID_IRI: &[u8] = &[0x1F, 0x24];
