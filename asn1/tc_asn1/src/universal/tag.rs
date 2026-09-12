//! X.680 通用型別的識別位元組；號碼 31 以上使用高號碼形式。

pub const BOOLEAN: &[u8] = &[0x01];
pub const INTEGER: &[u8] = &[0x02];
pub const BIT_STRING: &[u8] = &[0x03];
/// BER 分段位元字串的識別位元組。
pub const CONSTRUCTED_BIT_STRING: &[u8] = &[0x23];
pub const OCTET_STRING: &[u8] = &[0x04];
/// BER 分段八位元字串的識別位元組。
pub const CONSTRUCTED_OCTET_STRING: &[u8] = &[0x24];
pub const NULL: &[u8] = &[0x05];
pub const OBJECT_IDENTIFIER: &[u8] = &[0x06];
pub const OBJECT_DESCRIPTOR: &[u8] = &[0x07];
/// BER constructed form of ObjectDescriptor.
pub const CONSTRUCTED_OBJECT_DESCRIPTOR: &[u8] = &[0x27];
/// 永遠是 constructed：`[UNIVERSAL 8] IMPLICIT SEQUENCE`。
pub const EXTERNAL: &[u8] = &[0x28];
pub const REAL: &[u8] = &[0x09];
pub const ENUMERATED: &[u8] = &[0x0A];
/// constructed 的 EMBEDDED PDV 關聯 SEQUENCE。
pub const EMBEDDED_PDV: &[u8] = &[0x2B];
pub const UTF8_STRING: &[u8] = &[0x0C];
/// BER constructed form of Utf8String.
pub const CONSTRUCTED_UTF8_STRING: &[u8] = &[0x2C];
pub const RELATIVE_OID: &[u8] = &[0x0D];
pub const TIME: &[u8] = &[0x0E];
pub const SEQUENCE: &[u8] = &[0x30];
pub const SET: &[u8] = &[0x31];
pub const NUMERIC_STRING: &[u8] = &[0x12];
/// BER constructed form of NumericString.
pub const CONSTRUCTED_NUMERIC_STRING: &[u8] = &[0x32];
pub const PRINTABLE_STRING: &[u8] = &[0x13];
/// BER constructed form of PrintableString.
pub const CONSTRUCTED_PRINTABLE_STRING: &[u8] = &[0x33];
pub const TELETEX_STRING: &[u8] = &[0x14];
/// BER constructed form of TeletexString.
pub const CONSTRUCTED_TELETEX_STRING: &[u8] = &[0x34];
pub const VIDEOTEX_STRING: &[u8] = &[0x15];
/// BER constructed form of VideotexString.
pub const CONSTRUCTED_VIDEOTEX_STRING: &[u8] = &[0x35];
pub const IA5_STRING: &[u8] = &[0x16];
/// BER constructed form of Ia5String.
pub const CONSTRUCTED_IA5_STRING: &[u8] = &[0x36];
pub const UTC_TIME: &[u8] = &[0x17];
pub const GENERALIZED_TIME: &[u8] = &[0x18];
pub const GRAPHIC_STRING: &[u8] = &[0x19];
/// BER constructed form of GraphicString.
pub const CONSTRUCTED_GRAPHIC_STRING: &[u8] = &[0x39];
pub const VISIBLE_STRING: &[u8] = &[0x1A];
/// BER constructed form of VisibleString.
pub const CONSTRUCTED_VISIBLE_STRING: &[u8] = &[0x3A];
pub const GENERAL_STRING: &[u8] = &[0x1B];
/// BER constructed form of GeneralString.
pub const CONSTRUCTED_GENERAL_STRING: &[u8] = &[0x3B];
pub const UNIVERSAL_STRING: &[u8] = &[0x1C];
/// BER constructed form of UniversalString.
pub const CONSTRUCTED_UNIVERSAL_STRING: &[u8] = &[0x3C];
pub const CHARACTER_STRING: &[u8] = &[0x3D];
pub const BMP_STRING: &[u8] = &[0x1E];
/// BER constructed form of BmpString.
pub const CONSTRUCTED_BMP_STRING: &[u8] = &[0x3E];
/// 高號碼形式的 UNIVERSAL 31；不是 constructed 的 SET。
pub const DATE: &[u8] = &[0x1F, 0x1F];
pub const TIME_OF_DAY: &[u8] = &[0x1F, 0x20];
pub const DATE_TIME: &[u8] = &[0x1F, 0x21];
pub const DURATION: &[u8] = &[0x1F, 0x22];
pub const OID_IRI: &[u8] = &[0x1F, 0x23];
pub const RELATIVE_OID_IRI: &[u8] = &[0x1F, 0x24];
