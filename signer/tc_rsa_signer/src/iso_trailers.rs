//! BC 的 `IsoTrailers`：X9.31 與 ISO 9796-2 簽章結尾的 ISO/IEC 10118 雜湊代號。

/// 隱含結尾：不標明雜湊。
pub const TRAILER_IMPLICIT: u16 = 0xBC;
/// RIPEMD-160。
pub const TRAILER_RIPEMD160: u16 = 0x31CC;
/// RIPEMD-128。
pub const TRAILER_RIPEMD128: u16 = 0x32CC;
/// SHA-1。
pub const TRAILER_SHA1: u16 = 0x33CC;
/// SHA-256。
pub const TRAILER_SHA256: u16 = 0x34CC;
/// SHA-512。
pub const TRAILER_SHA512: u16 = 0x35CC;
/// SHA-384。
pub const TRAILER_SHA384: u16 = 0x36CC;
/// Whirlpool。
pub const TRAILER_WHIRLPOOL: u16 = 0x37CC;
/// SHA-224。
pub const TRAILER_SHA224: u16 = 0x38CC;
/// SHA-512/224。
pub const TRAILER_SHA512_224: u16 = 0x39CC;
/// SHA-512/256。
pub const TRAILER_SHA512_256: u16 = 0x40CC;

/// BC 的 `GetTrailer`：依雜湊的名稱（不分大小寫，同 BC 的 `AlgorithmName`）查結尾；沒有
/// 代號的雜湊回傳 `None`。變動時間：只能用於公開值，名稱是公開的。
pub fn trailer(name: &str) -> Option<u16> {
    [
        ("RIPEMD128", TRAILER_RIPEMD128),
        ("RIPEMD160", TRAILER_RIPEMD160),
        ("SHA-1", TRAILER_SHA1),
        ("SHA-224", TRAILER_SHA224),
        ("SHA-256", TRAILER_SHA256),
        ("SHA-384", TRAILER_SHA384),
        ("SHA-512", TRAILER_SHA512),
        ("SHA-512/224", TRAILER_SHA512_224),
        ("SHA-512/256", TRAILER_SHA512_256),
        ("Whirlpool", TRAILER_WHIRLPOOL),
    ]
    .into_iter()
    .find(|(known, _)| known.eq_ignore_ascii_case(name))
    .map(|(_, trailer)| trailer)
}
