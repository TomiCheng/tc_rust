use alloc::vec::Vec;

use tc_zeroize::Zeroizing;

/// The PKCS#5 encoding of BC's `Pkcs5PasswordToBytes`: the low byte of each UTF-16 code unit,
/// which is ASCII for ASCII passwords and loses the high byte of anything else, as in BC.
///
/// Variable time: UTF-16 encoding branches on each character's range, so timing reveals the
/// password's length and which characters lie outside the BMP. There is no constant-time form.
pub fn pkcs5_password_to_bytes(password: &str) -> Zeroizing<Vec<u8>> {
    // UTF-16 單元數不會多於 UTF-8 bytes 數，緩衝區不會重新配置而留下沒清除的舊區塊
    let mut bytes = Zeroizing::new(Vec::with_capacity(password.len()));
    bytes.extend(password.encode_utf16().map(|unit| unit as u8));
    bytes
}

/// The UTF-8 encoding of BC's `Pkcs5PasswordToUtf8Bytes`, which PBKDF2 users now expect.
///
/// Constant time with respect to the characters: the bytes are copied as they are; only the
/// length is public.
pub fn pkcs5_password_to_utf8_bytes(password: &str) -> Zeroizing<Vec<u8>> {
    Zeroizing::new(password.as_bytes().to_vec())
}

/// The PKCS#12 encoding of BC's `Pkcs12PasswordToBytes`: UTF-16 big-endian with a two-byte zero
/// terminator. An empty password gives no bytes at all, or the terminator alone when
/// `wrong_pkcs12_zero` is set, as BC's flag of that name does for files written that way.
///
/// Variable time: UTF-16 encoding branches on each character's range, so timing reveals the
/// password's length and which characters lie outside the BMP. There is no constant-time form.
pub fn pkcs12_password_to_bytes(password: &str, wrong_pkcs12_zero: bool) -> Zeroizing<Vec<u8>> {
    // 每個 UTF-16 單元 2 bytes 加上結尾，理由同上先預留
    let mut bytes = Zeroizing::new(Vec::with_capacity(2 * password.len() + 2));
    if password.is_empty() && !wrong_pkcs12_zero {
        return bytes;
    }
    for unit in password.encode_utf16() {
        bytes.extend_from_slice(&unit.to_be_bytes());
    }
    bytes.extend_from_slice(&[0, 0]);
    bytes
}
