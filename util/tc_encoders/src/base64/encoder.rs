//! 編碼與解碼不依位元組的值分支或查表：64 個編碼字元以字元表傳入，每個字元都
//! 與整張表逐一比對、以遮罩選出結果。解碼照 BC 略過空白（`\n`、`\r`、`\t`、
//! 空格）；有填充時輸入須補足填充，填充只能出現在最後一組，無填充時最後一組可以
//! 只有 2 或 3 個字元。
//!
//! 各種變形都是以另一張字元表或另一個填充設定建出的 `Base64`。逐一比對讓每個
//! 字元要走 64 次，比依字元範圍計算慢，換來任意字元表都是常數時間。

use crate::whitespace::is_whitespace;
use crate::{Encoder, EncoderError};

/// 以 64 個編碼字元與可有可無的填充字元編碼的 Base64。
///
/// 常用的變形是 [`DEFAULT`]、[`URL`]、[`RFC4648_URL`] 與 [`RFC4648_URL_NO_PAD`]。
///
/// ```
/// use tc_encoders::Encoder;
/// use tc_encoders::base64;
///
/// let mut text = [0; 8];
/// let len = base64::DEFAULT.encode(b"hello", &mut text)?;
/// assert_eq!(&text[..len], b"aGVsbG8=");
///
/// let mut bytes = [0; 6];
/// let len = base64::DEFAULT.decode(b"aGVs\nbG8=", &mut bytes)?;
/// assert_eq!(&bytes[..len], b"hello");
/// # Ok::<(), tc_encoders::EncoderError>(())
/// ```
#[derive(Clone, Copy, Debug, Eq, PartialEq, Hash)]
pub struct Base64 {
    symbols: &'static [u8; 64],
    padding: Option<u8>,
}

impl Base64 {
    /// 以 64 個編碼字元與填充字元建立；`padding` 為 `None` 時不填充。64 個字元須
    /// 互不相同，填充字元不得在其中，也都不得是空白；違反時 panic，用在 `const`
    /// 時就是編譯錯誤。
    /// 變動時間：只依字元表分支，字元表是公開值。
    pub const fn new(symbols: &'static [u8; 64], padding: Option<u8>) -> Self {
        if let Some(padding) = padding {
            assert!(
                !is_whitespace(padding),
                "the padding character is whitespace"
            );
        }
        let mut i = 0;
        while i < 64 {
            let symbol = symbols[i];
            assert!(!is_whitespace(symbol), "a symbol is whitespace");
            if let Some(padding) = padding {
                assert!(symbol != padding, "the padding character is also a symbol");
            }
            let mut j = i + 1;
            while j < 64 {
                assert!(symbol != symbols[j], "a symbol appears twice");
                j += 1;
            }
            i += 1;
        }
        Self { symbols, padding }
    }
}

impl Default for Base64 {
    /// [`DEFAULT`]。
    /// 常數時間：不讀任何資料。
    fn default() -> Self {
        DEFAULT
    }
}

const STANDARD_SYMBOLS: &[u8; 64] =
    b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
const URL_SYMBOLS: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_";

/// RFC 4648 §4 的標準 Base64：`+`、`/` 與 `=` 填充，BC `Base64Encoder` 的預設。
pub const DEFAULT: Base64 = Base64::new(STANDARD_SYMBOLS, Some(b'='));

/// BC 的 UrlBase64（`UrlBase64Encoder`）：以 `-`、`_` 取代 `+`、`/`，填充字元是
/// `.`。這是 BC 的格式，不是 RFC 4648 §5 的 base64url。
///
/// ```
/// use tc_encoders::Encoder;
/// use tc_encoders::base64;
///
/// let mut text = [0; 4];
/// let len = base64::URL.encode(&[0xfb, 0xff], &mut text)?;
/// assert_eq!(&text[..len], b"-_8.");
/// # Ok::<(), tc_encoders::EncoderError>(())
/// ```
pub const URL: Base64 = Base64::new(URL_SYMBOLS, Some(b'.'));

/// RFC 4648 §5 的 base64url：`-`、`_` 與 `=` 填充。
pub const RFC4648_URL: Base64 = Base64::new(URL_SYMBOLS, Some(b'='));

/// RFC 4648 §5 的 base64url 不填充，JWS（RFC 7515）等使用的形式。
///
/// ```
/// use tc_encoders::Encoder;
/// use tc_encoders::base64;
///
/// let mut text = [0; 3];
/// let len = base64::RFC4648_URL_NO_PAD.encode(&[0xfb, 0xff], &mut text)?;
/// assert_eq!(&text[..len], b"-_8");
/// # Ok::<(), tc_encoders::EncoderError>(())
/// ```
pub const RFC4648_URL_NO_PAD: Base64 = Base64::new(URL_SYMBOLS, None);

/// `a == b` 時為 `0xff`，否則為 0。
fn eq_mask(a: u8, b: u8) -> u8 {
    (u16::from(a ^ b).wrapping_sub(1) >> 8) as u8
}

/// `sextet` 須小於 64；與整張表逐一比對，不以 `sextet` 為索引。
fn encode_sextet(sextet: u8, symbols: &[u8; 64]) -> u8 {
    let mut c = 0;
    for (index, &symbol) in (0..64).zip(symbols) {
        c |= symbol & eq_mask(index, sextet);
    }
    c
}

/// 字元表中的字元回 0..=63，其餘（含填充字元）回 -1。
fn decode_sextet(c: u8, symbols: &[u8; 64]) -> i16 {
    let mut value = -1;
    for (index, &symbol) in (0..64).zip(symbols) {
        value += i16::from(eq_mask(c, symbol) as i8) & (index + 1);
    }
    value
}

/// 變動時間：只依長度分支，長度是公開值。
fn encoded_len(data_len: usize, padded: bool) -> usize {
    if padded {
        data_len.div_ceil(3) * 4
    } else {
        data_len / 3 * 4 + [0, 2, 3][data_len % 3]
    }
}

/// 變動時間：只依長度分支，長度是公開值。
fn decoded_len(encoded_len: usize) -> usize {
    encoded_len / 4 * 3 + (encoded_len % 4).saturating_sub(1)
}

/// 常數時間：不依 `data` 的內容分支或查表；只依長度決定最後一組的長度與填充。
fn encode(
    data: &[u8],
    out: &mut [u8],
    symbols: &[u8; 64],
    padding: Option<u8>,
) -> Result<usize, EncoderError> {
    let len = encoded_len(data.len(), padding.is_some());
    let out = out.get_mut(..len).ok_or(EncoderError::BufferTooSmall)?;
    let (body, tail) = out.split_at_mut(data.len() / 3 * 4);
    let mut chunks = data.chunks_exact(3);
    for (chunk, group) in (&mut chunks).zip(body.chunks_exact_mut(4)) {
        group[0] = encode_sextet(chunk[0] >> 2, symbols);
        group[1] = encode_sextet(((chunk[0] << 4) | (chunk[1] >> 4)) & 0x3f, symbols);
        group[2] = encode_sextet(((chunk[1] << 2) | (chunk[2] >> 6)) & 0x3f, symbols);
        group[3] = encode_sextet(chunk[2] & 0x3f, symbols);
    }
    let rest = chunks.remainder();
    if let Some(&first) = rest.first() {
        let second = rest.get(1).copied().unwrap_or(0);
        let sextets = [
            first >> 2,
            ((first << 4) | (second >> 4)) & 0x3f,
            (second << 2) & 0x3f,
        ];
        let (written, padded) = tail.split_at_mut(rest.len() + 1);
        for (slot, &sextet) in written.iter_mut().zip(&sextets) {
            *slot = encode_sextet(sextet, symbols);
        }
        if let Some(padding) = padding {
            padded.fill(padding);
        }
    }
    Ok(len)
}

/// 常數時間：不依字元值分支或查表；只依空白的位置、最後一組的填充與長度分支。
fn decode(
    data: &[u8],
    out: &mut [u8],
    symbols: &[u8; 64],
    padding: Option<u8>,
) -> Result<usize, EncoderError> {
    let mut invalid = 0;
    let mut written = 0;
    let mut group = [0; 4];
    let mut filled = 0;
    let mut pending: Option<[u8; 4]> = None;
    for &c in data {
        if is_whitespace(c) {
            continue;
        }
        group[filled] = c;
        filled += 1;
        if filled < 4 {
            continue;
        }
        filled = 0;
        if let Some(full) = pending.replace(group) {
            let sextets = full.map(|c| decode_sextet(c, symbols));
            invalid |= sextets[0] | sextets[1] | sextets[2] | sextets[3];
            written += write(out, written, &triple(sextets))?;
        }
    }
    // 最後一個完整的組；有填充且沒有剩下的字元時，它可能帶填充。
    if let Some(last) = pending {
        let sextets = last.map(|c| decode_sextet(c, symbols));
        let used = match padding {
            Some(padding) if filled == 0 && last[2] == padding => {
                if last[3] != padding {
                    return Err(EncoderError::InvalidPadding);
                }
                invalid |= sextets[0] | sextets[1];
                1
            }
            Some(padding) if filled == 0 && last[3] == padding => {
                invalid |= sextets[0] | sextets[1] | sextets[2];
                2
            }
            _ => {
                invalid |= sextets[0] | sextets[1] | sextets[2] | sextets[3];
                3
            }
        };
        written += write(out, written, &triple(sextets)[..used])?;
    }
    match (padding, filled) {
        (_, 0) => {}
        (Some(_), _) | (None, 1) => return Err(EncoderError::InvalidLength),
        (None, _) => {
            let mut sextets = [0; 4];
            for (sextet, &c) in sextets.iter_mut().zip(&group[..filled]) {
                *sextet = decode_sextet(c, symbols);
                invalid |= *sextet;
            }
            written += write(out, written, &triple(sextets)[..filled - 1])?;
        }
    }
    if invalid < 0 {
        return Err(EncoderError::InvalidCharacter);
    }
    Ok(written)
}

fn triple(sextets: [i16; 4]) -> [u8; 3] {
    [
        ((sextets[0] << 2) | (sextets[1] >> 4)) as u8,
        ((sextets[1] << 4) | (sextets[2] >> 2)) as u8,
        ((sextets[2] << 6) | sextets[3]) as u8,
    ]
}

/// 常數時間：只依長度分支。
fn write(out: &mut [u8], at: usize, bytes: &[u8]) -> Result<usize, EncoderError> {
    out.get_mut(at..at + bytes.len())
        .ok_or(EncoderError::BufferTooSmall)?
        .copy_from_slice(bytes);
    Ok(bytes.len())
}

impl Encoder for Base64 {
    const DECODED_BLOCK_SIZE: usize = 3;
    const ENCODED_BLOCK_SIZE: usize = 4;

    /// 變動時間：只依長度分支，長度是公開值。
    fn encoded_len(&self, data_len: usize) -> usize {
        encoded_len(data_len, self.padding.is_some())
    }

    /// 變動時間：只依長度分支，長度是公開值。
    fn decoded_len(&self, encoded_len: usize) -> usize {
        decoded_len(encoded_len)
    }

    /// 常數時間：不依 `data` 的內容分支或查表；只依長度決定最後一組的長度與填充。
    fn encode(&self, data: &[u8], out: &mut [u8]) -> Result<usize, EncoderError> {
        encode(data, out, self.symbols, self.padding)
    }

    /// 字元表以外的字元回 `InvalidCharacter`。有填充時，略過空白後的字元數不是
    /// 4 的倍數回 `InvalidLength`，填充只出現在第三個字元回 `InvalidPadding`；
    /// 無填充時，最後一組只有 1 個字元回 `InvalidLength`。
    /// 常數時間：不依字元值分支或查表；只依空白的位置、最後一組的填充與長度分支。
    fn decode(&self, data: &[u8], out: &mut [u8]) -> Result<usize, EncoderError> {
        decode(data, out, self.symbols, self.padding)
    }

    /// 長度不是 4 的倍數回 `InvalidLength`；填充字元與空白都回 `InvalidCharacter`。
    /// 常數時間：不依字元值分支或查表；只依長度分支。
    fn decode_blocks(&self, data: &[u8], out: &mut [u8]) -> Result<usize, EncoderError> {
        if data.len() % 4 != 0 {
            return Err(EncoderError::InvalidLength);
        }
        let mut invalid = 0;
        let out = out
            .get_mut(..data.len() / 4 * 3)
            .ok_or(EncoderError::BufferTooSmall)?;
        for (bytes, group) in out.chunks_exact_mut(3).zip(data.chunks_exact(4)) {
            let sextets = [
                decode_sextet(group[0], self.symbols),
                decode_sextet(group[1], self.symbols),
                decode_sextet(group[2], self.symbols),
                decode_sextet(group[3], self.symbols),
            ];
            invalid |= sextets[0] | sextets[1] | sextets[2] | sextets[3];
            bytes.copy_from_slice(&triple(sextets));
        }
        if invalid < 0 {
            return Err(EncoderError::InvalidCharacter);
        }
        Ok(out.len())
    }
}

#[cfg(test)]
mod tests {
    use super::{
        Base64, DEFAULT, RFC4648_URL_NO_PAD, STANDARD_SYMBOLS, decode_sextet, encode_sextet,
    };
    use crate::{Encoder, EncoderError};

    #[test]
    fn every_sextet_round_trips_through_the_standard_table() {
        for (sextet, &c) in (0..64u8).zip(STANDARD_SYMBOLS) {
            assert_eq!(encode_sextet(sextet, STANDARD_SYMBOLS), c);
            assert_eq!(decode_sextet(c, STANDARD_SYMBOLS), i16::from(sextet));
        }
    }

    #[test]
    fn every_other_byte_is_not_a_base64_character() {
        for c in 0..=255u8 {
            if !STANDARD_SYMBOLS.contains(&c) {
                assert_eq!(decode_sextet(c, STANDARD_SYMBOLS), -1, "{c:#04x}");
            }
        }
    }

    #[test]
    fn rfc_4648_base64_vectors_round_trip_with_and_without_padding() {
        let vectors: [(&[u8], &[u8]); 7] = [
            (b"", b""),
            (b"f", b"Zg=="),
            (b"fo", b"Zm8="),
            (b"foo", b"Zm9v"),
            (b"foob", b"Zm9vYg=="),
            (b"fooba", b"Zm9vYmE="),
            (b"foobar", b"Zm9vYmFy"),
        ];
        let mut buffer = [0; 8];
        for (data, encoded) in vectors {
            assert_eq!(DEFAULT.encoded_len(data.len()), encoded.len());
            let len = DEFAULT.encode(data, &mut buffer).unwrap();
            assert_eq!(&buffer[..len], encoded);
            let len = DEFAULT.decode(encoded, &mut buffer).unwrap();
            assert_eq!(&buffer[..len], data);

            let unpadded = encoded.strip_suffix(b"==").or(encoded.strip_suffix(b"="));
            let unpadded = unpadded.unwrap_or(encoded);
            assert_eq!(RFC4648_URL_NO_PAD.encoded_len(data.len()), unpadded.len());
            let len = RFC4648_URL_NO_PAD.encode(data, &mut buffer).unwrap();
            assert_eq!(&buffer[..len], unpadded);
            let len = RFC4648_URL_NO_PAD.decode(unpadded, &mut buffer).unwrap();
            assert_eq!(&buffer[..len], data);
        }
    }

    #[test]
    fn every_byte_value_round_trips() {
        let data: [u8; 256] = core::array::from_fn(|i| i as u8);
        let mut text = [0; 344];
        let mut back = [0; 258];
        for base64 in [DEFAULT, RFC4648_URL_NO_PAD] {
            let len = base64.encode(&data, &mut text).unwrap();
            assert_eq!(len, base64.encoded_len(256));
            let len = base64.decode(&text[..len], &mut back).unwrap();
            assert_eq!(back[..len], data);
        }
    }

    #[test]
    #[should_panic(expected = "a symbol appears twice")]
    fn a_table_with_a_repeated_symbol_is_rejected() {
        let mut symbols = *STANDARD_SYMBOLS;
        symbols[1] = b'A';
        Base64::new(leak(symbols), None);
    }

    #[test]
    #[should_panic(expected = "the padding character is also a symbol")]
    fn a_padding_character_that_is_a_symbol_is_rejected() {
        Base64::new(STANDARD_SYMBOLS, Some(b'A'));
    }

    #[test]
    #[should_panic(expected = "a symbol is whitespace")]
    fn a_table_with_whitespace_is_rejected() {
        let mut symbols = *STANDARD_SYMBOLS;
        symbols[0] = b' ';
        Base64::new(leak(symbols), Some(b'='));
    }

    #[test]
    #[should_panic(expected = "the padding character is whitespace")]
    fn a_whitespace_padding_character_is_rejected() {
        Base64::new(STANDARD_SYMBOLS, Some(b' '));
    }

    /// 測試裡在執行期組出 `'static` 字元表。
    fn leak(symbols: [u8; 64]) -> &'static [u8; 64] {
        extern crate std;
        std::boxed::Box::leak(std::boxed::Box::new(symbols))
    }

    #[test]
    fn whitespace_is_skipped_anywhere() {
        let mut buffer = [0; 6];
        let len = DEFAULT.decode(b" Zm9v\r\nYm\tFy \n", &mut buffer).unwrap();
        assert_eq!(&buffer[..len], b"foobar");
        let len = RFC4648_URL_NO_PAD
            .decode(b"Zm9v\nYmE", &mut buffer)
            .unwrap();
        assert_eq!(&buffer[..len], b"fooba");
    }

    #[test]
    fn bad_characters_lengths_padding_and_buffers_are_errors() {
        let mut buffer = [0; 6];
        for (base64, input, error) in [
            (DEFAULT, &b"Zm9*"[..], EncoderError::InvalidCharacter),
            (DEFAULT, b"Zg==Zm9v", EncoderError::InvalidCharacter),
            (DEFAULT, b"=Zg=", EncoderError::InvalidCharacter),
            (DEFAULT, b"Zm9", EncoderError::InvalidLength),
            (DEFAULT, b"Zm9vY", EncoderError::InvalidLength),
            (DEFAULT, b"Zg=A", EncoderError::InvalidPadding),
            (DEFAULT, b"Zm9vYmFyZm9v", EncoderError::BufferTooSmall),
            (RFC4648_URL_NO_PAD, b"Zg==", EncoderError::InvalidCharacter),
            (RFC4648_URL_NO_PAD, b"Zm9vY", EncoderError::InvalidLength),
            (RFC4648_URL_NO_PAD, b"Zm*", EncoderError::InvalidCharacter),
        ] {
            assert_eq!(base64.decode(input, &mut buffer), Err(error), "{input:?}");
        }
        assert_eq!(
            DEFAULT.encode(b"foobar", &mut buffer),
            Err(EncoderError::BufferTooSmall)
        );
    }
}
