//! 編碼與解碼不依位元組的值分支或查表：字元表以 65 個字元（64 個編碼字元
//! 加上填充字元）傳入，每個字元都與整張表逐一比對、以遮罩選出結果。解碼照 BC
//! 略過空白（`\n`、`\r`、`\t`、空格），輸入須補足填充，填充只能出現在最後一組。
//!
//! UrlBase64 只換一張字元表，共用同一套核心。逐一比對讓每個字元要走 64 次，比
//! 依字元範圍計算慢，換來任意字元表都是常數時間。

use crate::{Encoder, EncoderError};

/// 標準 Base64（RFC 4648 §4），`+`、`/` 與 `=` 填充。
///
/// ```
/// use tc_encoders::Encoder;
/// use tc_encoders::base64::Base64;
///
/// let mut text = [0; 8];
/// let len = Base64.encode(b"hello", &mut text)?;
/// assert_eq!(&text[..len], b"aGVsbG8=");
///
/// let mut bytes = [0; 6];
/// let len = Base64.decode(b"aGVs\nbG8=", &mut bytes)?;
/// assert_eq!(&bytes[..len], b"hello");
/// # Ok::<(), tc_encoders::EncoderError>(())
/// ```
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq, Hash)]
pub struct Base64;

/// 64 個編碼字元依序排列，最後一個是填充字元。
pub(super) type Alphabet = [u8; 65];

const STANDARD: &Alphabet = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/=";

/// `a == b` 時為 `0xff`，否則為 0。
fn eq_mask(a: u8, b: u8) -> u8 {
    (u16::from(a ^ b).wrapping_sub(1) >> 8) as u8
}

/// `sextet` 須小於 64；與整張表逐一比對，不以 `sextet` 為索引。
fn encode_sextet(sextet: u8, alphabet: &Alphabet) -> u8 {
    let mut c = 0;
    for (index, &symbol) in (0..64).zip(alphabet) {
        c |= symbol & eq_mask(index, sextet);
    }
    c
}

/// 字元表中的字元回 0..=63，其餘（含填充字元）回 -1。
fn decode_sextet(c: u8, alphabet: &Alphabet) -> i16 {
    let mut value = -1;
    for (index, &symbol) in (0..64).zip(alphabet) {
        value += i16::from(eq_mask(c, symbol) as i8) & (index + 1);
    }
    value
}

fn is_whitespace(c: u8) -> bool {
    matches!(c, b'\n' | b'\r' | b'\t' | b' ')
}

pub(super) fn encoded_len(data_len: usize) -> usize {
    data_len.div_ceil(3) * 4
}

pub(super) fn decoded_len(encoded_len: usize) -> usize {
    encoded_len / 4 * 3
}

pub(super) fn encode(
    data: &[u8],
    out: &mut [u8],
    alphabet: &Alphabet,
) -> Result<usize, EncoderError> {
    let out = out
        .get_mut(..encoded_len(data.len()))
        .ok_or(EncoderError::BufferTooSmall)?;
    let mut chunks = data.chunks_exact(3);
    let mut groups = out.chunks_exact_mut(4);
    for (chunk, group) in (&mut chunks).zip(&mut groups) {
        group[0] = encode_sextet(chunk[0] >> 2, alphabet);
        group[1] = encode_sextet(((chunk[0] << 4) | (chunk[1] >> 4)) & 0x3f, alphabet);
        group[2] = encode_sextet(((chunk[1] << 2) | (chunk[2] >> 6)) & 0x3f, alphabet);
        group[3] = encode_sextet(chunk[2] & 0x3f, alphabet);
    }
    if let Some(group) = groups.next() {
        let rest = chunks.remainder();
        let second = rest.get(1).copied().unwrap_or(0);
        group[0] = encode_sextet(rest[0] >> 2, alphabet);
        group[1] = encode_sextet(((rest[0] << 4) | (second >> 4)) & 0x3f, alphabet);
        group[2] = if rest.len() == 2 {
            encode_sextet((second << 2) & 0x3f, alphabet)
        } else {
            alphabet[64]
        };
        group[3] = alphabet[64];
    }
    Ok(out.len())
}

pub(super) fn decode(
    data: &[u8],
    out: &mut [u8],
    alphabet: &Alphabet,
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
            let sextets = full.map(|c| decode_sextet(c, alphabet));
            invalid |= sextets[0] | sextets[1] | sextets[2] | sextets[3];
            written += write(out, written, &triple(sextets))?;
        }
    }
    if filled != 0 {
        return Err(EncoderError::InvalidLength);
    }
    if let Some(last) = pending {
        let sextets = last.map(|c| decode_sextet(c, alphabet));
        let bytes = triple(sextets);
        let used = if last[2] == alphabet[64] {
            if last[3] != alphabet[64] {
                return Err(EncoderError::InvalidPadding);
            }
            invalid |= sextets[0] | sextets[1];
            1
        } else if last[3] == alphabet[64] {
            invalid |= sextets[0] | sextets[1] | sextets[2];
            2
        } else {
            invalid |= sextets[0] | sextets[1] | sextets[2] | sextets[3];
            3
        };
        written += write(out, written, &bytes[..used])?;
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
        encoded_len(data_len)
    }

    /// 變動時間：只依長度分支，長度是公開值。
    fn decoded_len(&self, encoded_len: usize) -> usize {
        decoded_len(encoded_len)
    }

    /// 常數時間：不依 `data` 的內容分支或查表；只依長度決定填充。
    fn encode(&self, data: &[u8], out: &mut [u8]) -> Result<usize, EncoderError> {
        encode(data, out, STANDARD)
    }

    /// 字元表以外的字元回 `InvalidCharacter`，略過空白後的字元數不是 4 的倍數回
    /// `InvalidLength`，填充只出現在第三個字元回 `InvalidPadding`。
    /// 常數時間：不依字元值分支或查表；只依空白的位置、最後一組的填充與長度分支。
    fn decode(&self, data: &[u8], out: &mut [u8]) -> Result<usize, EncoderError> {
        decode(data, out, STANDARD)
    }
}

#[cfg(test)]
mod tests {
    use super::{Base64, STANDARD, decode_sextet, encode_sextet};
    use crate::{Encoder, EncoderError};

    const TABLE: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";

    #[test]
    fn every_sextet_round_trips_through_the_standard_table() {
        for (sextet, &c) in (0..64u8).zip(TABLE) {
            assert_eq!(encode_sextet(sextet, STANDARD), c);
            assert_eq!(decode_sextet(c, STANDARD), i16::from(sextet));
        }
    }

    #[test]
    fn every_other_byte_is_not_a_base64_character() {
        for c in 0..=255u8 {
            if !TABLE.contains(&c) {
                assert_eq!(decode_sextet(c, STANDARD), -1, "{c:#04x}");
            }
        }
    }

    #[test]
    fn rfc_4648_base64_vectors_round_trip() {
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
            assert_eq!(Base64.encoded_len(data.len()), encoded.len());
            let len = Base64.encode(data, &mut buffer).unwrap();
            assert_eq!(&buffer[..len], encoded);
            let len = Base64.decode(encoded, &mut buffer).unwrap();
            assert_eq!(&buffer[..len], data);
        }
    }

    #[test]
    fn every_byte_value_round_trips() {
        let data: [u8; 256] = core::array::from_fn(|i| i as u8);
        let mut text = [0; 344];
        let mut back = [0; 258];
        let len = Base64.encode(&data, &mut text).unwrap();
        assert_eq!(len, 344);
        let len = Base64.decode(&text, &mut back).unwrap();
        assert_eq!(back[..len], data);
    }

    #[test]
    fn whitespace_is_skipped_anywhere() {
        let mut buffer = [0; 6];
        let len = Base64.decode(b" Zm9v\r\nYm\tFy \n", &mut buffer).unwrap();
        assert_eq!(&buffer[..len], b"foobar");
    }

    #[test]
    fn bad_characters_lengths_padding_and_buffers_are_errors() {
        let mut buffer = [0; 6];
        for (input, error) in [
            (&b"Zm9*"[..], EncoderError::InvalidCharacter),
            (b"Zg==Zm9v", EncoderError::InvalidCharacter),
            (b"=Zg=", EncoderError::InvalidCharacter),
            (b"Zm9", EncoderError::InvalidLength),
            (b"Zm9vY", EncoderError::InvalidLength),
            (b"Zg=A", EncoderError::InvalidPadding),
            (b"Zm9vYmFyZm9v", EncoderError::BufferTooSmall),
        ] {
            assert_eq!(Base64.decode(input, &mut buffer), Err(error), "{input:?}");
        }
        assert_eq!(
            Base64.encode(b"foobar", &mut buffer),
            Err(EncoderError::BufferTooSmall)
        );
    }
}
