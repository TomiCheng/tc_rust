//! 編碼與解碼都以算術取代查表，不依位元組的值分支；解碼照 BC 略過空白
//! （`\n`、`\r`、`\t`、空格），大小寫都收。

use crate::{Encoder, EncoderError};

/// 十六進位編碼，預設輸出小寫。
///
/// ```
/// use tc_encoders::Encoder;
/// use tc_encoders::hex::Hex;
///
/// let mut text = [0; 8];
/// let len = Hex::LOWER.encode(&[0xde, 0xad, 0xbe, 0xef], &mut text)?;
/// assert_eq!(&text[..len], b"deadbeef");
///
/// let mut bytes = [0; 4];
/// let len = Hex::LOWER.decode(b"DE AD\nbe ef", &mut bytes)?;
/// assert_eq!(&bytes[..len], [0xde, 0xad, 0xbe, 0xef]);
/// # Ok::<(), tc_encoders::EncoderError>(())
/// ```
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq, Hash)]
pub struct Hex {
    upper_case: bool,
}

impl Hex {
    /// 輸出小寫，BC `HexEncoder` 的預設。
    pub const LOWER: Self = Self { upper_case: false };

    /// 輸出大寫，BC `ToHexString(data, true)`。
    pub const UPPER: Self = Self { upper_case: true };

    /// 不收空白、長度須為偶數的解碼，對應 BC 的 `DecodeStrict`。
    /// 常數時間：不依字元值分支或查表；只依長度分支。
    pub fn decode_strict(&self, data: &[u8], out: &mut [u8]) -> Result<usize, EncoderError> {
        if data.len() % 2 != 0 {
            return Err(EncoderError::InvalidLength);
        }
        let out = out
            .get_mut(..data.len() / 2)
            .ok_or(EncoderError::BufferTooSmall)?;
        let mut invalid = 0;
        for (byte, pair) in out.iter_mut().zip(data.chunks_exact(2)) {
            let high = decode_nibble(pair[0]);
            let low = decode_nibble(pair[1]);
            invalid |= high | low;
            *byte = ((high << 4) | low) as u8;
        }
        if invalid < 0 {
            return Err(EncoderError::InvalidCharacter);
        }
        Ok(out.len())
    }
}

/// `nibble` 須小於 16；`letters` 是 `'a' - '0' - 10` 或 `'A' - '0' - 10`。
fn encode_nibble(nibble: u8, letters: i16) -> u8 {
    let nibble = i16::from(nibble);
    // 9 - nibble 在 nibble > 9 時為負，右移得全 1 遮罩。
    (nibble + 0x30 + (((9 - nibble) >> 8) & letters)) as u8
}

/// 合法字元回 0..=15，其餘回 -1。
fn decode_nibble(c: u8) -> i16 {
    let c = i16::from(c);
    let mut value = -1;
    // 每段在範圍內時遮罩為全 1，加上 c 減去該段起點再加 1。
    value += (((0x2f - c) & (c - 0x3a)) >> 8) & (c - 0x2f);
    value += (((0x40 - c) & (c - 0x47)) >> 8) & (c - 0x36);
    value += (((0x60 - c) & (c - 0x67)) >> 8) & (c - 0x56);
    value
}

fn is_whitespace(c: u8) -> bool {
    matches!(c, b'\n' | b'\r' | b'\t' | b' ')
}

impl Encoder for Hex {
    const DECODED_BLOCK_SIZE: usize = 1;
    const ENCODED_BLOCK_SIZE: usize = 2;

    /// 變動時間：只依長度分支，長度是公開值。
    fn encoded_len(&self, data_len: usize) -> usize {
        data_len * 2
    }

    /// 變動時間：只依長度分支，長度是公開值。
    fn decoded_len(&self, encoded_len: usize) -> usize {
        encoded_len / 2
    }

    /// 常數時間：不依 `data` 的內容分支或查表。
    fn encode(&self, data: &[u8], out: &mut [u8]) -> Result<usize, EncoderError> {
        let out = out
            .get_mut(..self.encoded_len(data.len()))
            .ok_or(EncoderError::BufferTooSmall)?;
        let letters = if self.upper_case { 0x07 } else { 0x27 };
        for (pair, byte) in out.chunks_exact_mut(2).zip(data) {
            pair[0] = encode_nibble(byte >> 4, letters);
            pair[1] = encode_nibble(byte & 0x0f, letters);
        }
        Ok(out.len())
    }

    /// 字元表以外的字元回 `InvalidCharacter`，略過空白後的字元數為奇數回
    /// `InvalidLength`。
    /// 常數時間：不依字元值分支或查表；只依空白的位置與長度分支。
    fn decode(&self, data: &[u8], out: &mut [u8]) -> Result<usize, EncoderError> {
        let mut invalid = 0;
        let mut high = None;
        let mut written = 0;
        for &c in data {
            if is_whitespace(c) {
                continue;
            }
            let nibble = decode_nibble(c);
            invalid |= nibble;
            match high.take() {
                None => high = Some(nibble),
                Some(high) => {
                    *out.get_mut(written).ok_or(EncoderError::BufferTooSmall)? =
                        ((high << 4) | nibble) as u8;
                    written += 1;
                }
            }
        }
        if invalid < 0 {
            return Err(EncoderError::InvalidCharacter);
        }
        if high.is_some() {
            return Err(EncoderError::InvalidLength);
        }
        Ok(written)
    }
}

#[cfg(test)]
mod tests {
    use super::{Hex, decode_nibble, encode_nibble};
    use crate::{Encoder, EncoderError};

    #[test]
    fn every_nibble_round_trips_in_both_cases() {
        for nibble in 0..16u8 {
            let lower = encode_nibble(nibble, 0x27);
            let upper = encode_nibble(nibble, 0x07);
            assert_eq!(lower, b"0123456789abcdef"[usize::from(nibble)]);
            assert_eq!(upper, b"0123456789ABCDEF"[usize::from(nibble)]);
            assert_eq!(decode_nibble(lower), i16::from(nibble));
            assert_eq!(decode_nibble(upper), i16::from(nibble));
        }
    }

    #[test]
    fn every_other_byte_is_not_a_hex_digit() {
        for c in 0..=255u8 {
            if !c.is_ascii_hexdigit() {
                assert_eq!(decode_nibble(c), -1, "{c:#04x}");
            }
        }
    }

    #[test]
    fn rfc_4648_base16_vectors_round_trip() {
        let vectors: [(&[u8], &[u8]); 7] = [
            (b"", b""),
            (b"f", b"66"),
            (b"fo", b"666F"),
            (b"foo", b"666F6F"),
            (b"foob", b"666F6F62"),
            (b"fooba", b"666F6F6261"),
            (b"foobar", b"666F6F626172"),
        ];
        let mut buffer = [0; 12];
        for (data, encoded) in vectors {
            let len = Hex::UPPER.encode(data, &mut buffer).unwrap();
            assert_eq!(&buffer[..len], encoded);
            let len = Hex::LOWER.decode(encoded, &mut buffer).unwrap();
            assert_eq!(&buffer[..len], data);
            let len = Hex::LOWER.decode_strict(encoded, &mut buffer).unwrap();
            assert_eq!(&buffer[..len], data);
        }
    }

    #[test]
    fn decoding_skips_whitespace_but_strict_decoding_rejects_it() {
        let mut buffer = [0; 4];
        let spaced = b" de\tad\r\nbe ef \n";
        assert_eq!(Hex::LOWER.decode(spaced, &mut buffer), Ok(4));
        assert_eq!(buffer, [0xde, 0xad, 0xbe, 0xef]);
        assert_eq!(
            Hex::LOWER.decode_strict(b"de ad", &mut buffer),
            Err(EncoderError::InvalidLength)
        );
        assert_eq!(
            Hex::LOWER.decode_strict(b"de a", &mut buffer),
            Err(EncoderError::InvalidCharacter)
        );
    }

    #[test]
    fn bad_characters_odd_lengths_and_small_buffers_are_errors() {
        let mut buffer = [0; 2];
        assert_eq!(
            Hex::LOWER.decode(b"0g", &mut buffer),
            Err(EncoderError::InvalidCharacter)
        );
        assert_eq!(
            Hex::LOWER.decode(b"abc", &mut buffer),
            Err(EncoderError::InvalidLength)
        );
        assert_eq!(
            Hex::LOWER.decode(b"aabbcc", &mut buffer),
            Err(EncoderError::BufferTooSmall)
        );
        assert_eq!(
            Hex::LOWER.encode(&[1, 2], &mut buffer),
            Err(EncoderError::BufferTooSmall)
        );
    }
}
