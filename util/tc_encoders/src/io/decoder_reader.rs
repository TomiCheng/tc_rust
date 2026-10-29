//! 邊讀邊解碼的 `Read` 轉接器，取代 BC 的 `BufferedDecoder`。

use std::io::{self, Read};

use tc_zeroize::Zeroize;

use crate::Encoder;
use crate::whitespace::is_whitespace;

/// 暫存編碼文字（已去掉空白）與解碼結果的大小。
const BUFFER: usize = 1024;

/// 從 `R` 讀進編碼文字，讀出解碼後的資料。
///
/// 照 [`Encoder::decode`] 略過空白。最後一個完整的組與不完整的尾巴會留到 `R` 讀
/// 完才解碼，因為只有最後一組可以帶填充；在那之前的組經過
/// [`Encoder::decode_blocks`]，出現填充就是錯誤。解碼錯誤以 `InvalidData` 回報。
/// 暫存的文字與解碼結果在 drop 時清除。
///
/// ```
/// use std::io::Read;
///
/// use tc_encoders::{DecoderReader, base64};
///
/// let mut reader = DecoderReader::new(base64::DEFAULT, &b"aGVs\nbG8="[..]);
/// let mut text = String::new();
/// reader.read_to_string(&mut text)?;
/// assert_eq!(text, "hello");
/// # Ok::<(), std::io::Error>(())
/// ```
pub struct DecoderReader<E: Encoder, R: Read> {
    encoder: E,
    inner: Option<R>,
    text: [u8; BUFFER],
    text_len: usize,
    decoded: [u8; BUFFER],
    decoded_start: usize,
    decoded_end: usize,
    finished: bool,
}

impl<E: Encoder, R: Read> DecoderReader<E, R> {
    /// 以 `encoder` 解碼從 `inner` 讀進的文字。
    /// 變動時間：不讀任何資料。
    pub fn new(encoder: E, inner: R) -> Self {
        const {
            assert!(E::ENCODED_BLOCK_SIZE > 0 && 2 * E::ENCODED_BLOCK_SIZE < BUFFER);
            assert!(E::DECODED_BLOCK_SIZE <= E::ENCODED_BLOCK_SIZE);
        }
        Self {
            encoder,
            inner: Some(inner),
            text: [0; BUFFER],
            text_len: 0,
            decoded: [0; BUFFER],
            decoded_start: 0,
            decoded_end: 0,
            finished: false,
        }
    }

    /// 回傳底下的 `R`。
    /// 變動時間：不讀任何資料。
    pub fn get_ref(&self) -> &R {
        self.inner.as_ref().expect("present until into_inner")
    }

    /// 交回底下的 `R`；暫存但還沒讀出的資料就此丟棄。
    /// 變動時間：不讀任何資料。
    pub fn into_inner(mut self) -> R {
        self.wipe();
        self.inner.take().expect("present until into_inner")
    }

    /// 常數時間：只寫零。
    fn wipe(&mut self) {
        self.text.zeroize();
        self.decoded.zeroize();
        self.text_len = 0;
        self.decoded_start = 0;
        self.decoded_end = 0;
    }

    /// 讀一次 `R`，把能確定不是最後一段的完整組解碼；`R` 讀完時解碼剩下的全部。
    /// 常數時間：同 [`Encoder::decode`]；只依空白的位置與長度分支。
    fn fill(&mut self) -> io::Result<()> {
        let inner = self.inner.as_mut().expect("present until into_inner");
        let read = inner.read(&mut self.text[self.text_len..])?;
        let decoded = if read == 0 {
            self.finished = true;
            self.encoder
                .decode(&self.text[..self.text_len], &mut self.decoded)
                .map_err(invalid_data)?
        } else {
            let mut kept = self.text_len;
            for i in self.text_len..self.text_len + read {
                let c = self.text[i];
                if !is_whitespace(c) {
                    self.text[kept] = c;
                    kept += 1;
                }
            }
            self.text_len = kept;
            let block = E::ENCODED_BLOCK_SIZE;
            let ready = (self.text_len / block).saturating_sub(1) * block;
            let decoded = self
                .encoder
                .decode_blocks(&self.text[..ready], &mut self.decoded)
                .map_err(invalid_data)?;
            self.text.copy_within(ready..self.text_len, 0);
            self.text[self.text_len - ready..self.text_len].zeroize();
            self.text_len -= ready;
            decoded
        };
        self.decoded_start = 0;
        self.decoded_end = decoded;
        Ok(())
    }
}

/// 變動時間：只依錯誤種類分支。
fn invalid_data(error: crate::EncoderError) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidData, error)
}

impl<E: Encoder, R: Read> Read for DecoderReader<E, R> {
    /// 常數時間：同 [`Encoder::decode`]；只依空白的位置與長度分支。
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        if buf.is_empty() {
            return Ok(0);
        }
        while self.decoded_start == self.decoded_end {
            if self.finished {
                return Ok(0);
            }
            self.fill()?;
        }
        let available = &mut self.decoded[self.decoded_start..self.decoded_end];
        let len = available.len().min(buf.len());
        buf[..len].copy_from_slice(&available[..len]);
        available[..len].zeroize();
        self.decoded_start += len;
        Ok(len)
    }
}

impl<E: Encoder, R: Read> Drop for DecoderReader<E, R> {
    /// 清除暫存的文字與解碼結果。
    /// 常數時間：只寫零。
    fn drop(&mut self) {
        self.wipe();
    }
}
