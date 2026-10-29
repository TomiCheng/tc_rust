//! 邊讀邊編碼的 `Read` 轉接器；BC 沒有對應的類別。

use std::io::{self, Read};

use tc_zeroize::Zeroize;

use crate::Encoder;

/// 暫存原始資料與編碼結果的大小。
const BUFFER: usize = 1024;

/// 從 `R` 讀進原始資料，讀出編碼後的文字。
///
/// 湊滿完整區塊就編碼；`R` 讀完時把不滿一個區塊的尾巴連同填充一起編碼。暫存的
/// 原始資料與編碼結果用完即清除。
///
/// ```
/// use std::io::Read;
///
/// use tc_encoders::{EncoderReader, base64};
///
/// let mut reader = EncoderReader::new(base64::DEFAULT, &b"hello"[..]);
/// let mut text = String::new();
/// reader.read_to_string(&mut text)?;
/// assert_eq!(text, "aGVsbG8=");
/// # Ok::<(), std::io::Error>(())
/// ```
pub struct EncoderReader<E: Encoder, R: Read> {
    encoder: E,
    inner: Option<R>,
    raw: [u8; BUFFER],
    raw_len: usize,
    encoded: [u8; BUFFER],
    encoded_start: usize,
    encoded_end: usize,
    finished: bool,
}

impl<E: Encoder, R: Read> EncoderReader<E, R> {
    /// 以 `encoder` 編碼從 `inner` 讀進的資料。
    /// 變動時間：不讀任何資料。
    pub fn new(encoder: E, inner: R) -> Self {
        const {
            assert!(E::ENCODED_BLOCK_SIZE > 0 && E::ENCODED_BLOCK_SIZE <= BUFFER);
            assert!(E::DECODED_BLOCK_SIZE > 0 && E::DECODED_BLOCK_SIZE <= E::ENCODED_BLOCK_SIZE);
        }
        Self {
            encoder,
            inner: Some(inner),
            raw: [0; BUFFER],
            raw_len: 0,
            encoded: [0; BUFFER],
            encoded_start: 0,
            encoded_end: 0,
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
        self.raw.zeroize();
        self.encoded.zeroize();
        self.raw_len = 0;
        self.encoded_start = 0;
        self.encoded_end = 0;
    }

    /// 讀一次 `R`，把完整的區塊編碼；`R` 讀完時連同尾巴與填充一起編碼。
    /// 常數時間：同 [`Encoder::encode`]；只依長度分支。
    fn fill(&mut self) -> io::Result<()> {
        // 編碼後不超過 `BUFFER` 的原始資料量。
        let capacity = BUFFER / E::ENCODED_BLOCK_SIZE * E::DECODED_BLOCK_SIZE;
        let inner = self.inner.as_mut().expect("present until into_inner");
        let read = inner.read(&mut self.raw[self.raw_len..capacity])?;
        let ready = if read == 0 {
            self.finished = true;
            self.raw_len
        } else {
            self.raw_len += read;
            self.raw_len / E::DECODED_BLOCK_SIZE * E::DECODED_BLOCK_SIZE
        };
        let encoded = self
            .encoder
            .encode(&self.raw[..ready], &mut self.encoded)
            .map_err(|error| io::Error::new(io::ErrorKind::InvalidInput, error))?;
        self.raw.copy_within(ready..self.raw_len, 0);
        self.raw[self.raw_len - ready..self.raw_len].zeroize();
        self.raw_len -= ready;
        self.encoded_start = 0;
        self.encoded_end = encoded;
        Ok(())
    }
}

impl<E: Encoder, R: Read> Read for EncoderReader<E, R> {
    /// 常數時間：同 [`Encoder::encode`]；只依長度分支。
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        if buf.is_empty() {
            return Ok(0);
        }
        while self.encoded_start == self.encoded_end {
            if self.finished {
                return Ok(0);
            }
            self.fill()?;
        }
        let available = &mut self.encoded[self.encoded_start..self.encoded_end];
        let len = available.len().min(buf.len());
        buf[..len].copy_from_slice(&available[..len]);
        available[..len].zeroize();
        self.encoded_start += len;
        Ok(len)
    }
}

impl<E: Encoder, R: Read> Drop for EncoderReader<E, R> {
    /// 清除暫存的原始資料與編碼結果。
    /// 常數時間：只寫零。
    fn drop(&mut self) {
        self.wipe();
    }
}
