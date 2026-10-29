//! 邊寫邊解碼的 `Write` 轉接器；BC 沒有對應的類別。

use std::io::{self, Write};

use tc_zeroize::Zeroize;

use crate::whitespace::is_whitespace;
use crate::{Encoder, EncoderError};

/// 暫存編碼文字（已去掉空白）與解碼結果的大小。
const BUFFER: usize = 1024;

/// 寫進來的編碼文字解碼後寫進 `W`。
///
/// 照 [`Encoder::decode`] 略過空白。最後一個完整的組與不完整的尾巴留到
/// [`finish`](Self::finish) 才解碼，因為只有最後一組可以帶填充；在那之前的組經過
/// [`Encoder::decode_blocks`]，出現填充就是錯誤。解碼錯誤以 `InvalidData` 回報。
/// 沒呼叫 `finish` 就 drop 時會盡力補完，但錯誤無從回報；要拿到錯誤請呼叫
/// `finish`。暫存的文字與解碼結果用完即清除。
///
/// ```
/// use std::io::Write;
///
/// use tc_encoders::{DecoderWriter, base64};
///
/// let mut writer = DecoderWriter::new(base64::DEFAULT, Vec::new());
/// writer.write_all(b"aGVs\n")?;
/// writer.write_all(b"bG8=")?;
/// let bytes = writer.finish()?;
/// assert_eq!(bytes, b"hello");
/// # Ok::<(), std::io::Error>(())
/// ```
pub struct DecoderWriter<E: Encoder, W: Write> {
    encoder: E,
    inner: Option<W>,
    text: [u8; BUFFER],
    text_len: usize,
}

impl<E: Encoder, W: Write> DecoderWriter<E, W> {
    /// 以 `encoder` 解碼、寫進 `inner`。
    /// 變動時間：不讀任何資料。
    pub fn new(encoder: E, inner: W) -> Self {
        const {
            assert!(E::ENCODED_BLOCK_SIZE > 0 && 2 * E::ENCODED_BLOCK_SIZE < BUFFER);
            assert!(E::DECODED_BLOCK_SIZE <= E::ENCODED_BLOCK_SIZE);
        }
        Self {
            encoder,
            inner: Some(inner),
            text: [0; BUFFER],
            text_len: 0,
        }
    }

    /// 回傳底下的 `W`。
    /// 變動時間：不讀任何資料。
    pub fn get_ref(&self) -> &W {
        self.inner.as_ref().expect("present until finish")
    }

    /// 解碼暫存的最後一組與尾巴、寫出並 flush，交回 `W`。
    /// 常數時間：同 [`Encoder::decode`]；只依長度分支；寫出本身的時間由 `W` 決定。
    pub fn finish(mut self) -> io::Result<W> {
        self.write_tail()?;
        Ok(self.inner.take().expect("present until finish"))
    }

    /// 解碼能確定不是最後一段的完整組並寫出，其餘留著。
    /// 常數時間：同 [`Encoder::decode_blocks`]；只依長度分支。
    fn drain(&mut self, decoded: &mut [u8; BUFFER]) -> io::Result<()> {
        let block = E::ENCODED_BLOCK_SIZE;
        let ready = (self.text_len / block).saturating_sub(1) * block;
        if ready == 0 {
            return Ok(());
        }
        let inner = self.inner.as_mut().expect("present until finish");
        let len = self
            .encoder
            .decode_blocks(&self.text[..ready], decoded)
            .map_err(invalid_data)?;
        inner.write_all(&decoded[..len])?;
        self.text.copy_within(ready..self.text_len, 0);
        self.text[self.text_len - ready..self.text_len].zeroize();
        self.text_len -= ready;
        Ok(())
    }

    /// 常數時間：同 [`Encoder::decode`]；只依長度分支。
    fn write_tail(&mut self) -> io::Result<()> {
        let Some(inner) = self.inner.as_mut() else {
            return Ok(());
        };
        let mut decoded = [0; BUFFER];
        let result = self
            .encoder
            .decode(&self.text[..self.text_len], &mut decoded)
            .map_err(invalid_data)
            .and_then(|len| inner.write_all(&decoded[..len]));
        decoded.zeroize();
        self.text.zeroize();
        self.text_len = 0;
        result?;
        inner.flush()
    }
}

/// 變動時間：只依錯誤種類分支。
fn invalid_data(error: EncoderError) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidData, error)
}

impl<E: Encoder, W: Write> Write for DecoderWriter<E, W> {
    /// 一律取用整個 `buf`；最後一組與尾巴留到下次或 `finish`。
    /// 常數時間：同 [`Encoder::decode_blocks`]；只依空白的位置與長度分支。
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        let mut decoded = [0; BUFFER];
        let mut result = Ok(());
        for &c in buf {
            if is_whitespace(c) {
                continue;
            }
            self.text[self.text_len] = c;
            self.text_len += 1;
            if self.text_len == BUFFER {
                result = self.drain(&mut decoded);
                if result.is_err() {
                    break;
                }
            }
        }
        if result.is_ok() {
            result = self.drain(&mut decoded);
        }
        decoded.zeroize();
        result?;
        Ok(buf.len())
    }

    /// 只 flush 底下的 `W`；最後一組與尾巴要到 [`finish`](Self::finish) 才解碼，
    /// 因為它可能帶填充。
    /// 變動時間：不讀任何資料。
    fn flush(&mut self) -> io::Result<()> {
        self.inner.as_mut().expect("present until finish").flush()
    }
}

impl<E: Encoder, W: Write> Drop for DecoderWriter<E, W> {
    /// 沒呼叫 `finish` 時盡力解碼並寫出尾巴、忽略錯誤；暫存一律清除。
    /// 常數時間：同 [`Encoder::decode`]；寫出本身的時間由 `W` 決定。
    fn drop(&mut self) {
        let _ = self.write_tail();
        self.text.zeroize();
    }
}
