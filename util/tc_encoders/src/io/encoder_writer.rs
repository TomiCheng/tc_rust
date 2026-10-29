//! 邊寫邊編碼的 `Write` 轉接器，取代 BC 的 `BufferedEncoder`。

use std::io::{self, Write};

use tc_zeroize::Zeroize;

use crate::Encoder;

/// 一次編碼寫出的上限；完整區塊以這個大小分批，不配置記憶體。
const OUT: usize = 1024;

/// 暫存不滿一個區塊的尾巴所需的大小，須不小於 `E::DECODED_BLOCK_SIZE`。
const PENDING: usize = 16;

/// 寫進來的原始資料編碼後寫進 `W`。
///
/// 不滿一個區塊的尾巴（Base64 最多 2 個位元組）先暫存，湊滿才編碼；
/// [`finish`](Self::finish) 補上最後一組與填充並交回 `W`。沒呼叫 `finish` 就
/// drop 時會盡力補完，但寫出的錯誤無從回報；要拿到錯誤請呼叫 `finish`。暫存的
/// 尾巴與編碼緩衝區用完即清除。
///
/// ```
/// use std::io::Write;
///
/// use tc_encoders::{EncoderWriter, base64};
///
/// let mut writer = EncoderWriter::new(base64::DEFAULT, Vec::new());
/// writer.write_all(b"hel")?;
/// writer.write_all(b"lo")?;
/// let text = writer.finish()?;
/// assert_eq!(text, b"aGVsbG8=");
/// # Ok::<(), std::io::Error>(())
/// ```
pub struct EncoderWriter<E: Encoder, W: Write> {
    encoder: E,
    inner: Option<W>,
    pending: [u8; PENDING],
    pending_len: usize,
}

impl<E: Encoder, W: Write> EncoderWriter<E, W> {
    /// 以 `encoder` 編碼、寫進 `inner`。
    /// 變動時間：不讀任何資料。
    pub fn new(encoder: E, inner: W) -> Self {
        const {
            assert!(E::DECODED_BLOCK_SIZE > 0 && E::DECODED_BLOCK_SIZE <= PENDING);
            assert!(E::ENCODED_BLOCK_SIZE > 0 && E::ENCODED_BLOCK_SIZE <= OUT);
        }
        Self {
            encoder,
            inner: Some(inner),
            pending: [0; PENDING],
            pending_len: 0,
        }
    }

    /// 回傳底下的 `W`。
    /// 變動時間：不讀任何資料。
    pub fn get_ref(&self) -> &W {
        self.inner.as_ref().expect("present until finish")
    }

    /// 編碼暫存的尾巴（含填充）、寫出並 flush，交回 `W`。
    /// 常數時間：同 [`Encoder::encode`]；寫出本身的時間由 `W` 決定。
    pub fn finish(mut self) -> io::Result<W> {
        self.write_tail()?;
        Ok(self.inner.take().expect("present until finish"))
    }

    /// 常數時間：同 [`Encoder::encode`]；只依暫存的長度分支。
    fn write_tail(&mut self) -> io::Result<()> {
        let Some(inner) = self.inner.as_mut() else {
            return Ok(());
        };
        let mut out = [0; OUT];
        let result = encode(&self.encoder, &self.pending[..self.pending_len], &mut out)
            .and_then(|len| inner.write_all(&out[..len]));
        out.zeroize();
        self.pending.zeroize();
        self.pending_len = 0;
        result?;
        inner.flush()
    }
}

/// 常數時間：同 [`Encoder::encode`]。
fn encode<E: Encoder>(encoder: &E, data: &[u8], out: &mut [u8]) -> io::Result<usize> {
    encoder
        .encode(data, out)
        .map_err(|error| io::Error::new(io::ErrorKind::InvalidInput, error))
}

impl<E: Encoder, W: Write> Write for EncoderWriter<E, W> {
    /// 一律取用整個 `buf`；不滿一個區塊的部分留到下次或 `finish`。
    /// 常數時間：同 [`Encoder::encode`]；只依長度分支。
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        let block = E::DECODED_BLOCK_SIZE;
        let inner = self.inner.as_mut().expect("present until finish");
        let mut out = [0; OUT];
        let mut input = buf;
        let mut result = Ok(());
        if self.pending_len > 0 {
            let take = (block - self.pending_len).min(input.len());
            self.pending[self.pending_len..self.pending_len + take].copy_from_slice(&input[..take]);
            self.pending_len += take;
            input = &input[take..];
            if self.pending_len == block {
                result = encode(&self.encoder, &self.pending[..block], &mut out)
                    .and_then(|len| inner.write_all(&out[..len]));
                self.pending.zeroize();
                self.pending_len = 0;
            }
        }
        let full = input.len() / block * block;
        let chunk = OUT / E::ENCODED_BLOCK_SIZE * block;
        for piece in input[..full].chunks(chunk) {
            if result.is_err() {
                break;
            }
            result =
                encode(&self.encoder, piece, &mut out).and_then(|len| inner.write_all(&out[..len]));
        }
        out.zeroize();
        result?;
        let rest = &input[full..];
        self.pending[self.pending_len..self.pending_len + rest.len()].copy_from_slice(rest);
        self.pending_len += rest.len();
        Ok(buf.len())
    }

    /// 只 flush 底下的 `W`；暫存的尾巴要到 [`finish`](Self::finish) 才寫出，因為
    /// 它可能需要填充。
    /// 變動時間：不讀任何資料。
    fn flush(&mut self) -> io::Result<()> {
        self.inner.as_mut().expect("present until finish").flush()
    }
}

impl<E: Encoder, W: Write> Drop for EncoderWriter<E, W> {
    /// 沒呼叫 `finish` 時盡力寫出尾巴並忽略錯誤；暫存一律清除。
    /// 常數時間：同 [`Encoder::encode`]；寫出本身的時間由 `W` 決定。
    fn drop(&mut self) {
        let _ = self.write_tail();
        self.pending.zeroize();
    }
}
