//! 對應 bc-csharp 的 `ZOutputStream.cs`：寫入時壓縮或解壓，再交給底下的 `Write`。

use std::io::{self, Write};

use crate::constants::FlushMode;
use crate::deflate::DeflateState;
use crate::deflate_options::DeflateOptions;
use crate::inflate::InflateState;
use crate::inflate_options::InflateOptions;
use crate::stream::{self, Engine, Status};

/// 寫入時壓縮或解壓的 zlib writer。
///
/// 模式在建構時以 [`ZlibWriter::compress`] 或 [`ZlibWriter::decompress`] 決定；
/// 寫完要呼叫 [`ZlibWriter::finish`]，否則壓縮串流缺少結尾。
///
/// ```
/// use std::io::Write;
/// use tc_zlib::{DeflateOptions, InflateOptions, ZlibWriter};
///
/// let mut writer = ZlibWriter::compress(Vec::new(), DeflateOptions::default());
/// writer.write_all(b"hello world").unwrap();
/// let compressed = writer.finish().unwrap();
///
/// let mut writer = ZlibWriter::decompress(Vec::new(), InflateOptions::default());
/// writer.write_all(&compressed).unwrap();
/// assert_eq!(writer.finish().unwrap(), b"hello world");
/// ```
pub struct ZlibWriter<W: Write> {
    inner: W,
    engine: Engine,
    buf: Vec<u8>,
}

impl<W: Write> ZlibWriter<W> {
    /// 建立壓縮用的 writer。
    /// 變動時間：不讀任何資料。
    pub fn compress(inner: W, options: DeflateOptions) -> Self {
        Self {
            inner,
            engine: Engine::Deflate(Box::new(DeflateState::new(&options))),
            buf: vec![0; options.buf_size],
        }
    }

    /// 建立解壓用的 writer。
    /// 變動時間：不讀任何資料。
    pub fn decompress(inner: W, options: InflateOptions) -> Self {
        Self {
            inner,
            engine: Engine::Inflate(Box::new(InflateState::new(&options))),
            buf: vec![0; options.buf_size],
        }
    }

    /// 回傳底下的 `W`。
    /// 變動時間：不讀任何資料。
    pub fn get_ref(&self) -> &W {
        &self.inner
    }

    /// 寫出剩下的資料並交回底下的 `W`。壓縮時寫出最後區塊與檢查碼；解壓時串流
    /// 若還沒結束，回傳 `UnexpectedEof`。
    /// 變動時間：依資料內容分支，只能用於公開值。
    pub fn finish(mut self) -> io::Result<W> {
        loop {
            let step = self.engine.run(&[], &mut self.buf, FlushMode::Finish);
            self.inner.write_all(&self.buf[..step.written])?;
            stream::data_error(step.status)?;
            match step.status {
                Status::StreamEnd => break,
                _ if step.written == 0 => return Err(stream::truncated()),
                _ => {}
            }
        }
        self.inner.flush()?;
        Ok(self.inner)
    }
}

impl<W: Write> Write for ZlibWriter<W> {
    /// 解壓時，串流結束後還有資料會回傳 `InvalidData`。
    /// 變動時間：依資料內容分支，只能用於公開值。
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        if buf.is_empty() {
            return Ok(0);
        }
        let mut input = buf;
        loop {
            let step = self.engine.run(input, &mut self.buf, FlushMode::NoFlush);
            self.inner.write_all(&self.buf[..step.written])?;
            input = &input[step.read..];
            stream::data_error(step.status)?;
            if step.status == Status::StreamEnd && !input.is_empty() {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidData,
                    "data after the end of the zlib stream",
                ));
            }
            // 輸出緩衝區被填滿時，引擎裡可能還有待寫出的資料。
            if input.is_empty() && step.written < self.buf.len() {
                break;
            }
            if step.read == 0 && step.written == 0 {
                return Err(stream::stalled());
            }
        }
        Ok(buf.len())
    }

    /// 變動時間：只轉給底下的 `W`，不碰資料。
    fn flush(&mut self) -> io::Result<()> {
        self.inner.flush()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A pre-computed zlib-wrapped stream for `b"Hello, World!"` (fixed Huffman).
    const HELLO_ZLIB: &[u8] = &[
        0x78, 0x9c, 0xf3, 0x48, 0xcd, 0xc9, 0xc9, 0xd7, 0x51, 0x08, 0xcf, 0x2f, 0xca, 0x49, 0x51,
        0x04, 0x00, 0x1f, 0x9e, 0x04, 0x6a,
    ];

    /// Pre-computed zlib stream for an empty input — `0x789c 0x0300 0x0000 0x0001`.
    const EMPTY_ZLIB: &[u8] = &[0x78, 0x9c, 0x03, 0x00, 0x00, 0x00, 0x00, 0x01];

    // ── decompression path (uses fully-implemented InflateState) ─────────────

    #[test]
    fn decompress_fixed_huffman() {
        let out: Vec<u8> = Vec::new();
        let mut writer = ZlibWriter::decompress(out, InflateOptions::default());
        writer.write_all(HELLO_ZLIB).unwrap();
        let decoded = writer.finish().unwrap();
        assert_eq!(decoded, b"Hello, World!");
    }

    #[test]
    fn decompress_empty_stream() {
        let mut writer = ZlibWriter::decompress(Vec::new(), InflateOptions::default());
        writer.write_all(EMPTY_ZLIB).unwrap();
        let decoded = writer.finish().unwrap();
        assert_eq!(decoded, b"");
    }

    #[test]
    fn decompress_byte_by_byte_input() {
        // Same payload, but written one byte per `write` call — exercises
        // the multi-call inflate path (back-references crossing input chunks).
        let mut writer = ZlibWriter::decompress(Vec::new(), InflateOptions::default());
        for b in HELLO_ZLIB {
            writer.write_all(&[*b]).unwrap();
        }
        let decoded = writer.finish().unwrap();
        assert_eq!(decoded, b"Hello, World!");
    }

    #[test]
    fn decompress_in_arbitrary_chunks() {
        // Alternate small / large writes to exercise the buffer-flush loop.
        let chunks: &[&[u8]] = &[&HELLO_ZLIB[..3], &HELLO_ZLIB[3..7], &HELLO_ZLIB[7..]];
        let mut writer = ZlibWriter::decompress(Vec::new(), InflateOptions::default());
        for chunk in chunks {
            writer.write_all(chunk).unwrap();
        }
        let decoded = writer.finish().unwrap();
        assert_eq!(decoded, b"Hello, World!");
    }

    #[test]
    fn empty_write_returns_zero() {
        let mut writer = ZlibWriter::decompress(Vec::new(), InflateOptions::default());
        let n = writer.write(b"").unwrap();
        assert_eq!(n, 0);
    }

    #[test]
    fn finish_returns_inner_writer() {
        let mut writer = ZlibWriter::decompress(Vec::new(), InflateOptions::default());
        writer.write_all(EMPTY_ZLIB).unwrap();
        // `finish()` consumes the wrapper and yields ownership of `Vec<u8>`.
        let inner: Vec<u8> = writer.finish().unwrap();
        assert_eq!(inner, b"");
    }

    #[test]
    fn decompress_with_small_internal_buffer() {
        // Force the internal output buffer to be tiny so the inner write loop
        // has to iterate many times to flush all decompressed output.
        let mut writer = ZlibWriter::decompress(Vec::new(), InflateOptions::default().buf_size(4));
        writer.write_all(HELLO_ZLIB).unwrap();
        let decoded = writer.finish().unwrap();
        assert_eq!(decoded, b"Hello, World!");
    }

    #[test]
    fn decompress_raw_deflate_stream() {
        // Hand-encoded raw deflate of "ABCABCABC" (fixed Huffman block with a
        // length-6 / distance-3 back-reference; no zlib wrapper).
        let stream: &[u8] = &[0x73, 0x74, 0x72, 0x86, 0x20, 0x00];
        let mut writer = ZlibWriter::decompress(Vec::new(), InflateOptions::default().nowrap(true));
        writer.write_all(stream).unwrap();
        let decoded = writer.finish().unwrap();
        assert_eq!(decoded, b"ABCABCABC");
    }

    // NOTE: tests using the larger `testdata/lorem.zlib` dynamic-Huffman fixture
    // live in `tests/util/zlib/zlib_writer.rs`, alongside the fixture file.

    // NOTE: Compression / round-trip tests intentionally omitted.
    // `DeflateState` is still being stabilised; round-trip tests through
    // `ZlibWriter::compress` should be added once deflate is verified
    // independently.  All tests above exercise the decompression path only,
    // which goes through the fully-implemented `InflateState`.
}
