//! 對應 bc-csharp 的 `ZInputStream.cs`：從底下的 `Read` 讀進資料，讀出時壓縮或解壓。

use std::io::{self, Read};

use crate::constants::FlushMode;
use crate::deflate::DeflateState;
use crate::deflate_options::DeflateOptions;
use crate::inflate::InflateState;
use crate::inflate_options::InflateOptions;
use crate::stream::{self, Engine, Status};

/// 讀出時壓縮或解壓的 zlib reader。
///
/// 模式在建構時以 [`ZlibReader::compress`] 或 [`ZlibReader::decompress`] 決定。
///
/// ```
/// use std::io::Read;
/// use tc_zlib::{DeflateOptions, InflateOptions, ZlibReader};
///
/// let mut compressed = Vec::new();
/// ZlibReader::compress(&b"hello world"[..], DeflateOptions::default())
///     .read_to_end(&mut compressed)
///     .unwrap();
///
/// let mut plain = Vec::new();
/// ZlibReader::decompress(&compressed[..], InflateOptions::default())
///     .read_to_end(&mut plain)
///     .unwrap();
/// assert_eq!(plain, b"hello world");
/// ```
pub struct ZlibReader<R: Read> {
    inner: R,
    engine: Engine,
    buf: Vec<u8>,
    start: usize,
    end: usize,
    eof: bool,
    done: bool,
}

impl<R: Read> ZlibReader<R> {
    /// 建立壓縮用的 reader。
    /// 變動時間：不讀任何資料。
    pub fn compress(inner: R, options: DeflateOptions) -> Self {
        Self::new(
            inner,
            Engine::Deflate(Box::new(DeflateState::new(&options))),
            options.buf_size,
        )
    }

    /// 建立解壓用的 reader。
    /// 變動時間：不讀任何資料。
    pub fn decompress(inner: R, options: InflateOptions) -> Self {
        Self::new(
            inner,
            Engine::Inflate(Box::new(InflateState::new(&options))),
            options.buf_size,
        )
    }

    fn new(inner: R, engine: Engine, buf_size: usize) -> Self {
        Self {
            inner,
            engine,
            buf: vec![0; buf_size],
            start: 0,
            end: 0,
            eof: false,
            done: false,
        }
    }

    /// 回傳底下的 `R`。
    /// 變動時間：不讀任何資料。
    pub fn get_ref(&self) -> &R {
        &self.inner
    }

    /// 交回底下的 `R`；已讀進但還沒處理的資料就此丟棄。
    /// 變動時間：不讀任何資料。
    pub fn into_inner(self) -> R {
        self.inner
    }
}

impl<R: Read> Read for ZlibReader<R> {
    /// 解壓時，底下的 `R` 在串流結束前就讀完會回傳 `UnexpectedEof`；串流結束後的
    /// 資料不讀。
    /// 變動時間：依資料內容分支，只能用於公開值。
    fn read(&mut self, out: &mut [u8]) -> io::Result<usize> {
        if out.is_empty() || self.done {
            return Ok(0);
        }
        loop {
            if self.start == self.end && !self.eof {
                self.start = 0;
                self.end = self.inner.read(&mut self.buf)?;
                self.eof = self.end == 0;
            }
            let flush = if self.eof {
                FlushMode::Finish
            } else {
                FlushMode::NoFlush
            };
            let step = self.engine.run(&self.buf[self.start..self.end], out, flush);
            self.start += step.read;
            stream::data_error(step.status)?;
            if step.status == Status::StreamEnd {
                self.done = true;
                return Ok(step.written);
            }
            if step.written > 0 {
                return Ok(step.written);
            }
            if self.eof {
                return Err(stream::truncated());
            }
            if step.read == 0 && self.start < self.end {
                return Err(stream::stalled());
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::{Cursor, Read};

    /// Pre-computed zlib-wrapped stream for `b"Hello, World!"` (fixed Huffman).
    const HELLO_ZLIB: &[u8] = &[
        0x78, 0x9c, 0xf3, 0x48, 0xcd, 0xc9, 0xc9, 0xd7, 0x51, 0x08, 0xcf, 0x2f, 0xca, 0x49, 0x51,
        0x04, 0x00, 0x1f, 0x9e, 0x04, 0x6a,
    ];

    /// Pre-computed zlib stream for an empty input.
    const EMPTY_ZLIB: &[u8] = &[0x78, 0x9c, 0x03, 0x00, 0x00, 0x00, 0x00, 0x01];

    // ── decompression path (uses fully-implemented InflateState) ─────────────

    #[test]
    fn decompress_fixed_huffman_read_to_end() {
        let mut reader = ZlibReader::decompress(Cursor::new(HELLO_ZLIB), InflateOptions::default());
        let mut decoded = Vec::new();
        reader.read_to_end(&mut decoded).unwrap();
        assert_eq!(decoded, b"Hello, World!");
    }

    #[test]
    fn decompress_empty_stream() {
        let mut reader = ZlibReader::decompress(Cursor::new(EMPTY_ZLIB), InflateOptions::default());
        let mut decoded = Vec::new();
        reader.read_to_end(&mut decoded).unwrap();
        assert!(decoded.is_empty());
    }

    #[test]
    fn decompress_one_byte_at_a_time() {
        // Caller-side: tiny output buffer that forces many `read` calls.
        let mut reader = ZlibReader::decompress(Cursor::new(HELLO_ZLIB), InflateOptions::default());
        let mut decoded = Vec::new();
        let mut byte = [0u8; 1];
        loop {
            let n = reader.read(&mut byte).unwrap();
            if n == 0 {
                break;
            }
            decoded.extend_from_slice(&byte[..n]);
        }
        assert_eq!(decoded, b"Hello, World!");
    }

    #[test]
    fn decompress_with_small_internal_buffer() {
        // Engine-side: tiny input and output buffers force many compact /
        // refill / process iterations.
        let mut reader = ZlibReader::decompress(
            Cursor::new(HELLO_ZLIB),
            InflateOptions::default().buf_size(4),
        );
        let mut decoded = Vec::new();
        reader.read_to_end(&mut decoded).unwrap();
        assert_eq!(decoded, b"Hello, World!");
    }

    #[test]
    fn decompress_raw_deflate_stream() {
        // Hand-encoded raw deflate of "ABCABCABC" (fixed Huffman + back-reference).
        let stream: &[u8] = &[0x73, 0x74, 0x72, 0x86, 0x20, 0x00];
        let mut reader =
            ZlibReader::decompress(Cursor::new(stream), InflateOptions::default().nowrap(true));
        let mut decoded = Vec::new();
        reader.read_to_end(&mut decoded).unwrap();
        assert_eq!(decoded, b"ABCABCABC");
    }

    #[test]
    fn decompress_into_caller_chunks() {
        // The caller hands us output buffers of varying sizes.
        let mut reader = ZlibReader::decompress(Cursor::new(HELLO_ZLIB), InflateOptions::default());
        let mut chunk = [0u8; 5];
        let mut decoded = Vec::new();
        loop {
            let n = reader.read(&mut chunk).unwrap();
            if n == 0 {
                break;
            }
            decoded.extend_from_slice(&chunk[..n]);
        }
        assert_eq!(decoded, b"Hello, World!");
    }

    #[test]
    fn empty_read_buffer_returns_zero() {
        let mut reader = ZlibReader::decompress(Cursor::new(HELLO_ZLIB), InflateOptions::default());
        let mut empty: [u8; 0] = [];
        assert_eq!(reader.read(&mut empty).unwrap(), 0);
    }

    #[test]
    fn read_after_eof_returns_zero() {
        let mut reader = ZlibReader::decompress(Cursor::new(EMPTY_ZLIB), InflateOptions::default());
        // Drain the stream first.
        let mut sink = Vec::new();
        reader.read_to_end(&mut sink).unwrap();
        // Subsequent reads should keep returning EOF (Ok(0)).
        let mut buf = [0u8; 16];
        assert_eq!(reader.read(&mut buf).unwrap(), 0);
        assert_eq!(reader.read(&mut buf).unwrap(), 0);
    }

    #[test]
    fn inner_and_into_inner_accessors() {
        let reader = ZlibReader::decompress(Cursor::new(HELLO_ZLIB), InflateOptions::default());
        // `get_ref()` — borrow the wrapped reader.
        assert_eq!(reader.get_ref().get_ref(), &HELLO_ZLIB);
        // `into_inner()` — recover ownership.
        let cursor = reader.into_inner();
        assert_eq!(cursor.get_ref(), &HELLO_ZLIB);
    }

    #[test]
    fn decompress_short_inner_reads() {
        // Wrap the source in a reader that yields at most 1 byte per call.
        // This exercises the "inner returned less than requested" path.
        struct OneByteAtATime<'a> {
            data: &'a [u8],
        }
        impl<'a> Read for OneByteAtATime<'a> {
            fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
                if self.data.is_empty() || buf.is_empty() {
                    return Ok(0);
                }
                buf[0] = self.data[0];
                self.data = &self.data[1..];
                Ok(1)
            }
        }

        let inner = OneByteAtATime { data: HELLO_ZLIB };
        let mut reader = ZlibReader::decompress(inner, InflateOptions::default());
        let mut decoded = Vec::new();
        reader.read_to_end(&mut decoded).unwrap();
        assert_eq!(decoded, b"Hello, World!");
    }

    // NOTE: tests using the larger `testdata/lorem.zlib` dynamic-Huffman fixture
    // live in `tests/util/zlib/zlib_reader.rs`, alongside the fixture file.

    // NOTE: Compression / round-trip tests intentionally omitted.
    // `DeflateState` is still being stabilised; round-trip tests through
    // `ZlibReader::compress` should be added once deflate is verified
    // independently.  All tests above exercise the decompression path only,
    // which goes through the fully-implemented `InflateState`.
}
