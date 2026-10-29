//! Shared helpers for zlib integration tests.

use std::io::{self, Read};

/// 12,600 bytes of deterministic text → 566 bytes compressed at zlib level 6
/// (BFINAL=1, BTYPE=10 = dynamic Huffman).  Exercises `build_codes`,
/// multi-byte Huffman codes, and non-trivial back-references.
pub const LOREM_ZLIB: &[u8] = include_bytes!("../data/lorem.zlib");

/// Reproduces the plaintext corpus that `testdata/lorem.zlib` was generated
/// from: 200 numbered lorem-ipsum lines, LF-terminated.
pub fn lorem_corpus() -> Vec<u8> {
    let mut out = Vec::with_capacity(13_000);
    for i in 0..200 {
        out.extend_from_slice(
            format!("[{i:04}] lorem ipsum dolor sit amet, consectetur adipiscing elit\n")
                .as_bytes(),
        );
    }
    out
}

/// `Read` adapter that yields exactly one byte per call.  Stresses the
/// short-inner-read path of `ZlibReader` (compaction, partial-input inflate).
pub struct OneByteAtATime<'a> {
    pub data: &'a [u8],
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
