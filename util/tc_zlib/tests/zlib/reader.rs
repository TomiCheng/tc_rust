//! Integration tests for `ZlibReader` against the larger `lorem.zlib` fixture.

use super::helpers::{LOREM_ZLIB, OneByteAtATime, lorem_corpus};
use std::io::Read;
use tc_zlib::{InflateOptions, ZlibReader};

#[test]
fn decompress_lorem_via_short_inner_and_small_buffers() {
    // Inner reader hands us 1 byte per call AND we shrink the engine's
    // input/output buffers to 7 bytes — so the reader has to compact and
    // re-fill the input slice many times across non-trivial dynamic
    // Huffman input.
    let inner = OneByteAtATime { data: LOREM_ZLIB };
    let mut reader = ZlibReader::decompress(inner, InflateOptions::default().buf_size(7));
    let mut decoded = Vec::new();
    reader.read_to_end(&mut decoded).unwrap();
    assert_eq!(decoded, lorem_corpus());
}
