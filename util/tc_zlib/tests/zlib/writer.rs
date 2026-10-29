//! Integration tests for `ZlibWriter` against the larger `lorem.zlib` fixture.

use super::helpers::{LOREM_ZLIB, lorem_corpus};
use std::io::Write;
use tc_zlib::{InflateOptions, ZlibWriter};

#[test]
fn decompress_lorem_in_one_call() {
    let mut writer = ZlibWriter::decompress(Vec::new(), InflateOptions::default());
    writer.write_all(LOREM_ZLIB).unwrap();
    let decoded = writer.finish().unwrap();
    assert_eq!(decoded, lorem_corpus());
}

#[test]
fn decompress_lorem_byte_by_byte() {
    // Single-byte writes through ~566 bytes of dynamic-Huffman input —
    // stresses the same incremental-input path that previously hung at the
    // header, but now also through `build_codes` and `decode_codes`.
    let mut writer = ZlibWriter::decompress(Vec::new(), InflateOptions::default());
    for b in LOREM_ZLIB {
        writer.write_all(&[*b]).unwrap();
    }
    let decoded = writer.finish().unwrap();
    assert_eq!(decoded, lorem_corpus());
}

#[test]
fn decompress_lorem_chunked_with_small_internal_buffer() {
    // Tiny chunks on the input side AND a tiny output buffer — forces the
    // writer's flush loop to iterate many times across non-trivial input.
    let mut writer = ZlibWriter::decompress(Vec::new(), InflateOptions::default().buf_size(7));
    for chunk in LOREM_ZLIB.chunks(13) {
        writer.write_all(chunk).unwrap();
    }
    let decoded = writer.finish().unwrap();
    assert_eq!(decoded, lorem_corpus());
}
