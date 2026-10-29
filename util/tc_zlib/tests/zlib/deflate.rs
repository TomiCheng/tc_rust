//! Integration tests pinning the public-API contract of compression behavior
//! (the deflate side of `ZlibWriter` / `ZlibReader`).

use std::io::{Cursor, Read, Write};
use tc_zlib::{DeflateOptions, InflateOptions, Strategy, ZlibReader, ZlibWriter};

/// `ZlibWriter::finish()` must drive the deflate engine to completion so the
/// final block + Adler-32 trailer get written.  For empty input that means
/// the canonical 8-byte zlib stream — the absolute minimum a valid zlib
/// stream can be.
///
/// Regression target for the bug where `finish()` only flushed the inner
/// writer (never calling `deflate(_, _, Finish)`), so empty input round-tripped
/// only by accident — both ends produced 0 bytes.
#[test]
fn finish_emits_zlib_trailer_for_empty_input() {
    let mut w = ZlibWriter::compress(
        Vec::new(),
        DeflateOptions::default().strategy(Strategy::Fixed),
    );
    w.write_all(b"").unwrap();
    let comp = w.finish().unwrap();

    // Lower bound: 2-byte header + ≥2 bytes of EOB block + 4-byte Adler-32.
    assert!(
        comp.len() >= 8,
        "empty zlib stream must be at least 8 bytes; got {}: {:02x?}",
        comp.len(),
        comp
    );
    // Trailing 4 bytes are big-endian Adler-32 of empty input == 1.
    assert_eq!(
        &comp[comp.len() - 4..],
        &[0x00, 0x00, 0x00, 0x01],
        "trailer must be Adler-32(empty)=1 big-endian; full stream: {:02x?}",
        comp
    );
}

/// Same idea for non-empty input: `finish()` must emit the Adler-32 trailer
/// matching the input bytes.
#[test]
fn finish_emits_correct_adler32_trailer() {
    // Adler-32("hello") = 0x062c0215 — verified against Python's zlib.adler32.
    let plain = b"hello";
    let expected_adler: [u8; 4] = [0x06, 0x2c, 0x02, 0x15];

    let mut w = ZlibWriter::compress(
        Vec::new(),
        DeflateOptions::default().strategy(Strategy::Fixed),
    );
    w.write_all(plain).unwrap();
    let comp = w.finish().unwrap();

    assert!(
        comp.len() >= 4,
        "stream too short to contain a trailer: {} bytes",
        comp.len()
    );
    assert_eq!(
        &comp[comp.len() - 4..],
        &expected_adler,
        "trailer must be Adler-32({:?}) big-endian; got stream: {:02x?}",
        plain,
        comp
    );
}

/// `Strategy::Default` (dynamic Huffman) on empty input forces
/// `build_tree_l` / `build_tree_d` to invent two placeholder leaves to
/// satisfy DEFLATE's "at least two codes" rule.  They `wrapping_sub` from
/// `opt_len` / `static_len` to pre-cancel the artificial contribution, then
/// `gen_bitlen_l` / `gen_bitlen_d` are supposed to add it back so the
/// running total ends up at zero.  The C original relies on unsigned wrap;
/// `gen_bitlen` in our port used non-wrapping `+=` (deflate.rs:1204/1205/
/// 1431/1432) so it panicked instead.
#[test]
fn writer_compress_empty_default_strategy() {
    let mut w = ZlibWriter::compress(Vec::new(), DeflateOptions::default());
    w.write_all(b"").unwrap();
    let comp = w.finish().unwrap();

    // ≥ 8 bytes is the floor for any valid zlib stream.
    assert!(
        comp.len() >= 8,
        "empty stream too short ({} bytes): {:02x?}",
        comp.len(),
        comp
    );

    // Round-trip back to verify the produced bytes are a valid zlib stream.
    let mut r = ZlibReader::decompress(Cursor::new(&comp), InflateOptions::default());
    let mut decoded = Vec::new();
    r.read_to_end(&mut decoded).unwrap();
    assert_eq!(decoded, b"");
}

#[test]
fn reader_compress_empty_default_strategy() {
    // Same bug, hit through the reader-compress path: ZlibReader sees inner
    // EOF immediately, switches to FlushMode::Finish, and dives into the
    // dynamic-Huffman builder.
    let mut rc = ZlibReader::compress(Cursor::new(Vec::<u8>::new()), DeflateOptions::default());
    let mut comp = Vec::new();
    rc.read_to_end(&mut comp).unwrap();

    assert!(
        comp.len() >= 8,
        "empty stream too short ({} bytes): {:02x?}",
        comp.len(),
        comp
    );

    let mut r = ZlibReader::decompress(Cursor::new(&comp), InflateOptions::default());
    let mut decoded = Vec::new();
    r.read_to_end(&mut decoded).unwrap();
    assert_eq!(decoded, b"");
}
