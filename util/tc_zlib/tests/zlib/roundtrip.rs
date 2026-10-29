//! Round-trip integration tests: compress with deflate, decompress with inflate,
//! and vice versa.  Exercises the public crate API (`ZlibWriter`, `ZlibReader`).
//!
//! `Strategy::Default` (the dynamic-Huffman path of `DeflateState`) is
//! deliberately avoided — that path is still being stabilised; see
//! `src/util/zlib/CLAUDE.md`.  The fixed-Huffman, run-length, Huffman-only,
//! and stored-block paths all round-trip cleanly today and are exercised here.

use super::helpers::lorem_corpus;
use std::io::{Cursor, Read, Write};
use tc_zlib::{CompressionLevel, DeflateOptions, InflateOptions, Strategy, ZlibReader, ZlibWriter};

// ── fixtures ─────────────────────────────────────────────────────────────────

const HELLO: &[u8] = b"Hello, World!";

// ── helpers ──────────────────────────────────────────────────────────────────

/// Compress via `ZlibWriter::compress`, decompress via `ZlibReader::decompress`,
/// assert the result equals the input.
fn roundtrip_w_to_r(plain: &[u8], dopts: DeflateOptions, iopts: InflateOptions) {
    let mut w = ZlibWriter::compress(Vec::new(), dopts);
    w.write_all(plain).unwrap();
    let comp = w.finish().unwrap();

    let mut r = ZlibReader::decompress(Cursor::new(&comp), iopts);
    let mut decoded = Vec::new();
    r.read_to_end(&mut decoded).unwrap();
    assert_eq!(decoded, plain);
}

/// Compress via `ZlibReader::compress`, decompress via `ZlibWriter::decompress`,
/// assert the result equals the input.
fn roundtrip_r_to_w(plain: &[u8], dopts: DeflateOptions, iopts: InflateOptions) {
    let mut rc = ZlibReader::compress(Cursor::new(plain.to_vec()), dopts);
    let mut comp = Vec::new();
    rc.read_to_end(&mut comp).unwrap();

    let mut wd = ZlibWriter::decompress(Vec::new(), iopts);
    wd.write_all(&comp).unwrap();
    let decoded = wd.finish().unwrap();
    assert_eq!(decoded, plain);
}

// ── basic round-trips: writer → reader ───────────────────────────────────────

#[test]
fn empty_w_to_r() {
    roundtrip_w_to_r(b"", DeflateOptions::default(), InflateOptions::default());
}

#[test]
fn hello_w_to_r_fixed_huffman() {
    roundtrip_w_to_r(
        HELLO,
        DeflateOptions::default().strategy(Strategy::Fixed),
        InflateOptions::default(),
    );
}

#[test]
fn lorem_w_to_r_fixed_huffman() {
    roundtrip_w_to_r(
        &lorem_corpus(),
        DeflateOptions::default().strategy(Strategy::Fixed),
        InflateOptions::default(),
    );
}

#[test]
fn lorem_w_to_r_huffman_only() {
    // Strategy::HuffmanOnly disables string matching — every byte becomes a
    // literal. Useful sanity check that the literal-only encode path works.
    roundtrip_w_to_r(
        &lorem_corpus(),
        DeflateOptions::default().strategy(Strategy::HuffmanOnly),
        InflateOptions::default(),
    );
}

#[test]
fn lorem_w_to_r_rle() {
    // Strategy::Rle limits match distance to 1 — pure run-length matches.
    roundtrip_w_to_r(
        &lorem_corpus(),
        DeflateOptions::default().strategy(Strategy::Rle),
        InflateOptions::default(),
    );
}

#[test]
fn lorem_w_to_r_no_compression() {
    // CompressionLevel::None forces stored (uncompressed) blocks.
    roundtrip_w_to_r(
        &lorem_corpus(),
        DeflateOptions::default().level(CompressionLevel::None),
        InflateOptions::default(),
    );
}

// ── basic round-trips: reader → writer ───────────────────────────────────────

#[test]
fn empty_r_to_w() {
    roundtrip_r_to_w(b"", DeflateOptions::default(), InflateOptions::default());
}

#[test]
fn lorem_r_to_w_fixed_huffman() {
    roundtrip_r_to_w(
        &lorem_corpus(),
        DeflateOptions::default().strategy(Strategy::Fixed),
        InflateOptions::default(),
    );
}

#[test]
fn lorem_r_to_w_no_compression() {
    roundtrip_r_to_w(
        &lorem_corpus(),
        DeflateOptions::default().level(CompressionLevel::None),
        InflateOptions::default(),
    );
}

// ── raw deflate (no zlib wrapper) on both sides ──────────────────────────────

#[test]
fn lorem_w_to_r_raw_deflate() {
    let plain = lorem_corpus();
    roundtrip_w_to_r(
        &plain,
        DeflateOptions::default()
            .nowrap(true)
            .strategy(Strategy::Fixed),
        InflateOptions::default().nowrap(true),
    );
}

// ── chunking stress ──────────────────────────────────────────────────────────

#[test]
fn lorem_byte_by_byte_compress_then_decompress() {
    // Feed plaintext into the compressor one byte per write — exercises the
    // sliding-window fill / tally path under maximum call fragmentation.
    let plain = lorem_corpus();
    let mut w = ZlibWriter::compress(
        Vec::new(),
        DeflateOptions::default().strategy(Strategy::Fixed),
    );
    for b in &plain {
        w.write_all(&[*b]).unwrap();
    }
    let comp = w.finish().unwrap();

    let mut r = ZlibReader::decompress(Cursor::new(&comp), InflateOptions::default());
    let mut decoded = Vec::new();
    r.read_to_end(&mut decoded).unwrap();
    assert_eq!(decoded, plain);
}

#[test]
fn lorem_compress_then_decompress_byte_by_byte() {
    // Same payload, but feed the compressed bytes into the decompressor one at
    // a time — covers the writer-side bug fixed in 58a741a from the producer
    // angle (real compressed input rather than a pre-baked fixture).
    let plain = lorem_corpus();
    let mut w = ZlibWriter::compress(
        Vec::new(),
        DeflateOptions::default().strategy(Strategy::Fixed),
    );
    w.write_all(&plain).unwrap();
    let comp = w.finish().unwrap();

    let mut wd = ZlibWriter::decompress(Vec::new(), InflateOptions::default());
    for b in &comp {
        wd.write_all(&[*b]).unwrap();
    }
    let decoded = wd.finish().unwrap();
    assert_eq!(decoded, plain);
}

#[test]
fn lorem_tight_buffers_both_sides() {
    // Tiny output buffer on both engines — many flush iterations on each side.
    let plain = lorem_corpus();
    let mut w = ZlibWriter::compress(
        Vec::new(),
        DeflateOptions::default()
            .strategy(Strategy::Fixed)
            .buf_size(7),
    );
    w.write_all(&plain).unwrap();
    let comp = w.finish().unwrap();

    let mut r = ZlibReader::decompress(Cursor::new(&comp), InflateOptions::default().buf_size(7));
    let mut decoded = Vec::new();
    r.read_to_end(&mut decoded).unwrap();
    assert_eq!(decoded, plain);
}

// ── compression smoke checks ─────────────────────────────────────────────────

#[test]
fn no_compression_overhead_is_small() {
    // Stored-block overhead per 64 KiB block: 2 (zlib header) + 5 per stored
    // block + 4 (Adler-32 trailer). For our 12,600-byte input that's < 20 B.
    let plain = lorem_corpus();
    let mut w = ZlibWriter::compress(
        Vec::new(),
        DeflateOptions::default().level(CompressionLevel::None),
    );
    w.write_all(&plain).unwrap();
    let comp = w.finish().unwrap();
    assert!(
        comp.len() < plain.len() + 64,
        "stored-block overhead unexpectedly large: {} vs plain {}",
        comp.len(),
        plain.len()
    );
}
