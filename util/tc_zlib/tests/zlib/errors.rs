//! 壞掉的串流要回報錯誤，不能卡住或默默截斷。

use std::fs;
use std::io::{ErrorKind, Read, Write};
use std::path::Path;

use tc_zlib::{InflateOptions, ZlibReader, ZlibWriter};

fn text_stream() -> Vec<u8> {
    let path = Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/data/python/text_6_default.zlib");
    fs::read(path).unwrap()
}

fn through_writer(stream: &[u8]) -> std::io::Result<Vec<u8>> {
    let mut writer = ZlibWriter::decompress(Vec::new(), InflateOptions::default());
    writer.write_all(stream)?;
    writer.finish()
}

fn through_reader(stream: &[u8]) -> std::io::Result<Vec<u8>> {
    let mut out = Vec::new();
    ZlibReader::decompress(stream, InflateOptions::default()).read_to_end(&mut out)?;
    Ok(out)
}

fn kinds(stream: &[u8]) -> (ErrorKind, ErrorKind) {
    (
        through_writer(stream).unwrap_err().kind(),
        through_reader(stream).unwrap_err().kind(),
    )
}

#[test]
fn every_flipped_bit_is_reported_unless_it_only_touches_padding() {
    let stream = text_stream();
    let plain = through_writer(&stream).unwrap();
    for at in 0..stream.len() {
        for bit in [0x01, 0x80] {
            let mut broken = stream.clone();
            broken[at] ^= bit;
            for result in [through_writer(&broken), through_reader(&broken)] {
                match result {
                    Err(e) => assert!(
                        matches!(e.kind(), ErrorKind::InvalidData | ErrorKind::UnexpectedEof),
                        "byte {at}: {e}"
                    ),
                    // 最後一個區塊之後補齊 byte 的位元不參與解碼。
                    Ok(out) => assert_eq!(out, plain, "byte {at} bit {bit:#x}"),
                }
            }
        }
    }
}

#[test]
fn a_wrong_checksum_is_invalid_data() {
    let mut stream = text_stream();
    *stream.last_mut().unwrap() ^= 1;
    assert_eq!(
        kinds(&stream),
        (ErrorKind::InvalidData, ErrorKind::InvalidData)
    );
    let error = through_writer(&stream).unwrap_err();
    assert_eq!(error.to_string(), "incorrect data check");
}

#[test]
fn a_truncated_stream_is_an_unexpected_end() {
    let stream = text_stream();
    for len in [0, 1, 2, 10, stream.len() - 1] {
        assert_eq!(
            kinds(&stream[..len]),
            (ErrorKind::UnexpectedEof, ErrorKind::UnexpectedEof),
            "length {len}"
        );
    }
}

#[test]
fn data_after_the_stream_is_rejected_by_the_writer_and_left_unread_by_the_reader() {
    let mut stream = text_stream();
    let plain = through_writer(&stream).unwrap();
    stream.extend_from_slice(b"trailing");
    assert_eq!(
        through_writer(&stream).unwrap_err().kind(),
        ErrorKind::InvalidData
    );
    assert_eq!(through_reader(&stream).unwrap(), plain);
}

#[test]
fn a_stream_that_needs_a_dictionary_is_invalid_data() {
    // CMF 0x78，FLG 設了 FDICT（0x20）並滿足 % 31，後面接字典的 Adler-32。
    let stream = [0x78, 0xbb, 0, 0, 0, 1, 0x03, 0x00];
    assert_eq!(
        kinds(&stream),
        (ErrorKind::InvalidData, ErrorKind::InvalidData)
    );
}
