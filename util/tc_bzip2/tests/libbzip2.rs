use std::io::{Read, Write};

use tc_bzip2::{BZip2Reader, BZip2Writer};

fn text() -> Vec<u8> {
    b"The quick brown fox jumps over the lazy dog. ".repeat(5000)
}

fn bytes() -> Vec<u8> {
    (0..=255u8).collect::<Vec<_>>().repeat(3)
}

fn runs() -> Vec<u8> {
    [
        b"a".repeat(4),
        b"b".repeat(5),
        b"c".repeat(259),
        b"d".repeat(1000),
    ]
    .concat()
}

fn decompress(data: &[u8]) -> Vec<u8> {
    let mut out = Vec::new();
    BZip2Reader::new(data)
        .unwrap()
        .read_to_end(&mut out)
        .unwrap();
    out
}

#[test]
fn streams_from_libbzip2_decompress_to_their_contents() {
    for (compressed, expected) in [
        (
            &include_bytes!("data/hello_level9.bz2")[..],
            b"Hello, world!".to_vec(),
        ),
        (include_bytes!("data/bytes_level9.bz2"), bytes()),
        (include_bytes!("data/runs_level9.bz2"), runs()),
        (include_bytes!("data/text_level1.bz2"), text()),
        (include_bytes!("data/text_level9.bz2"), text()),
    ] {
        assert_eq!(decompress(compressed), expected);
    }
}

#[test]
fn short_inputs_compress_to_the_same_bytes_as_libbzip2() {
    for (data, expected) in [
        (
            b"Hello, world!".to_vec(),
            &include_bytes!("data/hello_level9.bz2")[..],
        ),
        (runs(), include_bytes!("data/runs_level9.bz2")),
    ] {
        let mut writer = BZip2Writer::new(Vec::new()).unwrap();
        writer.write_all(&data).unwrap();
        assert_eq!(writer.finish().unwrap(), expected);
    }
}
