#![cfg(feature = "std")]

use std::io::{ErrorKind, Write};

use tc_encoders::hex::Hex;
use tc_encoders::{DecoderWriter, Encoder, base64};

fn streamed<E: Encoder + Copy>(encoder: E, text: &[u8], piece: usize) -> Vec<u8> {
    let mut writer = DecoderWriter::new(encoder, Vec::new());
    for part in text.chunks(piece) {
        writer.write_all(part).unwrap();
    }
    writer.finish().unwrap()
}

fn with_line_breaks(text: &[u8]) -> Vec<u8> {
    text.chunks(64)
        .flat_map(|line| line.iter().chain(b"\r\n"))
        .copied()
        .collect()
}

#[test]
fn writing_in_pieces_matches_decoding_at_once() {
    for len in [0, 1, 2, 3, 4, 5, 767, 768, 769, 3000] {
        let data: Vec<u8> = (0..len).map(|i| (i * 7 + 3) as u8).collect();
        let padded = with_line_breaks(&base64::DEFAULT.encode_to_vec(&data));
        let unpadded = with_line_breaks(&base64::RFC4648_URL_NO_PAD.encode_to_vec(&data));
        let hex = with_line_breaks(&Hex::UPPER.encode_to_vec(&data));
        for piece in [1, 2, 3, 5, 64, 1000, 4096] {
            assert_eq!(
                streamed(base64::DEFAULT, &padded, piece),
                data,
                "base64 {len} by {piece}"
            );
            assert_eq!(
                streamed(base64::RFC4648_URL_NO_PAD, &unpadded, piece),
                data,
                "no pad {len} by {piece}"
            );
            assert_eq!(
                streamed(Hex::LOWER, &hex, piece),
                data,
                "hex {len} by {piece}"
            );
        }
    }
}

#[test]
fn padding_before_the_last_group_is_an_error_even_across_writes() {
    let mut writer = DecoderWriter::new(base64::DEFAULT, Vec::new());
    writer.write_all(b"Zg==").unwrap();
    let error = writer.write_all(b"Zm9v").unwrap_err();
    assert_eq!(error.kind(), ErrorKind::InvalidData);
}

#[test]
fn a_bad_tail_is_reported_by_finish() {
    for text in [&b"Zm9vY"[..], b"Zg=A", b"Zm9*"] {
        let mut writer = DecoderWriter::new(base64::DEFAULT, Vec::new());
        writer.write_all(text).unwrap();
        let error = writer.finish().unwrap_err();
        assert_eq!(error.kind(), ErrorKind::InvalidData, "{text:?}");
    }
}

#[test]
fn flush_holds_back_the_last_group_and_drop_still_writes_it() {
    let mut bytes = Vec::new();
    {
        let mut writer = DecoderWriter::new(base64::DEFAULT, &mut bytes);
        writer.write_all(b"Zm9vYmFy").unwrap();
        writer.flush().unwrap();
        assert_eq!(writer.get_ref().as_slice(), b"foo");
    }
    assert_eq!(bytes, b"foobar");
}
