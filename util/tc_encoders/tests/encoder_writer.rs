#![cfg(feature = "std")]

use std::io::Write;

use tc_encoders::hex::Hex;
use tc_encoders::{Encoder, EncoderWriter, base64};

fn data(len: usize) -> Vec<u8> {
    (0..len).map(|i| (i * 7 + 3) as u8).collect()
}

/// 以各種大小分段寫入，結果與一次編碼相同。
fn streamed<E: Encoder + Copy>(encoder: E, data: &[u8], piece: usize) -> Vec<u8> {
    let mut writer = EncoderWriter::new(encoder, Vec::new());
    for part in data.chunks(piece) {
        writer.write_all(part).unwrap();
    }
    writer.finish().unwrap()
}

#[test]
fn writing_in_pieces_matches_encoding_at_once() {
    for len in [0, 1, 2, 3, 4, 5, 767, 768, 769, 3000] {
        let data = data(len);
        for piece in [1, 2, 3, 5, 64, 1000, 4096] {
            assert_eq!(
                streamed(base64::DEFAULT, &data, piece),
                base64::DEFAULT.encode_to_vec(&data),
                "base64 {len} by {piece}"
            );
            assert_eq!(
                streamed(base64::RFC4648_URL_NO_PAD, &data, piece),
                base64::RFC4648_URL_NO_PAD.encode_to_vec(&data),
                "no pad {len} by {piece}"
            );
            assert_eq!(
                streamed(Hex::UPPER, &data, piece),
                Hex::UPPER.encode_to_vec(&data),
                "hex {len} by {piece}"
            );
        }
    }
}

#[test]
fn flush_holds_back_the_tail_until_finish() {
    let mut text = Vec::new();
    let mut writer = EncoderWriter::new(base64::DEFAULT, &mut text);
    writer.write_all(b"hello").unwrap();
    writer.flush().unwrap();
    assert_eq!(writer.get_ref().as_slice(), b"aGVs");
    writer.finish().unwrap();
    assert_eq!(text, b"aGVsbG8=");
}

#[test]
fn dropping_without_finish_still_writes_the_tail() {
    let mut text = Vec::new();
    {
        let mut writer = EncoderWriter::new(base64::DEFAULT, &mut text);
        writer.write_all(b"hi").unwrap();
    }
    assert_eq!(text, b"aGk=");
}
