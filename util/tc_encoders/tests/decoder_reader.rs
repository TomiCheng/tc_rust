#![cfg(feature = "std")]

use std::io::{ErrorKind, Read};

use tc_encoders::hex::Hex;
use tc_encoders::{DecoderReader, Encoder, base64};

/// 每次最多交出 `step` 個位元組的 `Read`，模擬分段到達的輸入。
struct Trickle<'a> {
    data: &'a [u8],
    step: usize,
}

impl Read for Trickle<'_> {
    fn read(&mut self, buf: &mut [u8]) -> std::io::Result<usize> {
        let len = self.step.min(buf.len()).min(self.data.len());
        buf[..len].copy_from_slice(&self.data[..len]);
        self.data = &self.data[len..];
        Ok(len)
    }
}

fn streamed<E: Encoder + Copy>(encoder: E, text: &[u8], step: usize, chunk: usize) -> Vec<u8> {
    let mut reader = DecoderReader::new(encoder, Trickle { data: text, step });
    let mut out = Vec::new();
    let mut buf = vec![0; chunk];
    loop {
        let len = reader.read(&mut buf).unwrap();
        if len == 0 {
            return out;
        }
        out.extend_from_slice(&buf[..len]);
    }
}

fn with_line_breaks(text: &[u8]) -> Vec<u8> {
    text.chunks(64)
        .flat_map(|line| line.iter().chain(b"\r\n"))
        .copied()
        .collect()
}

#[test]
fn reading_in_pieces_matches_decoding_at_once() {
    for len in [0, 1, 2, 3, 4, 5, 767, 768, 769, 3000] {
        let data: Vec<u8> = (0..len).map(|i| (i * 7 + 3) as u8).collect();
        for encoder_text in [
            (base64::DEFAULT.encode_to_vec(&data), 0),
            (base64::RFC4648_URL_NO_PAD.encode_to_vec(&data), 1),
            (Hex::LOWER.encode_to_vec(&data), 2),
        ] {
            let (text, which) = encoder_text;
            let text = with_line_breaks(&text);
            for (step, chunk) in [(1, 1), (3, 7), (5, 64), (1000, 2), (4096, 4096)] {
                let out = match which {
                    0 => streamed(base64::DEFAULT, &text, step, chunk),
                    1 => streamed(base64::RFC4648_URL_NO_PAD, &text, step, chunk),
                    _ => streamed(Hex::LOWER, &text, step, chunk),
                };
                assert_eq!(
                    out, data,
                    "len {len}, encoder {which}, step {step}, chunk {chunk}"
                );
            }
        }
    }
}

#[test]
fn padding_before_the_last_group_is_an_error_even_across_reads() {
    for step in [1, 2, 4, 8] {
        let mut reader = DecoderReader::new(
            base64::DEFAULT,
            Trickle {
                data: b"Zg==Zm9v",
                step,
            },
        );
        let error = reader.read_to_end(&mut Vec::new()).unwrap_err();
        assert_eq!(error.kind(), ErrorKind::InvalidData, "step {step}");
    }
}

#[test]
fn bad_characters_and_lengths_are_invalid_data() {
    for text in [&b"Zm9*Zm9v"[..], b"Zm9vY", b"Zg=A"] {
        let mut reader = DecoderReader::new(base64::DEFAULT, text);
        let error = reader.read_to_end(&mut Vec::new()).unwrap_err();
        assert_eq!(error.kind(), ErrorKind::InvalidData, "{text:?}");
    }
}

#[test]
fn into_inner_hands_back_the_reader() {
    let reader = DecoderReader::new(Hex::LOWER, &b"cafe"[..]);
    assert_eq!(reader.into_inner(), b"cafe");
}
