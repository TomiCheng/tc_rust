#![cfg(feature = "std")]

use std::io::Read;

use tc_encoders::hex::Hex;
use tc_encoders::{Encoder, EncoderReader, base64};

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

fn streamed<E: Encoder + Copy>(encoder: E, data: &[u8], step: usize, chunk: usize) -> Vec<u8> {
    let mut reader = EncoderReader::new(encoder, Trickle { data, step });
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

#[test]
fn reading_in_pieces_matches_encoding_at_once() {
    for len in [0, 1, 2, 3, 4, 5, 511, 512, 513, 767, 768, 769, 3000] {
        let data: Vec<u8> = (0..len).map(|i| (i * 7 + 3) as u8).collect();
        for (step, chunk) in [(1, 1), (2, 7), (5, 64), (1000, 3), (4096, 4096)] {
            assert_eq!(
                streamed(base64::DEFAULT, &data, step, chunk),
                base64::DEFAULT.encode_to_vec(&data),
                "base64 {len}, step {step}, chunk {chunk}"
            );
            assert_eq!(
                streamed(base64::RFC4648_URL_NO_PAD, &data, step, chunk),
                base64::RFC4648_URL_NO_PAD.encode_to_vec(&data),
                "no pad {len}, step {step}, chunk {chunk}"
            );
            assert_eq!(
                streamed(Hex::LOWER, &data, step, chunk),
                Hex::LOWER.encode_to_vec(&data),
                "hex {len}, step {step}, chunk {chunk}"
            );
        }
    }
}

#[test]
fn into_inner_hands_back_the_reader() {
    let reader = EncoderReader::new(Hex::LOWER, &b"\xca\xfe"[..]);
    assert_eq!(reader.into_inner(), b"\xca\xfe");
}
