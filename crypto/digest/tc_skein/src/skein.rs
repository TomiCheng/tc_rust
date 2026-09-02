//! `Digest` adapter for the Skein UBI engine.

use alloc::{format, string::String};
use core::convert::Infallible;

use tc_digest::TryDigest;

use crate::SkeinEngine;

/// Skein 1.3 with a configurable state and byte-aligned output size.
#[derive(Clone)]
pub struct SkeinDigest {
    engine: SkeinEngine,
    algorithm_name: String,
}

impl SkeinDigest {
    /// Creates a Skein digest with a 256-, 512-, or 1024-bit internal state.
    pub fn new(state_size_bits: usize, digest_size_bits: usize) -> Self {
        Self {
            engine: SkeinEngine::new(state_size_bits, digest_size_bits),
            algorithm_name: format!("Skein-{state_size_bits}-{digest_size_bits}"),
        }
    }
}

impl TryDigest for SkeinDigest {
    type Error = Infallible;

    fn algorithm_name(&self) -> &str {
        &self.algorithm_name
    }

    fn digest_size(&self) -> usize {
        self.engine.output_size()
    }

    fn byte_length(&self) -> usize {
        self.engine.block_size()
    }

    fn try_update(&mut self, input: &[u8]) -> Result<(), Self::Error> {
        self.engine.update(input);
        Ok(())
    }

    fn try_do_final(&mut self, output: &mut [u8]) -> Result<usize, Self::Error> {
        Ok(self.engine.do_final(output))
    }

    fn try_reset(&mut self) -> Result<(), Self::Error> {
        self.engine.reset();
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    extern crate std;

    use tc_digest::Digest;

    use super::*;

    fn decode(hex: &str) -> std::vec::Vec<u8> {
        let bytes = hex.as_bytes();
        (0..bytes.len())
            .step_by(2)
            .map(|index| {
                let digit = |byte: u8| match byte {
                    b'0'..=b'9' => byte - b'0',
                    b'a'..=b'f' => byte - b'a' + 10,
                    _ => panic!("invalid hex"),
                };
                digit(bytes[index]) << 4 | digit(bytes[index + 1])
            })
            .collect()
    }

    fn check(state_bits: usize, output_bits: usize, message: &str, expected: &str) {
        let message = decode(message);
        let mut digest = SkeinDigest::new(state_bits, output_bits);
        assert_eq!(
            digest.algorithm_name(),
            format!("Skein-{state_bits}-{output_bits}")
        );
        assert_eq!(digest.byte_length(), state_bits / 8);
        digest.update(&message);
        let mut output = std::vec![0u8; output_bits / 8];
        assert_eq!(digest.do_final(&mut output), output_bits / 8);
        assert_eq!(output, decode(expected));
    }

    #[test]
    fn skein_13_empty_and_single_byte_vectors() {
        check(
            256,
            256,
            "",
            "c8877087da56e072870daa843f176e9453115929094c3a40c463a196c29bf7ba",
        );
        check(
            256,
            256,
            "fb",
            "088eb23cc2bccfb8171aa64e966d4af937325167dfcd170700ffd21f8a4cbdac",
        );
        check(
            512,
            512,
            "",
            "bc5b4c50925519c290cc634277ae3d6257212395cba733bbad37a4af0fa06af41fca7903d06564fea7a2d3730dbdb80c1f85562dfcc070334ea4d1d9e72cba7a",
        );
        check(
            1024,
            1024,
            "",
            "0fff9563bb3279289227ac77d319b6fff8d7e9f09da1247b72a0a265cd6d2a62645ad547ed8193db48cff847c06494a03f55666d3b47eb4c20456c9373c86297d630d5578ebd34cb40991578f9f52b18003efa35d3da6553ff35db91b81ab890bec1b189b7f52cb2a783ebb7d823d725b0b4a71f6824e88f68f982eefc6d19c6",
        );
    }

    #[test]
    fn variable_output_and_multiple_output_blocks() {
        let message = "fbd17c26b61a82e12e125f0d459b96c91ab4837dff22b39b78439430cdfc5dc878bb393a1a5f79bef30995a85a12923339ba8ab7d8fc6dc5fec6f4ed22c122bbe7eb61981892966de5cef576f71fc7a80d14dab2d0c03940b95b9fb3a727c66a6e1ff0dc311b9aa21a3054484802154c1826c2a27a0914152aeb76f1168d4410";
        check(
            256,
            160,
            message,
            "0cd491b7715704c3a15a45a1ca8d93f8f646d3a1",
        );
        check(
            256,
            1024,
            message,
            "6c9b6facbaf116b538aa655e0be0168084aa9f1be445f7e06714585e5999a6c984fffa9d41a316028692d4aad18f573fbf27cf78e84de26da1928382b023987dcfe002b6201ea33713c54a8a5d9eb346f0365e04330d2faaf7bc8aba92a5d7fb6345c6fb26750bce65ab2045c233627679ac6e9acb33602e26fe3526063ecc8b",
        );
        check(
            512,
            384,
            message,
            "825f5cbd5da8807a7b4d3e7bd9cd089ca3a256bcc064cd73a9355bf3ae67f2bf93ac7074b3b19907a0665ba3a878b262",
        );
        check(
            1024,
            256,
            message,
            "986a4d472b123e8148731a8eac9db23325f0058c4ccbc44a5bb6fe3a8db672d7",
        );
    }

    #[test]
    fn streaming_clone_and_reset() {
        let message = decode(
            "fbd17c26b61a82e12e125f0d459b96c91ab4837dff22b39b78439430cdfc5dc878bb393a1a5f79bef30995a85a129233",
        );
        let expected = decode(
            "5c5b7956f9d973c0989aa40a71aa9c48a65af2757590e9a758343c7e23ea2df4057ce0b49f9514987feff97f648e1dd065926e2c371a0211ca977c213f14149f",
        );
        let mut digest = SkeinDigest::new(512, 512);
        digest.update(&message[..19]);
        let mut cloned = digest.clone();
        digest.update(&message[19..]);
        cloned.update(&message[19..]);
        let mut output = [0u8; 64];
        let mut clone_output = [0u8; 64];
        digest.do_final(&mut output);
        cloned.do_final(&mut clone_output);
        assert_eq!(output.as_slice(), expected);
        assert_eq!(clone_output, output);

        digest.update(&message);
        digest.do_final(&mut output);
        assert_eq!(output.as_slice(), expected);
    }

    #[test]
    fn chunking_matches_at_and_across_block_boundaries() {
        for state_bits in [256, 512, 1024] {
            let block_size = state_bits / 8;
            for length in [block_size - 1, block_size, block_size + 1, block_size * 2] {
                let message: std::vec::Vec<u8> = (0..length).map(|i| i as u8).collect();
                let mut whole = SkeinDigest::new(state_bits, 256);
                whole.update(&message);
                let mut expected = [0u8; 32];
                whole.do_final(&mut expected);

                let mut chunked = SkeinDigest::new(state_bits, 256);
                for chunk in message.chunks(7) {
                    chunked.update(chunk);
                }
                let mut actual = [0u8; 32];
                chunked.do_final(&mut actual);
                assert_eq!(actual, expected, "state={state_bits}, length={length}");
            }
        }
    }

    #[test]
    #[should_panic(expected = "Skein state size")]
    fn rejects_invalid_state_size() {
        let _ = SkeinDigest::new(384, 256);
    }

    #[test]
    #[should_panic(expected = "positive multiple of 8")]
    fn rejects_non_byte_aligned_output() {
        let _ = SkeinDigest::new(256, 255);
    }
}
