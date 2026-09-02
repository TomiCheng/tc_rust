//! Legacy Ascon v1.2 hash functions.
//!
//! These functions use the pre-standard Ascon v1.2 encoding and are retained
//! only for compatibility with existing hashes. New applications should use
//! [`crate::AsconHash256`], standardized in NIST SP 800-232.

#![allow(deprecated)]

use core::convert::Infallible;

use tc_digest::TryDigest;

use crate::ascon_core::{p8, p12};

const DIGEST_LENGTH: usize = 32;
const RATE: usize = 8;

const HASH_IV: [u64; 5] = [
    0xee93_98aa_db67_f03d,
    0x8bb2_1831_c60f_1002,
    0xb48a_92db_98d5_da62,
    0x4318_9921_b8f8_e3e8,
    0x348f_a5c9_d525_e140,
];

const HASH_A_IV: [u64; 5] = [
    0x0147_0194_fc65_28a6,
    0x738e_c38a_c0ad_ffa7,
    0x2ec8_e329_6c76_384c,
    0xd6f6_a54d_7f52_377d,
    0xa13c_42a2_23be_8d87,
];

/// Selects one of the obsolete Ascon v1.2 hash variants.
#[deprecated(
    since = "0.1.0",
    note = "legacy Ascon v1.2 compatibility only; use AsconHash256 for new applications"
)]
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum AsconParameters {
    /// Ascon-Hash with 12-round intermediate permutations.
    AsconHash,
    /// Ascon-HashA with 8-round intermediate permutations.
    AsconHashA,
}

/// Legacy Ascon v1.2 Hash/HashA digest.
///
/// This type is retained for compatibility with pre-standard hashes. It is not
/// interoperable with the standardized [`crate::AsconHash256`].
#[deprecated(
    since = "0.1.0",
    note = "legacy Ascon v1.2 compatibility only; use AsconHash256 for new applications"
)]
#[derive(Clone)]
pub struct AsconDigest {
    parameters: AsconParameters,
    state: [u64; 5],
    buffer: [u8; RATE],
    buffer_position: usize,
}

impl AsconDigest {
    /// Creates a legacy Ascon v1.2 Hash or HashA digest.
    pub fn new(parameters: AsconParameters) -> Self {
        Self {
            parameters,
            state: initial_state(parameters),
            buffer: [0; RATE],
            buffer_position: 0,
        }
    }

    #[inline]
    fn intermediate_permutation(&mut self) {
        match self.parameters {
            AsconParameters::AsconHash => p12(&mut self.state),
            AsconParameters::AsconHashA => p8(&mut self.state),
        }
    }

    #[inline]
    fn absorb_block(&mut self, block: &[u8; RATE]) {
        self.state[0] ^= u64::from_be_bytes(*block);
        self.intermediate_permutation();
    }
}

impl TryDigest for AsconDigest {
    type Error = Infallible;

    fn algorithm_name(&self) -> &str {
        match self.parameters {
            AsconParameters::AsconHash => "Ascon-Hash",
            AsconParameters::AsconHashA => "Ascon-HashA",
        }
    }

    fn digest_size(&self) -> usize {
        DIGEST_LENGTH
    }

    fn byte_length(&self) -> usize {
        RATE
    }

    fn try_update(&mut self, mut input: &[u8]) -> Result<(), Self::Error> {
        if self.buffer_position != 0 {
            let available = RATE - self.buffer_position;
            let copied = available.min(input.len());
            self.buffer[self.buffer_position..self.buffer_position + copied]
                .copy_from_slice(&input[..copied]);
            self.buffer_position += copied;
            input = &input[copied..];

            if self.buffer_position == RATE {
                let block = self.buffer;
                self.absorb_block(&block);
                self.buffer_position = 0;
            } else {
                return Ok(());
            }
        }

        while input.len() >= RATE {
            let block: &[u8; RATE] = input[..RATE].try_into().expect("8-byte legacy Ascon block");
            self.absorb_block(block);
            input = &input[RATE..];
        }

        self.buffer[..input.len()].copy_from_slice(input);
        self.buffer_position = input.len();
        Ok(())
    }

    fn try_do_final(&mut self, output: &mut [u8]) -> Result<usize, Self::Error> {
        let mut final_block = [0u8; RATE];
        final_block[..self.buffer_position].copy_from_slice(&self.buffer[..self.buffer_position]);
        final_block[self.buffer_position] = 0x80;
        self.state[0] ^= u64::from_be_bytes(final_block);
        p12(&mut self.state);

        for (index, chunk) in output[..DIGEST_LENGTH].chunks_exact_mut(RATE).enumerate() {
            if index != 0 {
                self.intermediate_permutation();
            }
            chunk.copy_from_slice(&self.state[0].to_be_bytes());
        }

        self.try_reset()?;
        Ok(DIGEST_LENGTH)
    }

    fn try_reset(&mut self) -> Result<(), Self::Error> {
        self.state = initial_state(self.parameters);
        self.buffer.fill(0);
        self.buffer_position = 0;
        Ok(())
    }
}

const fn initial_state(parameters: AsconParameters) -> [u64; 5] {
    match parameters {
        AsconParameters::AsconHash => HASH_IV,
        AsconParameters::AsconHashA => HASH_A_IV,
    }
}

#[cfg(test)]
mod tests {
    use alloc::{format, string::String, vec::Vec};

    use super::*;
    use tc_digest::Digest;

    fn hex(bytes: &[u8]) -> String {
        let mut encoded = String::with_capacity(bytes.len() * 2);
        for byte in bytes {
            encoded.push_str(&format!("{byte:02x}"));
        }
        encoded
    }

    fn digest_hex(digest: &mut AsconDigest, input: &[u8]) -> String {
        digest.update(input);
        let mut output = [0u8; DIGEST_LENGTH];
        digest.do_final(&mut output);
        hex(&output)
    }

    #[test]
    fn bc_legacy_ascon_hash_kat_vectors() {
        let vectors = [
            (
                0,
                "7346bc14f036e87ae03d0997913088f5f68411434b3cf8b54fa796a80d251f91",
            ),
            (
                1,
                "8dd446ada58a7740ecf56eb638ef775f7d5c0fd5f0c2bbbdfdec29609d3c43a2",
            ),
            (
                2,
                "f77ca13bf89146d3254f1cfb7eddba8fa1bf162284bb29e7f645545cf9e08424",
            ),
            (
                7,
                "dd409ccc0c60cd7f474c0beed1e1cd48140ad45d5136dc5fda5ebe283df8d3f6",
            ),
            (
                8,
                "f4c6a44b29915d3d57cf928a18ec6226bb8dd6c1136acd24965f7e7780cd69cf",
            ),
            (
                9,
                "1e1e710d08a78263773331782621088ca9fe2ee4f596f06c8f7884ca564acec1",
            ),
            (
                31,
                "2cb146aebbb6585b11bf1a371baa6e3e55108c69b0834f269f662c59bcaa5700",
            ),
            (
                32,
                "2a4f6f2b6b3ec2a6c47ba08d18c8ea561b493c13ccb35803fa8b9fb00a0f1f35",
            ),
            (
                33,
                "a6df1844412bad536a98db01024c73a8780be1a7099375696d37430586ba9381",
            ),
            (
                64,
                "5179e733b8a84f4c8a6898043c09f6a779bd6811d21aa25d353e357048279862",
            ),
            (
                128,
                "99f85ae900901d2667fe7fbc52ab6a924fd4aa902bc03019c92106f83578d459",
            ),
            (
                255,
                "d4d7b2b70bd7f57c37be24c5f9d14207b737d8c21632b1ae3093b7a740cddd3e",
            ),
        ];
        check_vectors(AsconParameters::AsconHash, &vectors);
    }

    #[test]
    fn bc_legacy_ascon_hash_a_kat_vectors() {
        let vectors = [
            (
                0,
                "aecd027026d0675f9de7a8ad8ccf512db64b1edcf0b20c388a0c7cc617aaa2c4",
            ),
            (
                1,
                "5a55f0367763d334a3174f9c17fa476eb9196a22f10daf29505633572e7756e4",
            ),
            (
                2,
                "4243fd3b872e1ed4013711382cba032fecb4147d840ddf8436172ac62d129bc4",
            ),
            (
                7,
                "6b6ad8a90eab00dccc182df1cec764e706461e76d303863728b8590b772e9082",
            ),
            (
                8,
                "be9332e10ad16137322968bbec1776ba3f4ecdc1183db7dbe1ac98bd66fce7b6",
            ),
            (
                9,
                "7d3e9e36b5865a874dbc7f9373fb184fa722a94dd3ee04612b5363c949b5089b",
            ),
            (
                31,
                "dadc63c0f6305655ba7a344300bf0f698815456754d737bc9f23f38f9b11ccab",
            ),
            (
                32,
                "3237cbcc617a2550583a50e8bad3dacda82562e06220150448c109008fa054a2",
            ),
            (
                33,
                "b2e4ee021a20b30a84e14060a894602f3f53942edc19266be6dfdc90ede518b2",
            ),
            (
                64,
                "34877b3831c3150bb447b8276caa1f2ccf98693db1f545b98e493fd1e2a1c147",
            ),
            (
                128,
                "e9862486da598741e9840d19f7a96d0b636523b1b2d7257ca36695da9c94be42",
            ),
            (
                255,
                "cb30ef67cf7dfe18f54efedfb6f72d1ebf3932de38f3381da214df8eaea5ceb8",
            ),
        ];
        check_vectors(AsconParameters::AsconHashA, &vectors);
    }

    fn check_vectors(parameters: AsconParameters, vectors: &[(usize, &str)]) {
        let mut digest = AsconDigest::new(parameters);
        for &(length, expected) in vectors {
            let message: Vec<u8> = (0..length).map(|i| i as u8).collect();
            assert_eq!(
                digest_hex(&mut digest, &message),
                expected,
                "length {length}"
            );

            for chunk in message.chunks(5) {
                digest.update(chunk);
            }
            let mut output = [0u8; DIGEST_LENGTH];
            digest.do_final(&mut output);
            assert_eq!(hex(&output), expected, "chunked length {length}");
        }
    }

    #[test]
    fn accessors_clone_bytewise_and_reset() {
        for parameters in [AsconParameters::AsconHash, AsconParameters::AsconHashA] {
            let message: Vec<u8> = (0..129).map(|i| i as u8).collect();
            let expected = digest_hex(&mut AsconDigest::new(parameters), &message);
            let mut digest = AsconDigest::new(parameters);

            assert_eq!(digest.digest_size(), 32);
            assert_eq!(digest.byte_length(), 8);
            assert_eq!(
                digest.algorithm_name(),
                match parameters {
                    AsconParameters::AsconHash => "Ascon-Hash",
                    AsconParameters::AsconHashA => "Ascon-HashA",
                }
            );

            digest.update(&message[..37]);
            let mut cloned = digest.clone();
            digest.update(&message[37..]);
            cloned.update(&message[37..]);
            assert_eq!(digest_hex(&mut digest, b""), expected);
            assert_eq!(digest_hex(&mut cloned, b""), expected);

            for byte in &message {
                digest.update_byte(*byte);
            }
            assert_eq!(digest_hex(&mut digest, b""), expected);

            digest.update(b"discarded state");
            digest.reset();
            assert_eq!(digest_hex(&mut digest, &message), expected);
        }
    }
}
