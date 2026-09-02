//! Official BLAKE3 known-answer tests (BLAKE3-team/BLAKE3 `test_vectors.json`, via
//! bc-csharp `Blake3Test.cs`). Each vector gives the unkeyed hash, the keyed hash,
//! and the derive-key hash of the length-`n` input `i % 251`, as extended XOF
//! output.

mod blake3_vectors;

use blake3_vectors::TEST_VECTORS;
use tc_blake3::Blake3Digest;
use tc_digest::{Digest, Xof};

const KEY: &[u8] = b"whats the Elvish word for friend";
const CONTEXT: &[u8] = b"BLAKE3 2019-12-27 16:29:52 test vectors context";

fn unhex(s: &str) -> Vec<u8> {
    (0..s.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&s[i..i + 2], 16).unwrap())
        .collect()
}

#[test]
fn official_blake3_kat() {
    for &(len, hash, keyed, derived) in TEST_VECTORS {
        let input: Vec<u8> = (0..len).map(|i| (i % 251) as u8).collect();

        // unkeyed
        let expected = unhex(hash);
        let mut d = Blake3Digest::new();
        d.update(&input);
        let mut out = vec![0u8; expected.len()];
        d.output_final(&mut out);
        assert_eq!(out, expected, "hash len {len}");

        // keyed
        let expected = unhex(keyed);
        let mut d = Blake3Digest::with_key(256, KEY);
        d.update(&input);
        let mut out = vec![0u8; expected.len()];
        d.output_final(&mut out);
        assert_eq!(out, expected, "keyed len {len}");

        // derive-key
        let expected = unhex(derived);
        let mut d = Blake3Digest::with_derive_key(256, CONTEXT);
        d.update(&input);
        let mut out = vec![0u8; expected.len()];
        d.output_final(&mut out);
        assert_eq!(out, expected, "derived len {len}");
    }
}
