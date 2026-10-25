use tc_digest::Digest;
use tc_kdf::kdf::{ConcatenationKdf, KdfParamsRef};
use tc_kdf::{Kdf, KdfError, KdfInit};
use tc_sha::{Sha1Digest, Sha256Digest, Sha512Digest};

fn hex(text: &str) -> Vec<u8> {
    (0..text.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&text[i..i + 2], 16).unwrap())
        .collect()
}

/// BC 的做法：每個長度都重新 init 再產生，結果都要是同一串向量的開頭。
fn check_every_length<D: Digest>(digest: D, secret: &str, other_info: &str, expected: &str) {
    let (secret, other_info, expected) = (hex(secret), hex(other_info), hex(expected));
    let mut kdf = ConcatenationKdf::new(digest);
    for len in 0..=expected.len() {
        kdf.init(&KdfParamsRef::with_iv(&secret, &other_info))
            .ok()
            .unwrap();
        let mut output = vec![0; len];
        assert_eq!(kdf.generate_bytes(&mut output), Ok(len));
        assert_eq!(output, expected[..len], "{len}");
    }
}

#[test]
fn every_prefix_matches_the_sp_800_56c_vector_over_sha1() {
    check_every_length(
        Sha1Digest::new(),
        "ebe28edbae5a410b87a479243db3f690",
        "e60dd8b28228ce5b9be74d3b",
        "b4a23963e07f485382cb358a493daec1759ac7043dbeac37152c6ddf105031f0f239f270b7f30616166f10e5d2b4cb11ba8bf4ba3f2276885abfbc3e811a568d480d9192",
    );
}

#[test]
fn every_prefix_matches_the_sp_800_56c_vector_over_sha256() {
    check_every_length(
        Sha256Digest::new(),
        "3f892bd8b84dae64a782a35f6eaa8f00",
        "ec3f1cd873d28858a58cc39e",
        "a7c0665298252531e0db37737a374651b368275f2048284d16a166c6d8a90a91a491c16f49641b9f516a03d9d6d0f4fe7b81ffdf1c816f40ecd74aed8eda2b8a3c714fa0",
    );
}

#[test]
fn every_prefix_matches_the_sp_800_56c_vector_over_sha512() {
    check_every_length(
        Sha512Digest::new(),
        "e65b1905878b95f68b5535bd3b2b1013",
        "830221b1730d9176f807d407",
        "b8c44bdf0b85a64b6a51c12a06710e373d829bb1fda5b4e1a20795c6199594f6fa65198a721257f7d58cb2f6f6db9bb5699f73863045909054b2389e06ec00fe318cabd9",
    );
}

#[test]
fn the_counter_comes_before_the_secret() {
    let (secret, other_info) = (b"shared secret", b"other info");
    let mut kdf = ConcatenationKdf::new(Sha256Digest::new());
    kdf.init(&KdfParamsRef::with_iv(secret, other_info))
        .ok()
        .unwrap();
    let mut output = [0; 32];
    kdf.generate_bytes(&mut output).unwrap();

    let mut digest = Sha256Digest::new();
    digest.update(&1u32.to_be_bytes());
    digest.update(secret);
    digest.update(other_info);
    let mut expected = [0; 32];
    digest.do_final(&mut expected);
    assert_eq!(output, expected);
}

#[test]
fn generating_before_init_fails() {
    let mut kdf = ConcatenationKdf::new(Sha256Digest::new());
    assert_eq!(
        kdf.generate_bytes(&mut [0; 16]),
        Err(KdfError::NotInitialised)
    );
}
