use core::convert::Infallible;

use tc_crypto::AlgorithmName;
use tc_digest::TryDigest;
use tc_hmac::HMac;
use tc_macs::{Mac, MacError, MacInit};
use tc_params::{KeyParams, KeyRef};
use tc_sha::{Sha1Digest, Sha256Digest};

fn hex(input: &str) -> Vec<u8> {
    input
        .as_bytes()
        .as_chunks::<2>()
        .0
        .iter()
        .map(|pair| {
            let text = core::str::from_utf8(pair).unwrap();
            u8::from_str_radix(text, 16).unwrap()
        })
        .collect()
}

fn message(input: &str) -> Vec<u8> {
    input
        .strip_prefix("0x")
        .map_or_else(|| input.as_bytes().to_vec(), hex)
}

fn authenticate<D: tc_digest::Digest>(digest: D, key: &[u8], input: &[u8]) -> Vec<u8> {
    let mut hmac = HMac::new(digest);
    hmac.init(&KeyRef::new(key)).unwrap();
    hmac.update(input).unwrap();
    let mut tag = vec![0_u8; hmac.mac_size()];
    let tag_length = tag.len();
    assert_eq!(hmac.do_final(&mut tag), Ok(tag_length));
    tag
}

#[test]
fn matches_bouncy_castle_sha256_vectors() {
    let keys = [
        "0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b",
        "4a656665",
        "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
        "0102030405060708090a0b0c0d0e0f10111213141516171819",
        "0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c",
        "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
        "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
    ];
    let messages = [
        "Hi There",
        "what do ya want for nothing?",
        "0xdddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddd",
        "0xcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcd",
        "Test With Truncation",
        "Test Using Larger Than Block-Size Key - Hash Key First",
        "This is a test using a larger than block-size key and a larger than block-size data. The key needs to be hashed before being used by the HMAC algorithm.",
    ];
    let tags = [
        "b0344c61d8db38535ca8afceaf0bf12b881dc200c9833da726e9376c2e32cff7",
        "5bdcc146bf60754e6a042426089575c75a003f089d2739839dec58b964ec3843",
        "773ea91e36800e46854db8ebd09181a72959098b3ef8c122d9635514ced565fe",
        "82558a389a443c0ea4cc819899f2083a85f0faa3e578f8077a2e3ff46729665b",
        "a3b6167473100ee06e0c796c2955552bfa6f7c0a6a8aef8b93f860aab0cd20c5",
        "60e431591ee0b67f0d8a26aacbf5b77f8e0bc6213728c5140546040f0ee37f54",
        "9b09ffa71b942fcb27635fbcd5b0e944bfdc63644f0713938a7f51535c3a35e2",
    ];

    for ((key, input), tag) in keys.into_iter().zip(messages).zip(tags) {
        assert_eq!(
            authenticate(Sha256Digest::new(), &hex(key), &message(input)),
            hex(tag)
        );
    }
}

struct NonCloneDigest(Sha1Digest);

impl TryDigest for NonCloneDigest {
    type Error = Infallible;

    fn algorithm_name(&self) -> &str {
        self.0.algorithm_name()
    }

    fn digest_size(&self) -> usize {
        self.0.digest_size()
    }

    fn byte_length(&self) -> usize {
        self.0.byte_length()
    }

    fn try_update(&mut self, input: &[u8]) -> Result<(), Self::Error> {
        self.0.try_update(input)
    }

    fn try_do_final(&mut self, output: &mut [u8]) -> Result<usize, Self::Error> {
        self.0.try_do_final(output)
    }

    fn try_reset(&mut self) -> Result<(), Self::Error> {
        self.0.try_reset()
    }
}

#[test]
fn supports_non_clone_digests_and_restores_keyed_state() {
    let key = hex("0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b");
    let expected = hex("b617318655057264e28bc0b6fb378c8ef146be00");
    let mut hmac = HMac::new(NonCloneDigest(Sha1Digest::new()));
    hmac.init(&KeyRef::new(&key)).unwrap();

    for _ in 0..2 {
        hmac.update(b"Hi There").unwrap();
        let mut tag = [0_u8; 20];
        hmac.do_final(&mut tag).unwrap();
        assert_eq!(tag, expected.as_slice());
        hmac.reset();
    }
}

#[test]
fn chunking_reset_dynamic_dispatch_names_and_errors_work() {
    let key = hex("4a656665");
    let input = b"what do ya want for nothing?";
    let expected = hex("5bdcc146bf60754e6a042426089575c75a003f089d2739839dec58b964ec3843");
    let mut hmac = HMac::new(Sha256Digest::new());

    assert_eq!(hmac.update(&[]), Err(MacError::NotInitialised));
    assert_eq!(hmac.do_final(&mut []), Err(MacError::NotInitialised));

    let params = KeyRef::new(&key);
    let params: &dyn KeyParams = &params;
    let initializer: &mut dyn MacInit<dyn KeyParams, Error = Infallible> = &mut hmac;
    initializer.init(params).unwrap();

    let mut name = String::new();
    hmac.write_algo_name(&mut name).unwrap();
    assert_eq!(name, "SHA-256/HMAC");
    assert_eq!(hmac.underlying_digest().algorithm_name(), "SHA-256");

    let mac: &mut dyn Mac<Error = MacError> = &mut hmac;
    for chunk in input.chunks(3) {
        mac.update(chunk).unwrap();
    }
    assert_eq!(
        mac.do_final(&mut [0_u8; 31]),
        Err(MacError::OutputTooShort {
            required: 32,
            available: 31,
        })
    );

    let mut tag = [0_u8; 32];
    assert_eq!(mac.do_final(&mut tag), Ok(32));
    assert_eq!(tag, expected.as_slice());

    mac.update(input).unwrap();
    mac.reset();
    mac.update(input).unwrap();
    mac.do_final(&mut tag).unwrap();
    assert_eq!(tag, expected.as_slice());
}

#[test]
fn reinitialization_replaces_the_key_and_empty_keys_are_allowed() {
    let input = b"message";
    let first_key = KeyRef::new(b"first key");
    let second_key = KeyRef::new(b"second key");
    let expected = authenticate(Sha256Digest::new(), second_key.key(), input);
    let mut hmac = HMac::new(Sha256Digest::new());

    hmac.init(&first_key).unwrap();
    hmac.update(input).unwrap();
    hmac.init(&second_key).unwrap();
    hmac.update(input).unwrap();
    let mut tag = [0_u8; 32];
    hmac.do_final(&mut tag).unwrap();
    assert_eq!(tag, expected.as_slice());

    hmac.init(&KeyRef::new(&[])).unwrap();
    hmac.update(&[]).unwrap();
    assert_eq!(hmac.do_final(&mut tag), Ok(32));
}

#[test]
#[should_panic(expected = "HMAC block length must be at least 16 bytes")]
fn rejects_too_short_custom_block_lengths() {
    let _ = HMac::with_block_length(Sha256Digest::new(), 15);
}

#[test]
#[should_panic(expected = "HMAC digest size must not exceed its block length")]
fn rejects_custom_block_lengths_shorter_than_the_digest() {
    let _ = HMac::with_block_length(Sha256Digest::new(), 16);
}
