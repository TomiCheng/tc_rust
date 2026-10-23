#![cfg(feature = "pbkdf2")]

use tc_digest::Digest;
use tc_pbe::{PbeError, PbeGenerator, PbeGeneratorInit, PbeParamsRef, Pkcs5S2};
use tc_sha::{Sha1Digest, Sha256Digest};

fn hex(text: &str) -> Vec<u8> {
    (0..text.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&text[i..i + 2], 16).unwrap())
        .collect()
}

fn pbkdf2<D: Digest>(digest: D, password: &[u8], salt: &[u8], count: usize, len: usize) -> Vec<u8> {
    let mut generator = Pkcs5S2::new(digest);
    generator
        .init(&PbeParamsRef::new(password, salt, count))
        .unwrap();
    let mut key = vec![0; len];
    generator.derive_key(&mut key).unwrap();
    key
}

#[test]
fn pbkdf2_hmac_sha1_matches_rfc_6070() {
    // 1677 萬次的那一組太慢，略過
    for (password, salt, count, expected) in [
        (
            &b"password"[..],
            &b"salt"[..],
            1,
            "0c60c80f961f0e71f3a9b524af6012062fe037a6",
        ),
        (
            b"password",
            b"salt",
            2,
            "ea6c014dc72d6f8ccd1ed92ace1d41f0d8de8957",
        ),
        (
            b"password",
            b"salt",
            4096,
            "4b007901b765489abead49d926f721d065a429c1",
        ),
        (
            b"passwordPASSWORDpassword",
            b"saltSALTsaltSALTsaltSALTsaltSALTsalt",
            4096,
            "3d2eec4fe41c849b80c8d83662c0e44a8b291a964cf2f07038",
        ),
        (
            b"pass\0word",
            b"sa\0lt",
            4096,
            "56fa6aa75548099dcc37d7f03425e0c3",
        ),
    ] {
        assert_eq!(
            pbkdf2(Sha1Digest::new(), password, salt, count, expected.len() / 2),
            hex(expected),
            "{count}"
        );
    }
}

#[test]
fn pbkdf2_hmac_sha256_matches_rfc_7914() {
    assert_eq!(
        pbkdf2(Sha256Digest::new(), b"passwd", b"salt", 1, 64),
        hex(
            "55ac046e56e3089fec1691c22544b605f94185216dde0465e68b9d57c20dacbc49ca9cccf179b645991664b39d77ef317c71b845b1e30bd509112041d3a19783"
        )
    );
    assert_eq!(
        pbkdf2(Sha256Digest::new(), b"Password", b"NaCl", 80000, 64),
        hex(
            "4ddcd8f60b98be21830cee5ef22701f9641a4418d04c0414aeff08876b34ab56a1d425a1225833549adb841b51c9b3176a272bdebba1d078478f62b397f33c8d"
        )
    );
}

#[test]
fn the_rfc_3211_keys_of_bcs_pkcs5_test_come_out() {
    let salt = hex("1234567878563412");
    let long = b"All n-entities must communicate with other n-entities via n-1 entiteeheehees";
    assert_eq!(
        pbkdf2(Sha1Digest::new(), b"password", &salt, 5, 8),
        hex("d1daa78615f287e6")
    );
    assert_eq!(
        pbkdf2(Sha1Digest::new(), long, &salt, 500, 24),
        hex("6a8970bf68c92caea84a8df28510858607126380cc47ab2d")
    );
    assert_eq!(
        pbkdf2(Sha1Digest::new(), long, &salt, 60000, 24),
        hex("29aaef810c12ecd2236bbcfb55407f9852b5573dc1c095bb")
    );
}

#[test]
fn key_and_iv_are_taken_in_turn_from_one_output() {
    let whole = pbkdf2(Sha1Digest::new(), b"password", b"salt", 4096, 40);
    let mut generator = Pkcs5S2::new(Sha1Digest::new());
    generator
        .init(&PbeParamsRef::new(b"password", b"salt", 4096))
        .unwrap();
    let (mut key, mut iv) = ([0; 24], [0; 16]);
    generator.derive_key_and_iv(&mut key, &mut iv).unwrap();
    assert_eq!([&key[..], &iv[..]].concat(), whole);

    let mut mac_key = [0; 24];
    generator.derive_mac_key(&mut mac_key).unwrap();
    assert_eq!(mac_key, key);
}

#[test]
fn a_zero_iteration_count_is_refused_and_init_comes_first() {
    let mut generator = Pkcs5S2::new(Sha1Digest::new());
    assert_eq!(
        generator.derive_key(&mut [0; 8]),
        Err(PbeError::NotInitialised)
    );
    assert_eq!(
        generator.init(&PbeParamsRef::new(b"password", b"salt", 0)),
        Err(PbeError::InvalidIterationCount(0))
    );
}
