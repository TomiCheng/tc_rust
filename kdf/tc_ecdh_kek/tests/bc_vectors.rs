//! Bouncy Castle's `ECDHKEKGeneratorTest` vectors, and the behavior around them.

use tc_asn1::{Asn1OctetString, Encode, EncodingOptions};
use tc_asn1_cms::ecc::EccCmsSharedInfo;
use tc_asn1_x509::alg::AlgorithmIdentifier;
use tc_ecdh_kek::{EcdhKek, EcdhKekParamsRef, RawUkmKek};
use tc_kdf::kdf::{Kdf2, KdfParamsRef};
use tc_kdf::{Kdf, KdfError, KdfInit};
use tc_sha::Sha1Digest;

fn hex(text: &str) -> Vec<u8> {
    (0..text.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&text[i..i + 2], 16).unwrap())
        .collect()
}

/// BC's legacy constructor from a bare OID implies NULL parameters.
fn with_null(dotted: &str) -> AlgorithmIdentifier {
    AlgorithmIdentifier::with_null(dotted.parse().unwrap())
}

const AES128_WRAP: &str = "2.16.840.1.101.3.4.1.5";
const AES256_WRAP: &str = "2.16.840.1.101.3.4.1.45";
const CMS3DES_WRAP: &str = "1.2.840.113549.1.9.16.3.6";

fn derive(key_info: &AlgorithmIdentifier, key_size: u32, z: &[u8], len: usize) -> Vec<u8> {
    let mut kek = EcdhKek::new(Sha1Digest::new());
    kek.init(&EcdhKekParamsRef::new(key_info, key_size, z))
        .unwrap();
    let mut out = vec![0; len];
    assert_eq!(kek.generate_bytes(&mut out), Ok(len));
    out
}

#[test]
fn bc_vectors_derive_their_keks_for_aes_and_3des_wrap() {
    for (key_info, key_size, seed, expected) in [
        (
            AES128_WRAP,
            128,
            "75d7487b5d3d2bfb3c69ce0365fe64e3bfab5d0d63731628a9f47eb8fddfa28c65decaf228a0b38f0c51c6a3356d7c56",
            "042be1faca3a4a8fc859241bfb87ba35",
        ),
        (
            CMS3DES_WRAP,
            192,
            "fdeb6d809f997e8ac174d638734dc36d37aaf7e876e39967cd82b1cada3de772449788461ee7f856bad9305627f8e48b",
            "bcd701fc92109b1b9d6f3b6497ad5ca9627fa8a597010305",
        ),
        (
            AES256_WRAP,
            256,
            "db4a8daba1f98791d54e940175dd1a5f3a0826a1066aa9b668d4dc1e1e0790158dcad1533c03b44214d1b61fefa8b579",
            "8ecc6d85caf25eaba823a7d620d4ab0d33e4c645f2",
        ),
    ] {
        let expected = hex(expected);
        assert_eq!(
            derive(&with_null(key_info), key_size, &hex(seed), expected.len()),
            expected,
            "{key_info}"
        );
    }
}

#[test]
fn null_and_absent_key_info_parameters_derive_different_keys() {
    let seed = hex(
        "75d7487b5d3d2bfb3c69ce0365fe64e3bfab5d0d63731628a9f47eb8fddfa28c65decaf228a0b38f0c51c6a3356d7c56",
    );
    let absent = AlgorithmIdentifier::new(AES128_WRAP.parse().unwrap());
    assert_eq!(
        derive(&with_null(AES128_WRAP), 128, &seed, 16),
        hex("042be1faca3a4a8fc859241bfb87ba35")
    );
    assert_ne!(
        derive(&absent, 128, &seed, 16),
        hex("042be1faca3a4a8fc859241bfb87ba35")
    );
}

#[test]
fn the_derivation_is_kdf2_over_the_der_shared_info_with_the_ukm() {
    let z = [7u8; 32];
    let ukm = [9u8; 64];
    let key_info = with_null(AES128_WRAP);
    let mut kek = EcdhKek::new(Sha1Digest::new());
    kek.init(&EcdhKekParamsRef::with_extra_info(&key_info, 128, &z, &ukm))
        .unwrap();
    let mut out = [0u8; 16];
    kek.generate_bytes(&mut out).unwrap();

    let shared_info = EccCmsSharedInfo::new(key_info, Asn1OctetString::new(&128u32.to_be_bytes()))
        .with_entity_u_info(Asn1OctetString::new(&ukm))
        .encode_to_vec(&EncodingOptions::DER)
        .unwrap();
    let mut kdf2 = Kdf2::new(Sha1Digest::new());
    kdf2.init(&KdfParamsRef::with_iv(&z, &shared_info)).unwrap();
    let mut direct = [0u8; 16];
    kdf2.generate_bytes(&mut direct).unwrap();
    assert_eq!(out, direct);
}

#[test]
fn raw_ukm_is_kdf2_over_the_ukm_and_ignores_the_wrap_algorithm() {
    let z = [7u8; 32];
    let ukm = [9u8; 64];
    let derive_raw = |key_info: &AlgorithmIdentifier, key_size| {
        let mut kek = RawUkmKek::new(Sha1Digest::new());
        kek.init(&EcdhKekParamsRef::with_extra_info(
            key_info, key_size, &z, &ukm,
        ))
        .unwrap();
        let mut out = [0u8; 16];
        kek.generate_bytes(&mut out).unwrap();
        out
    };
    let mut kdf2 = Kdf2::new(Sha1Digest::new());
    kdf2.init(&KdfParamsRef::with_iv(&z, &ukm)).unwrap();
    let mut direct = [0u8; 16];
    kdf2.generate_bytes(&mut direct).unwrap();

    assert_eq!(derive_raw(&with_null(AES128_WRAP), 128), direct);
    assert_eq!(derive_raw(&with_null(AES256_WRAP), 256), direct);
    assert_ne!(derive(&with_null(AES128_WRAP), 128, &z, 16), direct);
}

#[test]
fn generating_before_init_fails_and_every_call_starts_over() {
    let mut kek = EcdhKek::new(Sha1Digest::new());
    assert_eq!(
        kek.generate_bytes(&mut [0u8; 16]),
        Err(KdfError::NotInitialised)
    );
    let key_info = with_null(CMS3DES_WRAP);
    let seed = [3u8; 48];
    kek.init(&EcdhKekParamsRef::new(&key_info, 192, &seed))
        .unwrap();
    let mut long = [0u8; 50];
    kek.generate_bytes(&mut long).unwrap();
    let mut short = [0u8; 24];
    kek.generate_bytes(&mut short).unwrap();
    assert_eq!(short, long[..24]);
}
