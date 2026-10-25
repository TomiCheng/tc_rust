//! The RFC 2631 §2.1.6 examples, as BC's `DHKekGeneratorTest` checks them, and the behavior
//! around them.

use tc_asn1::Asn1Oid;
use tc_dh_kek::{DhKek, DhKekParamsRef};
use tc_kdf::{Kdf, KdfError, KdfInit};
use tc_sha::Sha1Digest;

fn hex(text: &str) -> Vec<u8> {
    (0..text.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&text[i..i + 2], 16).unwrap())
        .collect()
}

fn oid(dotted: &str) -> Asn1Oid {
    dotted.parse().unwrap()
}

const ZZ: &str = "000102030405060708090a0b0c0d0e0f10111213";
const CMS3DES_WRAP: &str = "1.2.840.113549.1.9.16.3.6";
const CMS_RC2_WRAP: &str = "1.2.840.113549.1.9.16.3.7";

fn derive(params: &DhKekParamsRef<'_>, len: usize) -> Vec<u8> {
    let mut kek = DhKek::new(Sha1Digest::new());
    kek.init(params).unwrap();
    let mut out = vec![0; len];
    assert_eq!(kek.generate_bytes(&mut out), Ok(len));
    out
}

#[test]
fn the_3des_wrap_example_derives_its_192_bit_kek_over_two_sha1_blocks() {
    let zz = hex(ZZ);
    let algorithm = oid(CMS3DES_WRAP);
    assert_eq!(
        derive(&DhKekParamsRef::new(&algorithm, 192, &zz), 24),
        hex("a09661392376f7044d9052a397883246b67f5f1ef63eb5fb")
    );
}

#[test]
fn the_rc2_wrap_example_puts_party_a_info_into_its_128_bit_kek() {
    let zz = hex(ZZ);
    let algorithm = oid(CMS_RC2_WRAP);
    let party_a_info = hex(concat!(
        "0123456789abcdeffedcba98765432010123456789abcdeffedcba9876543201",
        "0123456789abcdeffedcba98765432010123456789abcdeffedcba9876543201",
    ));
    assert_eq!(
        derive(
            &DhKekParamsRef::with_extra_info(&algorithm, 128, &zz, &party_a_info),
            16
        ),
        hex("48950c46e0530075403cce72889604e0")
    );
}

#[test]
fn every_call_starts_over_so_shorter_outputs_are_prefixes_of_longer_ones() {
    let zz = hex(ZZ);
    let algorithm = oid(CMS3DES_WRAP);
    let mut kek = DhKek::new(Sha1Digest::new());
    kek.init(&DhKekParamsRef::new(&algorithm, 192, &zz))
        .unwrap();

    let mut long = [0u8; 50];
    kek.generate_bytes(&mut long).unwrap();
    let mut short = [0u8; 24];
    kek.generate_bytes(&mut short).unwrap();
    assert_eq!(short, long[..24]);
    assert_eq!(
        short.to_vec(),
        hex("a09661392376f7044d9052a397883246b67f5f1ef63eb5fb")
    );
}

#[test]
fn generating_before_init_fails_and_a_new_init_replaces_the_parameters() {
    let mut kek = DhKek::new(Sha1Digest::new());
    let mut out = [0u8; 16];
    assert_eq!(kek.generate_bytes(&mut out), Err(KdfError::NotInitialised));

    let zz = hex(ZZ);
    let des = oid(CMS3DES_WRAP);
    let rc2 = oid(CMS_RC2_WRAP);
    kek.init(&DhKekParamsRef::new(&des, 192, &zz)).unwrap();
    kek.init(&DhKekParamsRef::new(&rc2, 192, &zz)).unwrap();
    let mut replaced = [0u8; 24];
    kek.generate_bytes(&mut replaced).unwrap();
    assert_eq!(
        replaced.to_vec(),
        derive(&DhKekParamsRef::new(&rc2, 192, &zz), 24)
    );
    assert_ne!(
        replaced.to_vec(),
        derive(&DhKekParamsRef::new(&des, 192, &zz), 24)
    );
}

#[test]
fn an_empty_output_succeeds_without_hashing() {
    let zz = hex(ZZ);
    let algorithm = oid(CMS3DES_WRAP);
    let mut kek = DhKek::new(Sha1Digest::new());
    kek.init(&DhKekParamsRef::new(&algorithm, 192, &zz))
        .unwrap();
    assert_eq!(kek.generate_bytes(&mut []), Ok(0));
}
