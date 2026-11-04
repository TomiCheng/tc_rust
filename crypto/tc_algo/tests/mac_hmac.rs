#![cfg(all(feature = "hmac", feature = "sha256"))]

// HMAC in the MAC table: the rows it builds from the digest table, the names and OIDs of Bouncy
// Castle's MacUtilities, the vectors of RFC 4231 and RFC 2202, and what init and the MAC refuse
use tc_algo::ErrorKind;
use tc_algo::digest::{self, TryDigest};
use tc_algo::mac::{self, AnyMacParams, Mac, MacInit};
use tc_algo::params::SecretKey;
use tc_asn1::Asn1Oid;

const HI_THERE: &[u8] = b"Hi There";
const JEFE: &[u8] = b"what do ya want for nothing?";
const LONG_KEY_MESSAGE: &[u8] = b"Test Using Larger Than Block-Size Key - Hash Key First";

fn unhex(text: &str) -> Vec<u8> {
    (0..text.len())
        .step_by(2)
        .map(|index| u8::from_str_radix(&text[index..index + 2], 16).unwrap())
        .collect()
}

fn params(key: &[u8]) -> AnyMacParams {
    AnyMacParams::new(SecretKey::new(key.to_vec()))
}

fn assert_tag(name: &str, key: &[u8], message: &[u8], expected: &str) {
    assert_eq!(
        mac::calculate(name, &params(key), message).unwrap(),
        unhex(expected),
        "{name}"
    );
}

fn digest_of(name: &str, parts: &[&[u8]]) -> Vec<u8> {
    let mut digest = digest::get_by_name(name).unwrap();
    for part in parts {
        digest.update(part);
    }
    digest.finalize()
}

// HMAC as RFC 2104 defines it, through the digest factory alone
fn rfc2104(name: &str, key: &[u8], message: &[u8]) -> Vec<u8> {
    let block = TryDigest::byte_length(&digest::get_by_name(name).unwrap());
    let mut padded = if key.len() > block {
        digest_of(name, &[key])
    } else {
        key.to_vec()
    };
    padded.resize(block, 0);
    let inner_pad: Vec<u8> = padded.iter().map(|byte| byte ^ 0x36).collect();
    let outer_pad: Vec<u8> = padded.iter().map(|byte| byte ^ 0x5c).collect();
    digest_of(
        name,
        &[&outer_pad, &digest_of(name, &[&inner_pad, message])],
    )
}

#[test]
fn hmac_sha256_matches_rfc_4231() {
    assert_tag(
        "HMAC-SHA256",
        &[0x0b; 20],
        HI_THERE,
        "b0344c61d8db38535ca8afceaf0bf12b881dc200c9833da726e9376c2e32cff7",
    );
    assert_tag(
        "HMAC-SHA256",
        b"Jefe",
        JEFE,
        "5bdcc146bf60754e6a042426089575c75a003f089d2739839dec58b964ec3843",
    );
    assert_tag(
        "HMAC-SHA256",
        &[0xaa; 131],
        LONG_KEY_MESSAGE,
        "60e431591ee0b67f0d8a26aacbf5b77f8e0bc6213728c5140546040f0ee37f54",
    );
}

#[cfg(feature = "sha224")]
#[test]
fn hmac_sha224_matches_rfc_4231() {
    assert_tag(
        "HMAC-SHA224",
        &[0x0b; 20],
        HI_THERE,
        "896fb1128abbdf196832107cd49df33f47b4b1169912ba4f53684b22",
    );
    assert_tag(
        "HMAC-SHA224",
        b"Jefe",
        JEFE,
        "a30e01098bc6dbbf45690f3a7e9e6d0f8bbea2a39e6148008fd05e44",
    );
}

#[cfg(feature = "sha384")]
#[test]
fn hmac_sha384_matches_rfc_4231() {
    assert_tag(
        "HMAC-SHA384",
        &[0x0b; 20],
        HI_THERE,
        "afd03944d84895626b0825f4ab46907f15f9dadbe4101ec682aa034c7cebc59c\
         faea9ea9076ede7f4af152e8b2fa9cb6",
    );
    assert_tag(
        "HMAC-SHA384",
        b"Jefe",
        JEFE,
        "af45d2e376484031617f78d2b58a6b1b9c7ef464f5a01b47e42ec3736322445e\
         8e2240ca5e69e2c78b3239ecfab21649",
    );
}

#[cfg(feature = "sha512")]
#[test]
fn hmac_sha512_matches_rfc_4231() {
    assert_tag(
        "HMAC-SHA512",
        &[0x0b; 20],
        HI_THERE,
        "87aa7cdea5ef619d4ff0b4241a1d6cb02379f4e2ce4ec2787ad0b30545e17cde\
         daa833b7d6b8a702038b274eaea3f4e4be9d914eeb61f1702e696c203a126854",
    );
    assert_tag(
        "HMAC-SHA512",
        b"Jefe",
        JEFE,
        "164b7a7bfcf819e2e395fbe73b56e0a387bd64222e831fd610270cd7ea250554\
         9758bf75c05a994a6d034f65f8f0e6fdcaeab1a34d4a6b4b636e070a38bce737",
    );
    assert_tag(
        "HMAC-SHA512",
        &[0xaa; 131],
        LONG_KEY_MESSAGE,
        "80b24263c7c1a3ebb71493c1dd7be8b49b46d1f41b4aeec1121b013783f8f352\
         6b56d037e05f2598bd0fd2215d6a1e5295e64f73f63f0aec8b915a985d786598",
    );
}

#[cfg(feature = "md5")]
#[test]
fn hmac_md5_matches_rfc_2202() {
    assert_tag(
        "HMAC-MD5",
        &[0x0b; 16],
        HI_THERE,
        "9294727a3638bb1c13f48ef8158bfc9d",
    );
}

#[cfg(feature = "sha1")]
#[test]
fn hmac_sha1_matches_rfc_2202() {
    assert_tag(
        "HMAC-SHA1",
        &[0x0b; 20],
        HI_THERE,
        "b617318655057264e28bc0b6fb378c8ef146be00",
    );
}

#[test]
fn every_row_is_rfc_2104_over_its_digest_with_short_and_long_keys() {
    let long_key = vec![0x5a; 300];
    for entry in mac::algorithms() {
        let Some(digest) = entry.name().strip_prefix("HMAC-") else {
            continue;
        };
        for key in [&b"short"[..], &long_key] {
            assert_eq!(
                mac::calculate(entry.name(), &params(key), b"message").unwrap(),
                rfc2104(digest, key, b"message"),
                "{}",
                entry.name()
            );
        }
    }
}

#[test]
fn there_is_a_row_for_every_digest_hmac_can_run_over_and_nothing_else() {
    let digests: Vec<String> = digest::algorithms()
        .filter(|entry| {
            let created = entry.create();
            let block = TryDigest::byte_length(&created);
            block >= 16
                && TryDigest::digest_size(&created) <= block
                && !entry.name().starts_with("HARAKA-")
        })
        .map(|entry| entry.name().to_string())
        .collect();
    let rows: Vec<String> = mac::algorithms()
        .filter_map(|entry| entry.name().strip_prefix("HMAC-"))
        .map(ToString::to_string)
        .collect();
    assert_eq!(rows, digests);
    assert_eq!(
        mac::get_by_name("HMAC-NONE").unwrap_err().kind(),
        ErrorKind::UnknownMac
    );
}

#[test]
fn every_form_of_the_name_finds_the_same_row() {
    for name in [
        "HMAC-SHA-256",
        "HMAC-SHA256",
        "HMAC/SHA256",
        "HMAC/SHA-256",
        "HMACSHA256",
        "HMACSHA-256",
        "hmac-sha256",
        "HmacSha256",
    ] {
        let mac = mac::get_by_name(name).unwrap();
        assert_eq!(mac.entry().name(), "HMAC-SHA-256", "{name}");
        assert_eq!(mac.to_string(), "HMAC-SHA-256");
    }
}

#[test]
fn every_oid_of_bouncy_castle_finds_its_row_when_the_digest_is_enabled() {
    for (oid, row) in [
        ("1.3.6.1.5.5.8.1.1", "HMAC-MD5"),
        ("1.2.840.113549.2.7", "HMAC-SHA-1"),
        ("1.3.6.1.5.5.8.1.2", "HMAC-SHA-1"),
        ("1.2.840.113549.2.8", "HMAC-SHA-224"),
        ("1.2.840.113549.2.9", "HMAC-SHA-256"),
        ("1.2.840.113549.2.10", "HMAC-SHA-384"),
        ("1.2.840.113549.2.11", "HMAC-SHA-512"),
        ("1.2.840.113549.2.12", "HMAC-SHA-512/224"),
        ("1.2.840.113549.2.13", "HMAC-SHA-512/256"),
        ("2.16.840.1.101.3.4.2.13", "HMAC-SHA3-224"),
        ("2.16.840.1.101.3.4.2.14", "HMAC-SHA3-256"),
        ("2.16.840.1.101.3.4.2.15", "HMAC-SHA3-384"),
        ("2.16.840.1.101.3.4.2.16", "HMAC-SHA3-512"),
        ("1.2.643.7.1.1.4.1", "HMAC-GOST3411-2012-256"),
        ("1.2.643.7.1.1.4.2", "HMAC-GOST3411-2012-512"),
        ("1.3.6.1.5.5.8.1.4", "HMAC-RIPEMD160"),
        ("1.3.6.1.5.5.8.1.3", "HMAC-TIGER"),
    ] {
        let parsed: Asn1Oid = oid.parse().unwrap();
        if mac::get_by_name(row).is_err() {
            assert_eq!(
                mac::get_by_oid(&parsed).unwrap_err().kind(),
                ErrorKind::UnknownMac,
                "{oid}"
            );
            continue;
        }
        assert_eq!(mac::get_by_oid(&parsed).unwrap().entry().name(), row);
        assert_eq!(mac::get_by_name(oid).unwrap().entry().name(), row);
    }
}

#[test]
fn the_tag_can_be_built_in_pieces_and_the_next_message_needs_no_new_init() {
    let expected = mac::calculate("HMAC-SHA256", &params(b"Jefe"), JEFE).unwrap();
    let mut hmac = mac::get_by_name("HMAC-SHA256").unwrap();
    assert_eq!(hmac.mac_size(), 32);
    hmac.init(&params(b"Jefe")).unwrap();
    for piece in JEFE.chunks(5) {
        hmac.update(piece).unwrap();
    }
    assert_eq!(hmac.finalize().unwrap(), expected);

    hmac.update(JEFE).unwrap();
    assert_eq!(hmac.finalize().unwrap(), expected);

    hmac.update(b"discarded").unwrap();
    hmac.reset();
    hmac.update(JEFE).unwrap();
    assert_eq!(hmac.finalize().unwrap(), expected);
}

#[test]
fn verify_accepts_the_right_tag_and_refuses_any_other() {
    let tag = mac::calculate("HMAC-SHA256", &params(b"Jefe"), JEFE).unwrap();
    let mut hmac = mac::get_by_name("HMAC-SHA256").unwrap();
    hmac.init(&params(b"Jefe")).unwrap();

    hmac.update(JEFE).unwrap();
    assert!(hmac.verify(&tag).unwrap());

    let mut forged = tag.clone();
    forged[31] ^= 1;
    hmac.update(JEFE).unwrap();
    assert!(!hmac.verify(&forged).unwrap());

    hmac.update(JEFE).unwrap();
    assert!(!hmac.verify(&tag[..31]).unwrap());
}

#[test]
fn init_refuses_an_iv_since_hmac_has_no_use_for_one() {
    let mut hmac = mac::get_by_name("HMAC-SHA256").unwrap();
    let error = hmac.init(&params(b"key").with_iv(vec![0; 16])).unwrap_err();
    assert_eq!(error.kind(), ErrorKind::InvalidParams);
}

#[test]
fn the_mac_refuses_to_run_before_a_successful_init() {
    let mut hmac = mac::get_by_name("HMAC-SHA256").unwrap();
    assert_eq!(
        hmac.update(b"x").unwrap_err().kind(),
        ErrorKind::NotInitialized
    );
    assert_eq!(
        hmac.finalize().unwrap_err().kind(),
        ErrorKind::NotInitialized
    );
}

#[test]
fn a_failed_init_never_goes_on_under_the_previous_key() {
    let mut hmac = mac::get_by_name("HMAC-SHA256").unwrap();
    hmac.init(&params(b"key")).unwrap();
    assert!(hmac.init(&params(b"key").with_iv(vec![0; 16])).is_err());
    assert_eq!(
        hmac.update(b"x").unwrap_err().kind(),
        ErrorKind::NotInitialized
    );
}

#[test]
fn the_contract_traits_report_a_short_output_with_the_tc_macs_error_as_source() {
    let mut hmac = mac::get_by_name("HMAC-SHA256").unwrap();
    MacInit::init(&mut hmac, &params(b"key")).unwrap();
    Mac::update(&mut hmac, b"message").unwrap();
    let mut short = [0x55; 31];
    let error = Mac::do_final(&mut hmac, &mut short).unwrap_err();
    assert_eq!(error.kind(), ErrorKind::DataLength);
    assert!(core::error::Error::source(&error).is_some());
    assert_eq!(short, [0x55; 31]);

    let mut output = [0; 32];
    assert_eq!(Mac::do_final(&mut hmac, &mut output).unwrap(), 32);
}

#[test]
fn the_table_shows_each_row_with_its_oids() {
    let row = mac::algorithms()
        .find(|entry| entry.name() == "HMAC-SHA-256")
        .unwrap();
    assert_eq!(row.to_string(), "HMAC-SHA-256  [id-hmacWithSHA256]");
}
