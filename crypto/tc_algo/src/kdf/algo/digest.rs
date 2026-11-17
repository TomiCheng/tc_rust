use std::sync::Arc;

use tc_asn1::Asn1Oid;

use super::typed::Row;
#[allow(unused_imports, reason = "each family uses it")]
use super::typed::Typed;
use crate::DefaultAlgoContext;
use crate::digest::DigestEntry;
#[allow(unused_imports, reason = "each family uses it")]
use crate::digest::RowDigest;
#[allow(unused_imports, reason = "used by hkdf alone")]
use crate::digest::TryDigest as _;
use crate::kdf::KdfEntry;

// The rows of the KDFs over a digest, to give to DefaultAlgoBuilder::reg_kdf: HKDF of RFC 5869,
// KDF1 and KDF2 of ISO 18033-2 and the concatenation KDF of SP 800-56C, each over every digest row
// that is on, named as HMAC is, HKDF-SHA256. Bouncy Castle has no factory of KDFs, so the names are
// this crate's own; the OIDs of HKDF are those of RFC 8619. NONE and Haraka, which takes inputs of
// one length alone, have none, and HKDF needs a digest that HMAC takes
pub(super) fn digest(context: &DefaultAlgoContext) -> Vec<Box<dyn KdfEntry>> {
    let mut rows = Vec::new();
    let digests = crate::digest::BUILT_IN
        .iter()
        .flat_map(|create| create(context))
        .filter(|digest| !matches!(digest.name(), "NONE" | "HARAKA-256" | "HARAKA-512"))
        .map(Arc::<dyn DigestEntry>::from);
    for digest in digests {
        let name = digest.name().replacen("SHA-", "SHA", 1).replace('/', "-");
        let mut others = vec![digest.name()];
        others.extend(digest.aliases().iter().map(String::as_str));

        #[cfg(feature = "hkdf")]
        if hmac_takes(digest.as_ref()) {
            use tc_kdf::hkdf::{Hkdf, HkdfParamsOwned};
            let oids = HKDF_OIDS
                .iter()
                .filter(|(row, _)| *row == name)
                .map(|(_, dotted)| dotted.parse().expect("a valid OID"))
                .collect();
            let entry = digest.clone();
            rows.push(Row::boxed("HKDF", &name, &others, oids, move || {
                Typed::<_, HkdfParamsOwned>::boxed(Hkdf::new(RowDigest::new(entry.clone())))
            }));
        }
        #[cfg(feature = "kdf1")]
        {
            use tc_kdf::kdf::{Kdf1, KdfParamsOwned};
            let entry = digest.clone();
            rows.push(Row::boxed("KDF1", &name, &others, no_oids(), move || {
                Typed::<_, KdfParamsOwned>::boxed(Kdf1::new(RowDigest::new(entry.clone())))
            }));
        }
        #[cfg(feature = "kdf2")]
        {
            use tc_kdf::kdf::{Kdf2, KdfParamsOwned};
            let entry = digest.clone();
            rows.push(Row::boxed("KDF2", &name, &others, no_oids(), move || {
                Typed::<_, KdfParamsOwned>::boxed(Kdf2::new(RowDigest::new(entry.clone())))
            }));
        }
        #[cfg(feature = "concat-kdf")]
        {
            use tc_kdf::kdf::{ConcatenationKdf, KdfParamsOwned};
            let entry = digest.clone();
            rows.push(Row::boxed("CONCAT", &name, &others, no_oids(), move || {
                Typed::<_, KdfParamsOwned>::boxed(ConcatenationKdf::new(RowDigest::new(
                    entry.clone(),
                )))
            }));
        }
    }
    rows
}

// The OIDs of RFC 8619, by the name of the row
#[allow(dead_code, reason = "unused when hkdf is off")]
const HKDF_OIDS: &[(&str, &str)] = &[
    ("SHA256", "1.2.840.113549.1.9.16.3.28"),
    ("SHA384", "1.2.840.113549.1.9.16.3.29"),
    ("SHA512", "1.2.840.113549.1.9.16.3.30"),
];

#[allow(dead_code, reason = "unused when only hkdf is on")]
fn no_oids() -> Vec<Asn1Oid> {
    Vec::new()
}

// tc_macs's Hmac takes a digest of a block of 16 bytes or more, and no longer than its digest, as
// the HMAC rows do
#[allow(dead_code, reason = "unused when hkdf is off")]
fn hmac_takes(digest: &dyn DigestEntry) -> bool {
    let digest = digest.create();
    digest.byte_length() >= 16 && digest.digest_size() <= digest.byte_length()
}

#[cfg(all(
    test,
    feature = "hkdf",
    feature = "sha256",
    feature = "sha384",
    feature = "sha512"
))]
mod hkdf_tests {
    use crate::kdf::Kdf;
    use crate::params::{HkdfParamsOwned, KeyLength};
    use crate::{AlgoBuilder, DefaultAlgoBuilder, ErrorKind};

    const SHA256: &str = "HKDF-SHA256";

    fn hex(text: &str) -> Vec<u8> {
        (0..text.len())
            .step_by(2)
            .map(|at| u8::from_str_radix(&text[at..at + 2], 16).unwrap())
            .collect()
    }

    // The inputs of Test Case 1 of RFC 5869
    fn params() -> HkdfParamsOwned {
        HkdfParamsOwned::new(
            vec![0x0b; 22],
            hex("000102030405060708090a0b0c"),
            hex("f0f1f2f3f4f5f6f7f8f9"),
        )
    }

    // SHA-256 is the output in RFC 5869. It has no case for the others, so theirs come from Python's
    // hmac module, with the same code giving the RFC's output for SHA-256
    const OUTPUTS: [(&str, &str, &str); 3] = [
        (
            SHA256,
            "1.2.840.113549.1.9.16.3.28",
            "3cb25f25faacd57a90434f64d0362f2a2d2d0a90cf1a5a4c5db02d56ecc4c5bf34007208d5b887185865",
        ),
        (
            "HKDF-SHA384",
            "1.2.840.113549.1.9.16.3.29",
            "9b5097a86038b805309076a44b3a9f38063e25b516dcbf369f394cfab43685f748b6457763e4f0204fc5",
        ),
        (
            "HKDF-SHA512",
            "1.2.840.113549.1.9.16.3.30",
            "832390086cda71fb47625bb5ceb168e4c8e26a1a16ed34d9fc7fe92c1481579338da362cb8d9f925d7cb",
        ),
    ];

    fn kdf(name: &str) -> Box<dyn Kdf> {
        let algo = DefaultAlgoBuilder::default().build();
        let mut kdf = algo.kdf().get_by_name(name).unwrap();
        kdf.init(&params()).unwrap();
        kdf
    }

    #[test]
    fn each_row_gives_the_output_of_its_digest_by_name_and_oid() {
        let algo = DefaultAlgoBuilder::default().build();
        for (name, dotted, expected) in OUTPUTS {
            let mut output = [0; 42];
            assert_eq!(kdf(name).generate_bytes(&mut output).unwrap(), 42);
            assert_eq!(output.to_vec(), hex(expected), "{name}");

            let mut by_oid = algo.kdf().get_by_oid(&dotted.parse().unwrap()).unwrap();
            by_oid.init(&params()).unwrap();
            let mut output = [0; 42];
            by_oid.generate_bytes(&mut output).unwrap();
            assert_eq!(output.to_vec(), hex(expected), "{dotted}");
        }
    }

    #[test]
    fn the_case_of_a_name_does_not_matter_and_the_digest_aliases_find_it() {
        let algo = DefaultAlgoBuilder::default().build();
        for name in ["hkdf-sha256", "hkdf-sha384", "hkdf-sha512", "HKDF-SHA-256"] {
            assert!(algo.kdf().get_by_name(name).is_ok(), "{name}");
        }
    }

    #[test]
    fn the_output_can_come_in_pieces() {
        let mut kdf = kdf(SHA256);
        let mut first = [0; 10];
        let mut second = [0; 32];
        kdf.generate_bytes(&mut first).unwrap();
        kdf.generate_bytes(&mut second).unwrap();
        assert_eq!([&first[..], &second[..]].concat(), hex(OUTPUTS[0].2));
    }

    #[test]
    fn expanding_the_pseudorandom_key_gives_the_same_output() {
        let algo = DefaultAlgoBuilder::default().build();
        let mut kdf = algo.kdf().get_by_name(SHA256).unwrap();
        let params = HkdfParamsOwned::expand_only(
            hex("077709362c2e32df0ddc3f0dc47bba6390b6c73bb50f9c3122ec844ad7c2b3e5"),
            hex("f0f1f2f3f4f5f6f7f8f9"),
        );
        kdf.init(&params).unwrap();
        let mut output = [0; 42];
        kdf.generate_bytes(&mut output).unwrap();
        assert_eq!(output.to_vec(), hex(OUTPUTS[0].2));
    }

    #[test]
    fn more_than_255_hashes_of_output_is_data_length() {
        for (name, hash_bytes) in [(SHA256, 32), ("HKDF-SHA384", 48), ("HKDF-SHA512", 64)] {
            let mut kdf = kdf(name);
            let mut output = vec![0; 255 * hash_bytes + 1];
            let error = kdf.generate_bytes(&mut output).unwrap_err();
            assert_eq!(error.kind(), ErrorKind::DataLength, "{name}");
            output.truncate(255 * hash_bytes);
            assert_eq!(kdf.generate_bytes(&mut output).unwrap(), 255 * hash_bytes);
        }
    }

    #[test]
    fn generating_needs_an_init() {
        let algo = DefaultAlgoBuilder::default().build();
        let mut kdf = algo.kdf().get_by_name(SHA256).unwrap();
        let error = kdf.generate_bytes(&mut [0; 1]).unwrap_err();
        assert_eq!(error.kind(), ErrorKind::NotInitialized);
    }

    #[test]
    fn init_refuses_params_of_another_type() {
        let algo = DefaultAlgoBuilder::default().build();
        let mut kdf = algo.kdf().get_by_name(SHA256).unwrap();
        let error = kdf.init(&KeyLength::new(1)).unwrap_err();
        assert_eq!(error.kind(), ErrorKind::InvalidParams);
    }
}

#[cfg(all(
    test,
    feature = "kdf1",
    feature = "kdf2",
    feature = "concat-kdf",
    feature = "sha256"
))]
mod digest_kdf_tests {
    use tc_kdf::kdf::{ConcatenationKdf, Kdf1, Kdf2, KdfParamsRef};
    use tc_kdf::{Kdf as _, KdfInit as _};
    use tc_sha::Sha256Digest;

    use crate::params::{KdfParamsOwned, KeyLength};
    use crate::{AlgoBuilder, DefaultAlgoBuilder, ErrorKind};

    const SECRET: [u8; 32] = [0x5a; 32];
    const CONTEXT: [u8; 7] = *b"context";

    fn row(name: &str) -> Vec<u8> {
        let algo = DefaultAlgoBuilder::default().build();
        let mut kdf = algo.kdf().get_by_name(name).unwrap();
        kdf.init(&KdfParamsOwned::with_iv(SECRET.to_vec(), CONTEXT.to_vec()))
            .unwrap();
        let mut output = vec![0; 80];
        kdf.generate_bytes(&mut output).unwrap();
        output
    }

    // The same function over SHA-256 itself, outside the factory
    macro_rules! direct {
        ($kdf:expr) => {{
            let mut kdf = $kdf;
            kdf.init(&KdfParamsRef::with_iv(&SECRET, &CONTEXT)).unwrap();
            let mut output = vec![0; 80];
            kdf.generate_bytes(&mut output).unwrap();
            output
        }};
    }

    #[test]
    fn each_row_gives_what_its_function_gives_over_the_digest() {
        assert_eq!(row("KDF1-SHA256"), direct!(Kdf1::new(Sha256Digest::new())));
        assert_eq!(row("KDF2-SHA256"), direct!(Kdf2::new(Sha256Digest::new())));
        assert_eq!(
            row("CONCAT-SHA256"),
            direct!(ConcatenationKdf::new(Sha256Digest::new()))
        );
        assert_ne!(row("KDF1-SHA256"), row("KDF2-SHA256"));
    }

    #[test]
    fn the_digest_aliases_find_the_rows_and_other_params_are_refused() {
        let algo = DefaultAlgoBuilder::default().build();
        for name in ["kdf2-sha-256", "KDF1-SHA-256", "concat-sha256"] {
            assert!(algo.kdf().get_by_name(name).is_ok(), "{name}");
        }
        let mut kdf = algo.kdf().get_by_name("KDF2-SHA256").unwrap();
        let error = kdf.generate_bytes(&mut [0; 1]).unwrap_err();
        assert_eq!(error.kind(), ErrorKind::NotInitialized);
        let error = kdf.init(&KeyLength::new(1)).unwrap_err();
        assert_eq!(error.kind(), ErrorKind::InvalidParams);
    }
}
