use tc_asn1::Asn1Oid;
use tc_digest::Digest;
use tc_kdf::KdfError;
use tc_kdf::hkdf::{Hkdf, HkdfParamsOwned};
use tc_macs::MacError;
#[cfg(feature = "hkdf-sha256")]
use tc_sha::Sha256Digest;
#[cfg(feature = "hkdf-sha384")]
use tc_sha::Sha384Digest;
#[cfg(feature = "hkdf-sha512")]
use tc_sha::Sha512Digest;

use crate::kdf::{Kdf, KdfEntry};
use crate::{AlgoError, DefaultAlgoContext, EntryBase, ErrorKind, Params};

// The rows of HKDF, to give to DefaultAlgoBuilder::reg_kdf. Each takes one digest, and HKDF always
// runs over HMAC. Bouncy Castle has no factory of KDFs, so the names are this crate's own. The OIDs
// are those of RFC 8619
#[cfg(feature = "hkdf-sha256")]
pub(super) fn hkdf_sha256(_context: &DefaultAlgoContext) -> Vec<Box<dyn KdfEntry>> {
    row("HKDF-SHA256", "1.2.840.113549.1.9.16.3.28", || {
        Box::new(HkdfKdf(Hkdf::new(Sha256Digest::new())))
    })
}

#[cfg(feature = "hkdf-sha384")]
pub(super) fn hkdf_sha384(_context: &DefaultAlgoContext) -> Vec<Box<dyn KdfEntry>> {
    row("HKDF-SHA384", "1.2.840.113549.1.9.16.3.29", || {
        Box::new(HkdfKdf(Hkdf::new(Sha384Digest::new())))
    })
}

#[cfg(feature = "hkdf-sha512")]
pub(super) fn hkdf_sha512(_context: &DefaultAlgoContext) -> Vec<Box<dyn KdfEntry>> {
    row("HKDF-SHA512", "1.2.840.113549.1.9.16.3.30", || {
        Box::new(HkdfKdf(Hkdf::new(Sha512Digest::new())))
    })
}

fn row(name: &'static str, dotted: &str, create: fn() -> Box<dyn Kdf>) -> Vec<Box<dyn KdfEntry>> {
    vec![Box::new(Row {
        name,
        oids: vec![dotted.parse().expect("a valid OID")],
        create,
    })]
}

struct Row {
    name: &'static str,
    oids: Vec<Asn1Oid>,
    create: fn() -> Box<dyn Kdf>,
}

impl EntryBase for Row {
    fn name(&self) -> &str {
        self.name
    }

    fn oids(&self) -> &[Asn1Oid] {
        &self.oids
    }
}

impl KdfEntry for Row {
    fn create(&self) -> Box<dyn Kdf> {
        (self.create)()
    }
}

// Its params are an HkdfParamsOwned
struct HkdfKdf<D>(Hkdf<D>);

impl<D: Digest> tc_kdf::Kdf for HkdfKdf<D> {
    type Error = AlgoError;

    fn generate_bytes(&mut self, output: &mut [u8]) -> Result<usize, AlgoError> {
        self.0.generate_bytes(output).map_err(algo_error)
    }
}

impl<D: Digest> tc_kdf::KdfInit<dyn Params> for HkdfKdf<D> {
    type Error = AlgoError;

    fn init(&mut self, params: &dyn Params) -> Result<(), AlgoError> {
        let params = params
            .as_any()
            .downcast_ref::<HkdfParamsOwned>()
            .ok_or(AlgoError::new(ErrorKind::InvalidParams))?;
        self.0
            .init(params)
            .map_err(|error| AlgoError::with_source(ErrorKind::InvalidParams, error))
    }
}

impl<D: Digest> Kdf for HkdfKdf<D> {}

fn algo_error(error: KdfError<MacError>) -> AlgoError {
    let kind = match error {
        KdfError::NotInitialised => ErrorKind::NotInitialized,
        _ => ErrorKind::DataLength,
    };
    AlgoError::with_source(kind, error)
}

#[cfg(all(
    test,
    feature = "hkdf-sha256",
    feature = "hkdf-sha384",
    feature = "hkdf-sha512"
))]
mod tests {
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
    fn the_case_of_a_name_does_not_matter() {
        let algo = DefaultAlgoBuilder::default().build();
        for name in ["hkdf-sha256", "hkdf-sha384", "hkdf-sha512"] {
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
