use tc_algo::Algo;
use tc_algo::signer::Signer;
use tc_asn1::{Asn1Object, Decode, DecodingOptions, Encode, EncodingOptions};
use tc_asn1_pkcs::{Pkcs1Algorithm, RsassaPssParams};
use tc_asn1_x509::alg::AlgorithmIdentifier;

use super::oid;
use crate::operator::signer::SignerEntry;
use crate::{DefaultX509OperatorContext, X509Error};

// The rows of RSASSA-PSS of RFC 4055: MGF1 over the same digest and a salt of its size, as
// Bouncy Castle's Asn1SignatureFactory writes them with the NULL of the digest. A signature read
// with other parameters, as another salt length, is no row's
pub(super) fn pss(_context: &DefaultX509OperatorContext) -> Vec<Box<dyn SignerEntry>> {
    [
        ("SHA-1withRSAandMGF1", "SHA1", "1.3.14.3.2.26", 20),
        (
            "SHA-224withRSAandMGF1",
            "SHA224",
            "2.16.840.1.101.3.4.2.4",
            28,
        ),
        (
            "SHA-256withRSAandMGF1",
            "SHA256",
            "2.16.840.1.101.3.4.2.1",
            32,
        ),
        (
            "SHA-384withRSAandMGF1",
            "SHA384",
            "2.16.840.1.101.3.4.2.2",
            48,
        ),
        (
            "SHA-512withRSAandMGF1",
            "SHA512",
            "2.16.840.1.101.3.4.2.3",
            64,
        ),
    ]
    .into_iter()
    .map(|(name, digest, dotted, salt)| {
        let hash = AlgorithmIdentifier::with_null(oid(dotted));
        let params = RsassaPssParams::new(
            hash.clone(),
            AlgorithmIdentifier::with_parameters(Pkcs1Algorithm::MGF1.oid(), object(&hash)),
            (salt as u64).into(),
            1.into(),
        )
        .expect("the parameters of the rows are valid");
        Box::new(Pss {
            name,
            aliases: vec![format!("{digest}withRSAandMGF1")],
            algorithm: AlgorithmIdentifier::with_parameters(
                Pkcs1Algorithm::RSASSA_PSS.oid(),
                object(&params),
            ),
            params,
        }) as Box<dyn SignerEntry>
    })
    .collect()
}

struct Pss {
    name: &'static str,
    aliases: Vec<String>,
    algorithm: AlgorithmIdentifier,
    params: RsassaPssParams,
}

impl SignerEntry for Pss {
    fn name(&self) -> &str {
        self.name
    }

    fn aliases(&self) -> &[String] {
        &self.aliases
    }

    fn algorithm(&self) -> &AlgorithmIdentifier {
        &self.algorithm
    }

    // RSASSA-PSS with the same digest for the hash and for MGF1, NULL or absent alike, and the
    // same salt length
    fn matches(&self, algorithm: &AlgorithmIdentifier) -> bool {
        if *algorithm.algorithm() != Pkcs1Algorithm::RSASSA_PSS {
            return false;
        }
        let Some(params) = algorithm.parameters().and_then(read::<RsassaPssParams>) else {
            return false;
        };
        let mgf = params.mask_gen_algorithm();
        let mgf_hash = mgf.parameters().and_then(read::<AlgorithmIdentifier>);
        equivalent(params.hash_algorithm(), self.params.hash_algorithm())
            && *mgf.algorithm() == Pkcs1Algorithm::MGF1
            && mgf_hash.is_some_and(|hash| equivalent(&hash, self.params.hash_algorithm()))
            && params.salt_length() == self.params.salt_length()
            && params.trailer_field() == self.params.trailer_field()
    }

    fn create(&self, algo: &dyn Algo) -> Result<Box<dyn Signer>, X509Error> {
        Ok(algo.signer().get_by_name(self.name)?)
    }
}

fn equivalent(a: &AlgorithmIdentifier, b: &AlgorithmIdentifier) -> bool {
    let absent =
        |id: &AlgorithmIdentifier| matches!(id.parameters(), None | Some(Asn1Object::Null(_)));
    a.algorithm() == b.algorithm() && ((absent(a) && absent(b)) || a.parameters() == b.parameters())
}

fn object<T: Encode>(value: &T) -> Asn1Object {
    read(value).expect("the parameters of the rows encode")
}

// `value` read again as T, with nothing after it
fn read<T: Decode>(value: &impl Encode) -> Option<T> {
    let der = value.encode_to_vec(&EncodingOptions::DER).ok()?;
    let (used, value) = T::decode(&der, &DecodingOptions::default()).ok()?;
    (used == der.len()).then_some(value)
}
