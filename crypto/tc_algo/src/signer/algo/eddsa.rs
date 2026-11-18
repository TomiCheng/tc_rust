use std::sync::Arc;

use tc_cfrg_curves::CfrgError;
use tc_signer::SignerInit;

use super::row::{Inner, Kind, Make, Row, keyed};
use crate::signer::SignerEntry;
use crate::{AlgoError, DefaultAlgoContext, ErrorKind, Params};

// The rows of EdDSA, RFC 8032, to give to DefaultAlgoBuilder::reg_signer, with the names and OIDs of
// Bouncy Castle's SignerUtilities: Ed25519, Ed25519ctx and Ed25519ph, Ed448 and Ed448ph, each with
// an empty context, as Bouncy Castle builds them. Each takes the private key to sign and the public
// key to verify, of the Ed25519 or Ed448 key pair generator. EdDSA draws no randomness
pub(super) fn eddsa(_context: &DefaultAlgoContext) -> Vec<Box<dyn SignerEntry>> {
    #[allow(unused_mut, reason = "Ed448 alone or Ed25519 alone")]
    let mut rows: Vec<Box<dyn SignerEntry>> = Vec::new();
    #[cfg(feature = "cfrg-curves")]
    {
        use tc_cfrg_curves::{
            Ed25519CtxSigner, Ed25519PhSigner, Ed25519PrivateKey, Ed25519PublicKey, Ed25519Signer,
        };
        type Keys = (Ed25519PrivateKey, Ed25519PublicKey);
        rows.push(row(
            "Ed25519",
            &["1.3.101.112"],
            Arc::new(|params| either::<Keys, _>(params, Ed25519Signer::new())),
        ));
        rows.push(row(
            "Ed25519ctx",
            &[],
            Arc::new(|params| either::<Keys, _>(params, Ed25519CtxSigner::new(&[]))),
        ));
        rows.push(row(
            "Ed25519ph",
            &[],
            Arc::new(|params| either::<Keys, _>(params, Ed25519PhSigner::new(&[]))),
        ));
    }
    #[cfg(feature = "cfrg-curves")]
    {
        use tc_cfrg_curves::{Ed448PhSigner, Ed448PrivateKey, Ed448PublicKey, Ed448Signer};
        type Keys = (Ed448PrivateKey, Ed448PublicKey);
        rows.push(row(
            "Ed448",
            &["1.3.101.113"],
            Arc::new(|params| either::<Keys, _>(params, Ed448Signer::new(&[]))),
        ));
        rows.push(row(
            "Ed448ph",
            &[],
            Arc::new(|params| either::<Keys, _>(params, Ed448PhSigner::new(&[]))),
        ));
    }
    rows
}

fn row(name: &str, oids: &[&str], make: Make) -> Box<dyn SignerEntry> {
    Box::new(Row::new(name.to_string(), Vec::new(), oids, make))
}

// The signer keyed by the private key K.0 to sign, or the public key K.1 to verify
fn either<K, S>(params: &dyn Params, signer: S) -> Result<Box<dyn Inner>, AlgoError>
where
    K: Pair,
    S: SignerInit<K::Private, Error = CfrgError>
        + SignerInit<K::Public, Error = CfrgError>
        + Inner
        + 'static,
{
    let params = params.as_any();
    if let Some(key) = params.downcast_ref::<K::Private>() {
        return keyed(signer, key);
    }
    let key = params
        .downcast_ref::<K::Public>()
        .ok_or(AlgoError::new(ErrorKind::InvalidParams))?;
    keyed(signer, key)
}

trait Pair {
    type Private: 'static;
    type Public: 'static;
}

impl<A: 'static, B: 'static> Pair for (A, B) {
    type Private = A;
    type Public = B;
}

impl Kind for CfrgError {
    fn kind(&self) -> ErrorKind {
        match self {
            CfrgError::NotInitialized | CfrgError::NotForSigning | CfrgError::NotForVerifying => {
                ErrorKind::NotInitialized
            }
            CfrgError::OutputTooShort => ErrorKind::DataLength,
            _ => ErrorKind::InvalidParams,
        }
    }
}

#[cfg(all(test, feature = "cfrg-curves"))]
mod tests {
    use crate::params::{Ed25519PrivateKey, Ed25519PublicKey};
    use crate::{Algo, AlgoBuilder, DefaultAlgoBuilder, ErrorKind, Params};

    fn unhex<const N: usize>(text: &str) -> [u8; N] {
        let bytes: Vec<u8> = (0..text.len())
            .step_by(2)
            .map(|at| u8::from_str_radix(&text[at..at + 2], 16).unwrap())
            .collect();
        bytes.try_into().unwrap()
    }

    fn algo() -> Box<dyn Algo> {
        DefaultAlgoBuilder::default().build()
    }

    fn sign(name: &str, key: &dyn Params, message: &[u8]) -> Vec<u8> {
        let mut signer = algo().signer().get_by_name(name).unwrap();
        signer.init(key).unwrap();
        signer.update(message).unwrap();
        signer.sign().unwrap()
    }

    fn verify(name: &str, key: &dyn Params, message: &[u8], signature: &[u8]) -> bool {
        let mut verifier = algo().signer().get_by_name(name).unwrap();
        verifier.init(key).unwrap();
        verifier.update(message).unwrap();
        verifier.verify_signature(signature).unwrap()
    }

    // RFC 8032, section 7.1, test 1
    #[test]
    fn ed25519_gives_the_signature_of_rfc_8032() {
        let private = Ed25519PrivateKey::new(unhex(
            "9d61b19deffd5a60ba844af492ec2cc44449c5697b326919703bac031cae7f60",
        ));
        let public = Ed25519PublicKey::new(unhex(
            "d75a980182b10ab7d54bfed3c964073a0ee172f3daa62325af021a68f707511a",
        ));
        let signature: [u8; 64] = unhex(
            "e5564300c360ac729086e2cc806e828a84877f1eb8e5d974d873e065224901555fb8821590a33bacc61e39701cf9b46bd25bf5f0595bbe24655141438e7a100b",
        );
        assert_eq!(sign("Ed25519", &private, &[]), signature);
        assert!(verify("ED25519", &public, &[], &signature));
        let oid = "1.3.101.112".parse().unwrap();
        assert!(algo().signer().get_by_oid(&oid).is_ok());
    }

    #[test]
    fn every_eddsa_row_verifies_what_it_signs_with_keys_of_its_generator() {
        for (generator, names) in [
            ("Ed25519", &["Ed25519", "Ed25519ctx", "Ed25519ph"][..]),
            ("Ed448", &["Ed448", "Ed448ph"][..]),
        ] {
            let pair = algo()
                .key_pair_generator()
                .generate_by_name(generator)
                .unwrap();
            for name in names {
                let signature = sign(name, pair.private(), b"attack at dawn");
                assert!(
                    verify(name, pair.public(), b"attack at dawn", &signature),
                    "{name}"
                );
                assert!(
                    !verify(name, pair.public(), b"attack at dusk", &signature),
                    "{name}"
                );
            }
        }
    }

    #[test]
    fn a_key_of_the_other_curve_is_refused() {
        let pair = algo()
            .key_pair_generator()
            .generate_by_name("Ed448")
            .unwrap();
        let mut signer = algo().signer().get_by_name("Ed25519").unwrap();
        let error = signer.init(pair.private()).unwrap_err();
        assert_eq!(error.kind(), ErrorKind::InvalidParams);
    }
}
