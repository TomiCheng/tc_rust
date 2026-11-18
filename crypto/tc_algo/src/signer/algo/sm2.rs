use std::sync::Arc;

use rand_core::CryptoRng;
use tc_dsa::RandomDsaKCalculator;
use tc_sm2::{Sm2Error, Sm2Signer};

use super::row::{Inner, Kind, Row, keyed};
use crate::params::sm2_keys::{Sm2Curve, Sm2PrivateKey, Sm2PublicKey};
use crate::signer::SignerEntry;
use crate::{AlgoError, DefaultAlgoContext, ErrorKind, Params};

type Rand = fn() -> Box<dyn CryptoRng>;

// The rows of SM2 signatures, of GM/T 0003, to give to DefaultAlgoBuilder::reg_signer, with the
// names and OIDs of Bouncy Castle's SignerUtilities: over SM3, and over SHA-256 when its feature is
// on. Each takes the SM2 private key to sign and the public key to verify, on sm2p256v1, as the SM2
// row of the key pair generators gives them, with the default user ID, and draws k at random
pub(super) fn sm2(context: &DefaultAlgoContext) -> Vec<Box<dyn SignerEntry>> {
    let rand: Rand = context.rand();
    #[allow(unused_mut, reason = "one row unless SHA-256 is on")]
    let mut rows: Vec<Box<dyn SignerEntry>> = vec![Box::new(Row::new(
        "SM3withSM2".to_string(),
        Vec::new(),
        &["1.2.156.10197.1.501"],
        Arc::new(move |params| {
            sign(
                params,
                Sm2Signer::<Sm2Curve, _>::new(RandomDsaKCalculator::new(rand())),
            )
        }),
    ))];
    #[cfg(feature = "sha")]
    rows.push(Box::new(Row::new(
        "SHA256withSM2".to_string(),
        Vec::new(),
        &["1.2.156.10197.1.503"],
        Arc::new(move |params| {
            sign(
                params,
                Sm2Signer::<Sm2Curve, _, _>::with_digest(
                    RandomDsaKCalculator::new(rand()),
                    tc_sha::Sha256Digest::new(),
                ),
            )
        }),
    )));
    rows
}

// The signer keyed by the private key to sign, or the public key to verify
fn sign<S>(params: &dyn Params, signer: S) -> Result<Box<dyn Inner>, AlgoError>
where
    S: tc_signer::SignerInit<Sm2PrivateKey, Error = Sm2Error>
        + tc_signer::SignerInit<Sm2PublicKey, Error = Sm2Error>
        + Inner
        + 'static,
{
    let params = params.as_any();
    if let Some(key) = params.downcast_ref::<Sm2PrivateKey>() {
        return keyed(signer, key);
    }
    let key = params
        .downcast_ref::<Sm2PublicKey>()
        .ok_or(AlgoError::new(ErrorKind::InvalidParams))?;
    keyed(signer, key)
}

impl Kind for Sm2Error {
    fn kind(&self) -> ErrorKind {
        match self {
            Sm2Error::NotInitialized
            | Sm2Error::WrongKeyForDirection
            | Sm2Error::WrongKeyForSigning => ErrorKind::NotInitialized,
            Sm2Error::OutputTooShort | Sm2Error::EmptyInput => ErrorKind::DataLength,
            _ => ErrorKind::InvalidParams,
        }
    }
}

#[cfg(all(test, feature = "sha"))]
mod tests {
    use crate::generate::KeyPair;
    use crate::{Algo, AlgoBuilder, DefaultAlgoBuilder};

    const MESSAGE: &[u8] = b"attack at dawn";

    fn algo() -> Box<dyn Algo> {
        DefaultAlgoBuilder::default().build()
    }

    #[test]
    fn both_rows_verify_what_they_sign_and_tell_one_from_the_other() {
        let pair: KeyPair = algo().key_pair_generator().generate_by_name("SM2").unwrap();
        let mut signatures = Vec::new();
        for name in ["SM3withSM2", "SHA256WITHSM2"] {
            let mut signer = algo().signer().get_by_name(name).unwrap();
            signer.init(pair.private()).unwrap();
            signer.update(MESSAGE).unwrap();
            let signature = signer.sign().unwrap();

            let mut verifier = algo().signer().get_by_name(name).unwrap();
            verifier.init(pair.public()).unwrap();
            verifier.update(MESSAGE).unwrap();
            assert!(verifier.verify_signature(&signature).unwrap(), "{name}");
            signatures.push(signature);
        }
        // An SM3 signature is not a SHA-256 one
        let mut verifier = algo().signer().get_by_name("SHA256withSM2").unwrap();
        verifier.init(pair.public()).unwrap();
        verifier.update(MESSAGE).unwrap();
        assert!(!verifier.verify_signature(&signatures[0]).unwrap());

        let oid = "1.2.156.10197.1.501".parse().unwrap();
        assert!(algo().signer().get_by_oid(&oid).is_ok());
    }
}
