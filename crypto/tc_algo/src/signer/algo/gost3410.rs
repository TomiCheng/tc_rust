use std::sync::Arc;

use rand_core::CryptoRng;
use tc_dsa::Gost3410DigestSigner;
use tc_gost3410::Gost3410Signer;
use tc_gost3410_key::{Gost3410PrivateKey, Gost3410PublicKey};
use tc_gost3411::Gost3411Digest;

use super::row::{Row, keyed};
use crate::signer::SignerEntry;
use crate::{AlgoError, DefaultAlgoContext, ErrorKind};

// The row of GOST R 34.10-94 over GOST R 34.11-94, to give to DefaultAlgoBuilder::reg_signer, with
// the name, aliases and OID of Bouncy Castle's SignerUtilities. It takes a Gost3410PrivateKey to
// sign and a Gost3410PublicKey to verify, and draws k at random
pub(super) fn gost3410(context: &DefaultAlgoContext) -> Vec<Box<dyn SignerEntry>> {
    let rand: fn() -> Box<dyn CryptoRng> = context.rand();
    vec![Box::new(Row::new(
        "GOST3410".to_string(),
        [
            "GOST-3410",
            "GOST-3410-94",
            "GOST3411WITHGOST3410",
            "GOST3411/GOST3410",
        ]
        .map(String::from)
        .to_vec(),
        &["1.2.643.2.2.4"],
        Arc::new(move |params| {
            let signer =
                || Gost3410DigestSigner::new(Gost3410Signer::new(rand()), Gost3411Digest::new());
            let params = params.as_any();
            if let Some(key) = params.downcast_ref::<Gost3410PrivateKey>() {
                return keyed(signer(), key);
            }
            let key = params
                .downcast_ref::<Gost3410PublicKey>()
                .ok_or(AlgoError::new(ErrorKind::InvalidParams))?;
            keyed(signer(), key)
        }),
    ))]
}

#[cfg(test)]
mod tests {
    use crate::params::generate::Gost3410KeyGenParams;
    use crate::{AlgoBuilder, DefaultAlgoBuilder};

    #[test]
    fn gost3410_verifies_what_it_signs_by_its_names_and_oid() {
        let algo = DefaultAlgoBuilder::default().build();
        let pair = algo
            .key_pair_generator()
            .generate_by_name_with("GOST-3410-94", &Gost3410KeyGenParams::new(512))
            .unwrap();
        for name in ["GOST3410", "GOST3411WITHGOST3410", "gost-3410"] {
            let mut signer = algo.signer().get_by_name(name).unwrap();
            signer.init(pair.private()).unwrap();
            signer.update(b"attack at dawn").unwrap();
            let signature = signer.sign().unwrap();

            let mut verifier = algo.signer().get_by_name(name).unwrap();
            verifier.init(pair.public()).unwrap();
            verifier.update(b"attack at dawn").unwrap();
            assert!(verifier.verify_signature(&signature).unwrap(), "{name}");
            verifier.update(b"attack at dusk").unwrap();
            assert!(!verifier.verify_signature(&signature).unwrap(), "{name}");
        }
        let oid = "1.2.643.2.2.4".parse().unwrap();
        assert!(algo.signer().get_by_oid(&oid).is_ok());
    }
}
