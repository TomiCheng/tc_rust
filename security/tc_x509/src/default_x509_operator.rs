use std::sync::Arc;

use tc_algo_v2::generate::KeyPairGeneratorProvider;
use tc_algo_v2::{Algo, Params};

use crate::operator::signer::{DefaultSignatureFactory, SignatureFactory, SignerEntry};
use crate::operator::spki::{DefaultSpkiProvider, SpkiProvider};
use crate::{X509Error, X509Operator};

pub(crate) struct DefaultX509Operator {
    algo: Arc<dyn Algo>,
    spki: DefaultSpkiProvider,
    // The last registered first
    signers: Vec<Arc<dyn SignerEntry>>,
}

impl DefaultX509Operator {
    pub(crate) fn new(
        algo: Arc<dyn Algo>,
        spki: DefaultSpkiProvider,
        signers: Vec<Arc<dyn SignerEntry>>,
    ) -> Self {
        Self {
            algo,
            spki,
            signers,
        }
    }

    fn find_signer(&self, name: &str) -> Option<&Arc<dyn SignerEntry>> {
        self.signers.iter().find(|row| {
            row.name().eq_ignore_ascii_case(name)
                || row
                    .aliases()
                    .iter()
                    .any(|alias| alias.eq_ignore_ascii_case(name))
        })
    }
}

impl X509Operator for DefaultX509Operator {
    fn key_pair_generator(&self) -> &dyn KeyPairGeneratorProvider {
        self.algo.key_pair_generator()
    }

    fn spki(&self) -> &dyn SpkiProvider {
        &self.spki
    }

    fn signature_factory(
        &self,
        name: &str,
        private_key: Arc<dyn Params>,
    ) -> Result<Box<dyn SignatureFactory>, X509Error> {
        let row = self.find_signer(name).ok_or(X509Error::UnknownSigner)?;
        Ok(Box::new(DefaultSignatureFactory::new(
            self.algo.clone(),
            row.clone(),
            private_key,
        )?))
    }
}
