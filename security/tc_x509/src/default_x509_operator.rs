use std::sync::Arc;

use tc_algo::generate::KeyPairGeneratorProvider;
use tc_algo::{Algo, Params};

use crate::cert::{X509AttributeCertificate, X509Certificate};
use crate::crl::X509Crl;
use crate::operator::parser::{DefaultParserProvider, ParserProvider};
use crate::operator::signer::{DefaultSignatureFactory, SignatureFactory, SignerEntry};
use crate::operator::spki::{DefaultSpkiProvider, SpkiProvider};
use crate::operator::verifier::{
    DefaultVerifierFactory, DefaultVerifierFactoryProvider, VerifierFactory,
    VerifierFactoryProvider,
};
use crate::{X509Error, X509Operator};

pub(crate) struct DefaultX509Operator {
    algo: Arc<dyn Algo>,
    spki: DefaultSpkiProvider,
    // The last registered first
    signers: Vec<Arc<dyn SignerEntry>>,
    parsers: Parsers,
}

// The parser providers of an operator, one per type parsed
pub(crate) struct Parsers {
    pub(crate) certificate: DefaultParserProvider<X509Certificate>,
    pub(crate) crl: DefaultParserProvider<X509Crl>,
    pub(crate) attribute_certificate: DefaultParserProvider<X509AttributeCertificate>,
}

impl DefaultX509Operator {
    pub(crate) fn new(
        algo: Arc<dyn Algo>,
        spki: DefaultSpkiProvider,
        signers: Vec<Arc<dyn SignerEntry>>,
        parsers: Parsers,
    ) -> Self {
        Self {
            algo,
            spki,
            signers,
            parsers,
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

    fn verifier_factory(
        &self,
        name: &str,
        public_key: Arc<dyn Params>,
    ) -> Result<Box<dyn VerifierFactory>, X509Error> {
        let row = self.find_signer(name).ok_or(X509Error::UnknownSigner)?;
        Ok(Box::new(DefaultVerifierFactory::new(
            self.algo.clone(),
            row.clone(),
            row.algorithm().clone(),
            public_key,
        )?))
    }

    fn verifier_factory_provider(
        &self,
        public_key: Arc<dyn Params>,
    ) -> Box<dyn VerifierFactoryProvider> {
        Box::new(DefaultVerifierFactoryProvider::new(
            self.algo.clone(),
            self.signers.clone(),
            public_key,
        ))
    }

    fn certificate_parser(&self) -> &dyn ParserProvider<X509Certificate> {
        &self.parsers.certificate
    }

    fn crl_parser(&self) -> &dyn ParserProvider<X509Crl> {
        &self.parsers.crl
    }

    fn attribute_certificate_parser(&self) -> &dyn ParserProvider<X509AttributeCertificate> {
        &self.parsers.attribute_certificate
    }
}
