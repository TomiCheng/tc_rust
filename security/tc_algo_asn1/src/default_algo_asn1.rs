use crate::AlgoAsn1;
use crate::pkcs8::{DefaultPkcs8Provider, Pkcs8Provider};
use crate::spki::{DefaultSpkiProvider, SpkiProvider};

pub(crate) struct DefaultAlgoAsn1 {
    spki: DefaultSpkiProvider,
    pkcs8: DefaultPkcs8Provider,
}

impl DefaultAlgoAsn1 {
    pub(crate) fn new(spki: DefaultSpkiProvider, pkcs8: DefaultPkcs8Provider) -> Self {
        Self { spki, pkcs8 }
    }
}

impl AlgoAsn1 for DefaultAlgoAsn1 {
    fn spki(&self) -> &dyn SpkiProvider {
        &self.spki
    }

    fn pkcs8(&self) -> &dyn Pkcs8Provider {
        &self.pkcs8
    }
}
