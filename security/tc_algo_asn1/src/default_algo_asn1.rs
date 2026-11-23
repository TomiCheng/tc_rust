use crate::AlgoAsn1;
use crate::spki::{DefaultSpkiProvider, SpkiProvider};

pub(crate) struct DefaultAlgoAsn1 {
    spki: DefaultSpkiProvider,
}

impl DefaultAlgoAsn1 {
    pub(crate) fn new(spki: DefaultSpkiProvider) -> Self {
        Self { spki }
    }
}

impl AlgoAsn1 for DefaultAlgoAsn1 {
    fn spki(&self) -> &dyn SpkiProvider {
        &self.spki
    }
}
