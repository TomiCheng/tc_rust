use crate::AlgoAsn1;
use crate::private_key_info::{DefaultPrivateKeyInfoProvider, PrivateKeyInfoProvider};
use crate::spki::{DefaultSpkiProvider, SpkiProvider};

pub(crate) struct DefaultAlgoAsn1 {
    spki: DefaultSpkiProvider,
    private_key_info: DefaultPrivateKeyInfoProvider,
}

impl DefaultAlgoAsn1 {
    pub(crate) fn new(
        spki: DefaultSpkiProvider,
        private_key_info: DefaultPrivateKeyInfoProvider,
    ) -> Self {
        Self {
            spki,
            private_key_info,
        }
    }
}

impl AlgoAsn1 for DefaultAlgoAsn1 {
    fn spki(&self) -> &dyn SpkiProvider {
        &self.spki
    }

    fn private_key_info(&self) -> &dyn PrivateKeyInfoProvider {
        &self.private_key_info
    }
}
