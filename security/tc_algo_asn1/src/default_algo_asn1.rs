use crate::AlgoAsn1;
use crate::cipher::{CipherProvider, DefaultCipherProvider};
use crate::digest::{DefaultDigestProvider, DigestProvider};
use crate::mac::{DefaultMacProvider, MacProvider};
use crate::pkcs8::{DefaultPkcs8Provider, Pkcs8Provider};
use crate::signer::{DefaultSignerProvider, SignerProvider};
use crate::spki::{DefaultSpkiProvider, SpkiProvider};

pub(crate) struct DefaultAlgoAsn1 {
    spki: DefaultSpkiProvider,
    pkcs8: DefaultPkcs8Provider,
    signer: DefaultSignerProvider,
    digest: DefaultDigestProvider,
    mac: DefaultMacProvider,
    cipher: DefaultCipherProvider,
}

impl DefaultAlgoAsn1 {
    pub(crate) fn new(
        spki: DefaultSpkiProvider,
        pkcs8: DefaultPkcs8Provider,
        signer: DefaultSignerProvider,
        digest: DefaultDigestProvider,
        mac: DefaultMacProvider,
        cipher: DefaultCipherProvider,
    ) -> Self {
        Self {
            spki,
            pkcs8,
            signer,
            digest,
            mac,
            cipher,
        }
    }
}

impl AlgoAsn1 for DefaultAlgoAsn1 {
    fn spki(&self) -> &dyn SpkiProvider {
        &self.spki
    }

    fn pkcs8(&self) -> &dyn Pkcs8Provider {
        &self.pkcs8
    }

    fn signer(&self) -> &dyn SignerProvider {
        &self.signer
    }

    fn digest(&self) -> &dyn DigestProvider {
        &self.digest
    }

    fn mac(&self) -> &dyn MacProvider {
        &self.mac
    }

    fn cipher(&self) -> &dyn CipherProvider {
        &self.cipher
    }
}
