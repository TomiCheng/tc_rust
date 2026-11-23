use std::sync::Arc;

use tc_algo::{Algo, AlgoBuilder, DefaultAlgoBuilder};

use crate::default_algo_asn1::DefaultAlgoAsn1;
use crate::digest::{self, DefaultDigestProvider, DigestEntry};
use crate::pkcs8::{self, DefaultPkcs8Provider, Pkcs8Entry};
use crate::signer::{self, DefaultSignerProvider, SignerEntry};
use crate::spki::{self, DefaultSpkiProvider, SpkiEntry};
use crate::{AlgoAsn1, AlgoAsn1Builder, DefaultAlgoAsn1Context};

#[derive(Clone)]
pub struct DefaultAlgoAsn1Builder {
    algo: Option<Arc<dyn Algo>>,
    spkis: Vec<spki::CreateRows>,
    pkcs8s: Vec<pkcs8::CreateRows>,
    signers: Vec<signer::CreateRows>,
    digests: Vec<digest::CreateRows>,
}

// Starts with the built-in rows
impl Default for DefaultAlgoAsn1Builder {
    fn default() -> Self {
        Self {
            algo: None,
            spkis: spki::BUILT_IN.to_vec(),
            pkcs8s: pkcs8::BUILT_IN.to_vec(),
            signers: signer::BUILT_IN.to_vec(),
            digests: digest::BUILT_IN.to_vec(),
        }
    }
}

impl DefaultAlgoAsn1Builder {
    // The algorithms the signers come from; DefaultAlgoBuilder's when none is set
    pub fn set_algo(&mut self, algo: Arc<dyn Algo>) {
        self.algo = Some(algo);
    }

    // Rows registered later are tried first, so they can take over a built-in one
    pub fn reg_spki(&mut self, create: fn(&DefaultAlgoAsn1Context) -> Vec<Box<dyn SpkiEntry>>) {
        self.spkis.push(create);
    }

    // Rows registered later are tried first, so they can take over a built-in one
    pub fn reg_pkcs8(&mut self, create: fn(&DefaultAlgoAsn1Context) -> Vec<Box<dyn Pkcs8Entry>>) {
        self.pkcs8s.push(create);
    }

    // Rows registered later are found first, so they can take over a built-in one
    pub fn reg_signer(&mut self, create: fn(&DefaultAlgoAsn1Context) -> Vec<Box<dyn SignerEntry>>) {
        self.signers.push(create);
    }

    // Rows registered later are found first, so they can take over a built-in one
    pub fn reg_digest(&mut self, create: fn(&DefaultAlgoAsn1Context) -> Vec<Box<dyn DigestEntry>>) {
        self.digests.push(create);
    }
}

impl AlgoAsn1Builder for DefaultAlgoAsn1Builder {
    fn build(&self) -> Box<dyn AlgoAsn1> {
        let algo = self
            .algo
            .clone()
            .unwrap_or_else(|| Arc::from(DefaultAlgoBuilder::default().build()));
        let context = DefaultAlgoAsn1Context;
        let spki_rows = self
            .spkis
            .iter()
            .rev()
            .flat_map(|create| create(&context))
            .collect();
        let pkcs8_rows = self
            .pkcs8s
            .iter()
            .rev()
            .flat_map(|create| create(&context))
            .collect();
        let signer_rows = self
            .signers
            .iter()
            .rev()
            .flat_map(|create| create(&context))
            .collect();
        let digest_rows = self
            .digests
            .iter()
            .rev()
            .flat_map(|create| create(&context))
            .collect();
        Box::new(DefaultAlgoAsn1::new(
            DefaultSpkiProvider::new(spki_rows),
            DefaultPkcs8Provider::new(pkcs8_rows),
            DefaultSignerProvider::new(algo.clone(), signer_rows),
            DefaultDigestProvider::new(algo, digest_rows),
        ))
    }
}
