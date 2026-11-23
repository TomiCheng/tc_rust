use crate::default_algo_asn1::DefaultAlgoAsn1;
use crate::pkcs8::{self, DefaultPkcs8Provider, Pkcs8Entry};
use crate::spki::{self, DefaultSpkiProvider, SpkiEntry};
use crate::{AlgoAsn1, AlgoAsn1Builder, DefaultAlgoAsn1Context};

#[derive(Clone)]
pub struct DefaultAlgoAsn1Builder {
    spkis: Vec<spki::CreateRows>,
    pkcs8s: Vec<pkcs8::CreateRows>,
}

// Starts with the built-in rows
impl Default for DefaultAlgoAsn1Builder {
    fn default() -> Self {
        Self {
            spkis: spki::BUILT_IN.to_vec(),
            pkcs8s: pkcs8::BUILT_IN.to_vec(),
        }
    }
}

impl DefaultAlgoAsn1Builder {
    // Rows registered later are tried first, so they can take over a built-in one
    pub fn reg_spki(&mut self, create: fn(&DefaultAlgoAsn1Context) -> Vec<Box<dyn SpkiEntry>>) {
        self.spkis.push(create);
    }

    // Rows registered later are tried first, so they can take over a built-in one
    pub fn reg_pkcs8(&mut self, create: fn(&DefaultAlgoAsn1Context) -> Vec<Box<dyn Pkcs8Entry>>) {
        self.pkcs8s.push(create);
    }
}

impl AlgoAsn1Builder for DefaultAlgoAsn1Builder {
    fn build(&self) -> Box<dyn AlgoAsn1> {
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
        Box::new(DefaultAlgoAsn1::new(
            DefaultSpkiProvider::new(spki_rows),
            DefaultPkcs8Provider::new(pkcs8_rows),
        ))
    }
}
