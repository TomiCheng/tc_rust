use std::sync::Arc;

use tc_algo_v2::{Algo, AlgoBuilder, DefaultAlgoBuilder};

use crate::default_x509_operator::DefaultX509Operator;
use crate::operator::signer::{self, SignerEntry};
use crate::operator::spki::{self, DefaultSpkiProvider, SpkiEntry};
use crate::{DefaultX509OperatorContext, X509Operator, X509OperatorBuilder};

#[derive(Clone)]
pub struct DefaultX509OperatorBuilder {
    algo: Option<Arc<dyn Algo>>,
    spkis: Vec<spki::CreateRows>,
    signers: Vec<signer::CreateRows>,
}

// Starts with the built-in rows
impl Default for DefaultX509OperatorBuilder {
    fn default() -> Self {
        Self {
            algo: None,
            spkis: spki::BUILT_IN.to_vec(),
            signers: signer::BUILT_IN.to_vec(),
        }
    }
}

impl DefaultX509OperatorBuilder {
    // The algorithms to work with. Without this, build uses DefaultAlgoBuilder's defaults
    pub fn set_algo(&mut self, algo: impl Into<Arc<dyn Algo>>) {
        self.algo = Some(algo.into());
    }

    // Rows registered later are tried first, so they can take over a built-in one
    pub fn reg_spki(&mut self, create: fn(&DefaultX509OperatorContext) -> Vec<Box<dyn SpkiEntry>>) {
        self.spkis.push(create);
    }

    // Rows registered later are found first, so they can take over a built-in one
    pub fn reg_signer(
        &mut self,
        create: fn(&DefaultX509OperatorContext) -> Vec<Box<dyn SignerEntry>>,
    ) {
        self.signers.push(create);
    }
}

impl X509OperatorBuilder for DefaultX509OperatorBuilder {
    fn build(&self) -> Box<dyn X509Operator> {
        let algo = self
            .algo
            .clone()
            .unwrap_or_else(|| DefaultAlgoBuilder::default().build().into());
        let context = DefaultX509OperatorContext;
        let spki_rows = self
            .spkis
            .iter()
            .rev()
            .flat_map(|create| create(&context))
            .collect();
        let signer_rows = self
            .signers
            .iter()
            .rev()
            .flat_map(|create| create(&context))
            .map(Arc::from)
            .collect();
        Box::new(DefaultX509Operator::new(
            algo,
            DefaultSpkiProvider::new(spki_rows),
            signer_rows,
        ))
    }
}
