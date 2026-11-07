use std::sync::Arc;

use tc_algo_v2::{Algo, AlgoBuilder, DefaultAlgoBuilder};

use crate::default_x509_operator::DefaultX509Operator;
use crate::operator::spki::SpkiEntry;
use crate::{DefaultX509OperatorContext, X509Operator, X509OperatorBuilder};

#[derive(Clone, Default)]
pub struct DefaultX509OperatorBuilder {
    algo: Option<Arc<dyn Algo>>,
    spkis: Vec<fn(&DefaultX509OperatorContext) -> Vec<Box<dyn SpkiEntry>>>,
}

impl DefaultX509OperatorBuilder {
    // The algorithms to work with. Without this, build uses DefaultAlgoBuilder's defaults
    pub fn set_algo(&mut self, algo: impl Into<Arc<dyn Algo>>) {
        self.algo = Some(algo.into());
    }

    pub fn reg_spki(&mut self, create: fn(&DefaultX509OperatorContext) -> Vec<Box<dyn SpkiEntry>>) {
        self.spkis.push(create);
    }
}

impl X509OperatorBuilder for DefaultX509OperatorBuilder {
    fn build(&self) -> Box<dyn X509Operator> {
        let algo = self
            .algo
            .clone()
            .unwrap_or_else(|| DefaultAlgoBuilder::default().build().into());
        Box::new(DefaultX509Operator::new(algo))
    }
}
