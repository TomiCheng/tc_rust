use std::sync::Arc;

use tc_algo::{Algo, AlgoBuilder, DefaultAlgoBuilder};
use tc_x509::{DefaultX509OperatorBuilder, X509Operator, X509OperatorBuilder};

use crate::default_pkcs_operator::DefaultPkcsOperator;
use crate::operator::private_key_info::{self, DefaultPrivateKeyInfoProvider, PrivateKeyInfoEntry};
use crate::{DefaultPkcsOperatorContext, PkcsOperator, PkcsOperatorBuilder};

#[derive(Clone)]
pub struct DefaultPkcsOperatorBuilder {
    algo: Option<Arc<dyn Algo>>,
    x509: Option<Arc<dyn X509Operator>>,
    private_key_infos: Vec<private_key_info::CreateRows>,
}

// Starts with the built-in rows
impl Default for DefaultPkcsOperatorBuilder {
    fn default() -> Self {
        Self {
            algo: None,
            x509: None,
            private_key_infos: private_key_info::BUILT_IN.to_vec(),
        }
    }
}

impl DefaultPkcsOperatorBuilder {
    // The algorithms to work with. Without this, build uses DefaultAlgoBuilder's defaults
    pub fn set_algo(&mut self, algo: impl Into<Arc<dyn Algo>>) {
        self.algo = Some(algo.into());
    }

    // The X.509 operator to work with. Without this, build makes a default one over the algorithms
    pub fn set_x509(&mut self, x509: impl Into<Arc<dyn X509Operator>>) {
        self.x509 = Some(x509.into());
    }

    // Rows registered later are tried first, so they can take over a built-in one
    pub fn reg_private_key_info(
        &mut self,
        create: fn(&DefaultPkcsOperatorContext) -> Vec<Box<dyn PrivateKeyInfoEntry>>,
    ) {
        self.private_key_infos.push(create);
    }
}

impl PkcsOperatorBuilder for DefaultPkcsOperatorBuilder {
    fn build(&self) -> Box<dyn PkcsOperator> {
        let algo = self
            .algo
            .clone()
            .unwrap_or_else(|| DefaultAlgoBuilder::default().build().into());
        let x509 = self.x509.clone().unwrap_or_else(|| {
            let mut builder = DefaultX509OperatorBuilder::default();
            builder.set_algo(algo.clone());
            builder.build().into()
        });
        let context = DefaultPkcsOperatorContext;
        let rows = self
            .private_key_infos
            .iter()
            .rev()
            .flat_map(|create| create(&context))
            .collect();
        Box::new(DefaultPkcsOperator::new(
            algo,
            x509,
            DefaultPrivateKeyInfoProvider::new(rows),
        ))
    }
}
