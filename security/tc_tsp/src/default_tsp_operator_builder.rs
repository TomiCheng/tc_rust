use std::sync::Arc;

use tc_algo::{Algo, AlgoBuilder, DefaultAlgoBuilder};
use tc_cms::{CmsOperatorBuilder, DefaultCmsOperatorBuilder};
use tc_x509::{DefaultX509OperatorBuilder, X509OperatorBuilder};

use crate::default_tsp_operator::DefaultTspOperator;
use crate::{TspOperator, TspOperatorBuilder};

#[derive(Clone, Default)]
pub struct DefaultTspOperatorBuilder {
    algo: Option<Arc<dyn Algo>>,
}

impl DefaultTspOperatorBuilder {
    // 沒設定時用 DefaultAlgoBuilder 的預設；X.509 與 CMS 的 operator 都建在同一個 algo 上
    pub fn set_algo(&mut self, algo: impl Into<Arc<dyn Algo>>) {
        self.algo = Some(algo.into());
    }
}

impl TspOperatorBuilder for DefaultTspOperatorBuilder {
    fn build(&self) -> Box<dyn TspOperator> {
        let algo = self
            .algo
            .clone()
            .unwrap_or_else(|| DefaultAlgoBuilder::default().build().into());
        let mut x509 = DefaultX509OperatorBuilder::default();
        x509.set_algo(algo.clone());
        let x509: Arc<dyn tc_x509::X509Operator> = x509.build().into();
        let mut cms = DefaultCmsOperatorBuilder::default();
        cms.set_algo(algo.clone());
        cms.set_x509(x509.clone());
        Box::new(DefaultTspOperator::new(algo, x509, cms.build().into()))
    }
}
