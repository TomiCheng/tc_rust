use std::sync::Arc;

use tc_algo::{Algo, AlgoBuilder, DefaultAlgoBuilder};
use tc_x509::{DefaultX509OperatorBuilder, X509Operator, X509OperatorBuilder};

use crate::default_cms_operator::DefaultCmsOperator;
use crate::{CmsOperator, CmsOperatorBuilder};

#[derive(Clone, Default)]
pub struct DefaultCmsOperatorBuilder {
    algo: Option<Arc<dyn Algo>>,
    x509: Option<Arc<dyn X509Operator>>,
}

impl DefaultCmsOperatorBuilder {
    // 沒設定時用 DefaultAlgoBuilder 的預設
    pub fn set_algo(&mut self, algo: impl Into<Arc<dyn Algo>>) {
        self.algo = Some(algo.into());
    }

    // 沒設定時用同一個 algo 建預設的 X509Operator
    pub fn set_x509(&mut self, x509: impl Into<Arc<dyn X509Operator>>) {
        self.x509 = Some(x509.into());
    }
}

impl CmsOperatorBuilder for DefaultCmsOperatorBuilder {
    fn build(&self) -> Box<dyn CmsOperator> {
        let algo = self
            .algo
            .clone()
            .unwrap_or_else(|| DefaultAlgoBuilder::default().build().into());
        let x509 = self.x509.clone().unwrap_or_else(|| {
            let mut builder = DefaultX509OperatorBuilder::default();
            builder.set_algo(algo.clone());
            builder.build().into()
        });
        Box::new(DefaultCmsOperator::new(algo, x509))
    }
}
