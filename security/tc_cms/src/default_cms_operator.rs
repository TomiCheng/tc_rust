use std::sync::Arc;

use tc_algo::Algo;
use tc_x509::X509Operator;

use crate::CmsOperator;
use crate::signed::SignedDataProvider;

pub(crate) struct DefaultCmsOperator {
    pub(crate) algo: Arc<dyn Algo>,
    pub(crate) x509: Arc<dyn X509Operator>,
}

impl DefaultCmsOperator {
    pub(crate) fn new(algo: Arc<dyn Algo>, x509: Arc<dyn X509Operator>) -> Self {
        Self { algo, x509 }
    }
}

impl CmsOperator for DefaultCmsOperator {
    fn signed_data(&self) -> &dyn SignedDataProvider {
        self
    }
}
