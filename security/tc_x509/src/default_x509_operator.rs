use std::sync::Arc;

use tc_algo_v2::Algo;

use crate::X509Operator;

pub(crate) struct DefaultX509Operator {
    algo: Arc<dyn Algo>,
}

impl DefaultX509Operator {
    pub(crate) fn new(algo: Arc<dyn Algo>) -> Self {
        Self { algo }
    }
}

impl X509Operator for DefaultX509Operator {}
