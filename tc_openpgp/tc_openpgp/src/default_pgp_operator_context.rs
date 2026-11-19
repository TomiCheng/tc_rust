use std::sync::Arc;

use tc_algo::Algo;

/// Services available to OpenPGP generator factories.
pub struct DefaultPgpOperatorContext {
    algo: Arc<dyn Algo>,
}

impl DefaultPgpOperatorContext {
    pub(crate) fn new(algo: Arc<dyn Algo>) -> Self {
        Self { algo }
    }

    pub fn algo(&self) -> &Arc<dyn Algo> {
        &self.algo
    }
}
