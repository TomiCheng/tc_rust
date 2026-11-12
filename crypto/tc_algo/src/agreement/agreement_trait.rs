use crate::agreement::SharedSecret;
use crate::{AlgoError, Params};

pub trait Agreement {
    // Takes this side's private key
    fn init(&mut self, params: &dyn Params) -> Result<(), AlgoError>;

    fn calculate_agreement(&self, public_key: &dyn Params) -> Result<SharedSecret, AlgoError>;
}
