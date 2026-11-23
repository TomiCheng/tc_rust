use crate::default_algo_asn1::DefaultAlgoAsn1;
use crate::{AlgoAsn1, AlgoAsn1Builder};

#[derive(Clone, Default)]
pub struct DefaultAlgoAsn1Builder;

impl AlgoAsn1Builder for DefaultAlgoAsn1Builder {
    fn build(&self) -> Box<dyn AlgoAsn1> {
        Box::new(DefaultAlgoAsn1)
    }
}
