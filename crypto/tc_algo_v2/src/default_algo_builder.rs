use crate::default_algo::DefaultAlgo;
use crate::{Algo, AlgoBuilder};

#[derive(Clone, Copy, Debug, Default)]
pub struct DefaultAlgoBuilder;

impl AlgoBuilder for DefaultAlgoBuilder {
    fn build(&self) -> Box<dyn Algo> {
        Box::new(DefaultAlgo)
    }
}
