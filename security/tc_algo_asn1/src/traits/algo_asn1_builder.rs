use super::AlgoAsn1;

pub trait AlgoAsn1Builder {
    fn build(&self) -> Box<dyn AlgoAsn1>;
}
