use super::Algo;

pub trait AlgoBuilder {
    fn build(&self) -> Box<dyn Algo>;
}
