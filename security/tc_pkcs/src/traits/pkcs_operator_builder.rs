use super::PkcsOperator;

pub trait PkcsOperatorBuilder {
    fn build(&self) -> Box<dyn PkcsOperator>;
}
