use super::TspOperator;

pub trait TspOperatorBuilder {
    fn build(&self) -> Box<dyn TspOperator>;
}
