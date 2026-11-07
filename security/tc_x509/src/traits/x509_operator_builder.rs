use super::X509Operator;

pub trait X509OperatorBuilder {
    fn build(&self) -> Box<dyn X509Operator>;
}
