use crate::default_x509_operator::DefaultX509Operator;
use crate::{X509Operator, X509OperatorBuilder};

#[derive(Clone, Debug, Default)]
pub struct DefaultX509OperatorBuilder;

impl X509OperatorBuilder for DefaultX509OperatorBuilder {
    fn build(&self) -> Box<dyn X509Operator> {
        Box::new(DefaultX509Operator)
    }
}
