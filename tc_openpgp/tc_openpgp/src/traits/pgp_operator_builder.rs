use super::PgpOperator;

pub trait PgpOperatorBuilder {
    fn build(&self) -> Box<dyn PgpOperator>;
}
