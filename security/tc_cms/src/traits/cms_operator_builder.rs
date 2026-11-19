use super::CmsOperator;

pub trait CmsOperatorBuilder {
    fn build(&self) -> Box<dyn CmsOperator>;
}
