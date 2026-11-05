use core::any::Any;

pub trait Params: Any {
    fn as_any(&self) -> &dyn Any;
}
