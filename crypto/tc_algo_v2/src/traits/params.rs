use core::any::Any;

// Send and Sync, as the other traits of this crate are, so that a key can be shared between
// threads behind an Arc
pub trait Params: Any + Send + Sync {
    fn as_any(&self) -> &dyn Any;
}
