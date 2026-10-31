//! The parameters every factory's init takes, as plain data: the key and the operation
//! parameters. Nothing here checks its contents; each algorithm does when it is initialized.

mod any_key_params;
mod any_op_params;
mod any_params;

pub use any_key_params::AnyKeyParams;
pub use any_op_params::AnyOpParams;
pub use any_params::AnyParams;
