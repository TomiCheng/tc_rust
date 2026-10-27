//! RFC 5084 parameters of authenticated content encryption with AES.

mod ccm_parameters;
mod gcm_parameters;

pub use ccm_parameters::CcmParameters;
pub use gcm_parameters::GcmParameters;
