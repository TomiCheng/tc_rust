//! The SP 800-108 KDFs in counter, feedback and double-pipeline mode, over
//! any MAC.
//!
//! A subkey for one purpose derived from a master key, in counter mode over
//! HMAC-SHA256. The fixed input follows the layout SP 800-108 suggests:
//! `Label || 0x00 || Context || [L]`, with L the output length in bits.
//!
//! ```
//! use tc_kdf::sp800_108::{KdfCounter, KdfCounterParamsRef};
//! use tc_kdf::{Kdf, KdfInit};
//! use tc_macs::Hmac;
//! use tc_sha::Sha256Digest;
//!
//! let master_key = [0x0b; 32];
//!
//! // Label names the purpose, Context the session; L is 256 bits.
//! let mut fixed_input = Vec::new();
//! fixed_input.extend_from_slice(b"encryption");
//! fixed_input.push(0x00);
//! fixed_input.extend_from_slice(b"session 42");
//! fixed_input.extend_from_slice(&256u32.to_be_bytes());
//!
//! // A 32-bit counter goes before the fixed input.
//! let mut kdf = KdfCounter::new(Hmac::new(Sha256Digest::new()));
//! kdf.init(&KdfCounterParamsRef::new(&master_key, &fixed_input, 32))?;
//!
//! let mut subkey = [0u8; 32];
//! kdf.generate_bytes(&mut subkey)?;
//! # Ok::<(), Box<dyn core::error::Error>>(())
//! ```

mod counter;
mod counter_field;
mod double_pipeline;
mod feedback;
mod init_error;
mod params;
mod params_owned;
mod params_ref;

pub use counter::KdfCounter;
pub use double_pipeline::KdfDoublePipeline;
pub use feedback::KdfFeedback;
pub use init_error::KdfInitError;
pub use params::{KdfCounterParams, KdfDoublePipelineParams, KdfFeedbackParams};
pub use params_owned::{
    KdfCounterParamsOwned, KdfDoublePipelineParamsOwned, KdfFeedbackParamsOwned,
};
pub use params_ref::{KdfCounterParamsRef, KdfDoublePipelineParamsRef, KdfFeedbackParamsRef};
