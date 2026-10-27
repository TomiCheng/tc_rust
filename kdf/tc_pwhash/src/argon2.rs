//! Argon2 of RFC 9106, by Biryukov, Dinu and Khovratovich: [`Argon2`] is BC's
//! `Argon2BytesGenerator`, memory-hard password hashing in three variants, of which RFC 9106
//! recommends Argon2id.
//!
//! Hashing a password to store:
//!
//! ```
//! use tc_pwhash::argon2::{Argon2, Argon2ParamsRef, Argon2Type};
//!
//! // A fresh random salt per password, stored beside the hash.
//! let salt = [0x3c; 16];
//!
//! // RFC 9106's second recommendation: Argon2id, 3 passes over 64 MiB in 4 lanes.
//! let params = Argon2ParamsRef::new(Argon2Type::Argon2id, &salt)
//!     .with_iterations(3)
//!     .with_memory_kib(64 * 1024)
//!     .with_parallelism(4);
//!
//! let mut argon2 = Argon2::new();
//! argon2.init(&params)?;
//! let mut hash = [0u8; 32];
//! argon2.generate_bytes(b"correct horse", &mut hash)?;
//! # Ok::<(), tc_pwhash::argon2::Argon2Error>(())
//! ```

mod argon2_error;
mod argon2_params_ref;
mod argon2_type;
mod argon2_version;
mod block;
mod generator;
mod hash;

pub use argon2_error::Argon2Error;
pub use argon2_params_ref::Argon2ParamsRef;
pub use argon2_type::Argon2Type;
pub use argon2_version::Argon2Version;
pub use generator::Argon2;
