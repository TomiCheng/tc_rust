//! Stream cipher implementations ported from Bouncy Castle's engine package.
//!
//! All engines implement the [`StreamCipher`](tc_crypto_core::StreamCipher) trait
//! from `tc_crypto_core`. Each algorithm owns its parameter type (validated key,
//! and nonce where applicable), while all engines report failures through the
//! shared [`StreamCipherError`] type.
//!
//! Stream ciphers keep fixed-size keystream state, so this crate is `no_std`
//! with no `alloc` requirement.

#![no_std]

pub mod chacha;
pub mod chacha7539;
mod error;
pub mod hc128;
pub mod hc256;
pub mod isaac;
pub mod rc4;
pub mod salsa20;
pub mod vmpc;
pub mod xchacha20;
pub mod xsalsa20;

pub use chacha::{
    CHACHA_DEFAULT_ROUNDS, CHACHA_MAX_KEY_BYTES, CHACHA_MIN_KEY_BYTES, CHACHA_NONCE_BYTES,
    ChaChaEngine, ChaChaParams,
};
pub use chacha7539::{
    CHACHA7539_KEY_BYTES, CHACHA7539_NONCE_BYTES, ChaCha7539Engine, ChaCha7539Params,
};
pub use error::StreamCipherError;
pub use hc128::{HC128_IV_BYTES, HC128_KEY_BYTES, Hc128Engine, Hc128Params};
pub use hc256::{
    HC256_IV_BYTES, HC256_KEY_BYTES, HC256_MIN_IV_BYTES, HC256_MIN_KEY_BYTES, Hc256Engine,
    Hc256Params,
};
pub use isaac::{ISAAC_MAX_KEY_BYTES, IsaacEngine, IsaacParams};
pub use rc4::{RC4_MAX_KEY_BYTES, Rc4Engine, Rc4Params};
pub use salsa20::{
    SALSA20_DEFAULT_ROUNDS, SALSA20_MAX_KEY_BYTES, SALSA20_MIN_KEY_BYTES, SALSA20_NONCE_BYTES,
    Salsa20Engine, Salsa20Params,
};
pub use vmpc::{
    VMPC_MAX_IV_BYTES, VMPC_MAX_KEY_BYTES, VMPC_MIN_IV_BYTES, VMPC_MIN_KEY_BYTES, VmpcEngine,
    VmpcKsa3Engine, VmpcParams,
};
pub use xchacha20::{XCHACHA20_KEY_BYTES, XCHACHA20_NONCE_BYTES, XChaCha20Engine, XChaCha20Params};
pub use xsalsa20::{XSALSA20_KEY_BYTES, XSALSA20_NONCE_BYTES, Xsalsa20Engine, Xsalsa20Params};
