//! RC4 與以它為起點設計的 VMPC、ISAAC，建在 `tc_stream_cipher` 的 trait 上。
//!
//! 三者的狀態都是一張表，並以狀態本身當索引讀寫：查表位置依秘密而定，都不是常數時間，共用快取的
//! 環境下可能洩漏。RC4 已被攻破，VMPC 與 ISAAC 也少有使用；這裡只為與 BC 相容保留，新的協定請用
//! ChaCha。
//!
//! 開了 `rustcrypto` 時，[`Rc4Engine`] 改跑在 RustCrypto 的 `rc4` 上；VMPC 與 ISAAC 在 RustCrypto 沒有
//! 對應，不受影響。
//!
//! ```
//! use tc_rc4_family::Rc4Engine;
//! use tc_stream_cipher::{CipherDirection, KeyRef, StreamCipher, StreamCipherInit};
//!
//! let mut cipher = Rc4Engine::new();
//! cipher.init(CipherDirection::Encrypt, &KeyRef::new(b"Key"))?;
//!
//! let mut output = [0u8; 9];
//! cipher.process_bytes(b"Plaintext", &mut output)?;
//! assert_eq!(output, [0xbb, 0xf3, 0x16, 0xe8, 0xd9, 0x40, 0xaf, 0x0a, 0xd3]);
//! # Ok::<(), Box<dyn core::error::Error>>(())
//! ```

#![no_std]

mod isaac_engine;
mod rc4_engine;
mod rc4_portable_engine;
#[cfg(feature = "rustcrypto")]
mod rc4_rustcrypto_engine;
mod vmpc_engine;
mod vmpc_ksa3_engine;
mod vmpc_state;

pub use isaac_engine::IsaacEngine;
pub use rc4_engine::Rc4Engine;
pub use rc4_portable_engine::Rc4PortableEngine;
#[cfg(feature = "rustcrypto")]
pub use rc4_rustcrypto_engine::Rc4RustCryptoEngine;
pub use vmpc_engine::VmpcEngine;
pub use vmpc_ksa3_engine::VmpcKsa3Engine;
