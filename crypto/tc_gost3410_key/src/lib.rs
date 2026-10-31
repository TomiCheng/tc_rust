//! GOST R 34.10-94 的參數與金鑰，移植自 Bouncy Castle：`Gost3410Parameters`、
//! `Gost3410ValidationParameters`、公私鑰、金鑰對產生器與參數產生器（程序 A、A'、B、B'、C）。
//! 簽章在另一個 crate。
//!
//! ```
//! use tc_asym_cipher::{KeyPairGenerator, KeyPairGeneratorInit};
//! use tc_gost3410_key::{
//!     Gost3410KeyGenerationParams, Gost3410KeyPairGenerator, Gost3410ParametersGenerator,
//! };
//!
//! // 以程序 A 產生 512 位元的 p 與 256 位元的 q（真正使用時是 1024 位元的程序 B）。
//! let mut rng = rand::rng();
//! let mut parameters = Gost3410ParametersGenerator::new();
//! parameters.init(512, 1, &mut rng)?;
//! let params = parameters.generate_parameters()?;
//!
//! let mut rng = rand::rng();
//! let mut generator = Gost3410KeyPairGenerator::new();
//! generator.init(Gost3410KeyGenerationParams::new(params, &mut rng))?;
//! let (public_key, private_key) = generator.generate_key_pair()?;
//! assert!(public_key.validate().is_ok() && private_key.validate().is_ok());
//! # Ok::<(), Box<dyn std::error::Error>>(())
//! ```

#![no_std]

extern crate alloc;

mod error;
mod key_pair_generator;
mod math;
mod parameters_generator;
mod params;

pub use error::Gost3410Error;
pub use key_pair_generator::Gost3410KeyPairGenerator;
pub use parameters_generator::Gost3410ParametersGenerator;
pub use params::{
    Gost3410KeyGenerationParams, Gost3410Parameters, Gost3410PrivateKey, Gost3410PublicKey,
    Gost3410ValidationParameters,
};
