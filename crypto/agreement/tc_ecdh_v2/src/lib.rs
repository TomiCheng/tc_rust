//! ECDH key agreement; a rewrite of `tc_ecdh` on `tc_ec_core_v2`.
//!
//! Alice and Bob agree on a secret over an open channel, sending each other only their
//! public keys:
//!
//! ```
//! use tc_agreement::{Agreement, AgreementInit};
//! use tc_asym_cipher::{KeyPairGenerator, KeyPairGeneratorInit};
//! use tc_ec_key::{EcKeyGenerationParams, EcKeyPairGenerator};
//! use tc_ecdh_v2::EcdhBasicAgreement;
//! use tc_fp_curve_v2::FpCtCurve;
//! use tc_fp_curve_v2::named_curves::SECP256R1;
//!
//! // Both use the same constant-time curve and its generator G.
//! let field = SECP256R1.field();
//! let curve = SECP256R1.ct_curve(&field);
//! let g = SECP256R1.ct_generator(&curve);
//! let mut rng = rand::rng();
//! let mut generator = EcKeyPairGenerator::<&FpCtCurve<'_>>::new();
//! generator.init(EcKeyGenerationParams::new(g, &mut rng))?;
//!
//! // Each makes a key pair and sends the other the public key.
//! let (alice_public, alice_private) = generator.generate_key_pair()?;
//! let (bob_public, bob_private) = generator.generate_key_pair()?;
//!
//! // Alice combines her private key with Bob's public key...
//! let mut alice = EcdhBasicAgreement::new();
//! alice.init(&alice_private)?;
//! let mut alice_secret = vec![0; alice.agreement_size()];
//! alice.calculate_agreement(&bob_public, &mut alice_secret)?;
//!
//! // ...and Bob his with hers; both reach the same secret, ready for a KDF.
//! let mut bob = EcdhBasicAgreement::new();
//! bob.init(&bob_private)?;
//! let mut bob_secret = vec![0; bob.agreement_size()];
//! bob.calculate_agreement(&alice_public, &mut bob_secret)?;
//!
//! assert_eq!(alice_secret, bob_secret);
//! # Ok::<(), Box<dyn std::error::Error>>(())
//! ```

#![no_std]

mod basic_agreement;
mod error;

pub use basic_agreement::EcdhBasicAgreement;
pub use error::EcdhError;
