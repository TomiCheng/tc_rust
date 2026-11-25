//! The RFC 5753 ECDH KEK derivation for CMS, after Bouncy Castle's
//! `ECDHKekGenerator`: the X9.63 KDF (KDF2) over the shared secret Z, with the
//! DER `ECC-CMS-SharedInfo` that names the wrap algorithm, the sender's user
//! keying material and the KEK length as its shared info.
//!
//! A CMS recipient's AES-256 key-wrap key from an ephemeral-static ECDH shared
//! secret, under `dhSinglePass-stdDH-sha256kdf-scheme`:
//!
//! ```
//! use tc_ecdh_kek::{EcdhKek, EcdhKekParamsRef};
//! use tc_kdf::{Kdf, KdfInit};
//! use tc_sha::Sha256Digest;
//! use tc_asn1_x509::alg::AlgorithmIdentifier;
//!
//! // Z from ECDH, the wrap algorithm as the sender wrote it, and the sender's UKM.
//! let z = [0x5a; 32];
//! let aes256_wrap = AlgorithmIdentifier::new("2.16.840.1.101.3.4.1.45".parse()?);
//! let ukm = [0x42; 64];
//!
//! let mut kek = EcdhKek::new(Sha256Digest::new());
//! kek.init(&EcdhKekParamsRef::with_extra_info(&aes256_wrap, 256, &z, &ukm))?;
//!
//! // The KEK is as long as the wrap algorithm's key: 256 bits.
//! let mut key = [0u8; 32];
//! kek.generate_bytes(&mut key)?;
//! # Ok::<(), Box<dyn core::error::Error>>(())
//! ```
//!
//! [`RawUkmKek`] is the non-conformant variant some senders used, for reading
//! their messages only.
//!
//! [`AgreementWithKdf`] runs a `tc_agreement` agreement and this derivation in
//! one step, as Bouncy Castle's `ECDHWithKdfBasicAgreement`,
//! `ECDHCWithKdfBasicAgreement` and `ECMqvWithKdfBasicAgreement` do. Alice and
//! Bob agree with ECDH and reach an AES-128 key-wrap key directly:
//!
//! ```
//! use tc_agreement::{Agreement, AgreementInit};
//! use tc_asn1_x509::alg::AlgorithmIdentifier;
//! use tc_asym_cipher::{KeyPairGenerator, KeyPairGeneratorInit};
//! use tc_ec_agreement::EcdhBasicAgreement;
//! use tc_ec_key::{EcKeyGenerationParams, EcKeyPairGenerator};
//! use tc_ecdh_kek::{AgreementWithKdf, EcdhKek, UkmParams};
//! use tc_fp_curve::FpCtCurve;
//! use tc_fp_curve::named_curves::SECP256R1;
//! use tc_sha::Sha256Digest;
//!
//! let field = SECP256R1.field();
//! let curve = SECP256R1.ct_curve(&field);
//! let g = SECP256R1.ct_generator(&curve);
//! let mut rng = rand::rng();
//! let mut generator = EcKeyPairGenerator::<&FpCtCurve<'_>, _>::new(&mut rng);
//! generator.init(&EcKeyGenerationParams::new(g))?;
//! let (alice_public, alice_private) = generator.generate_key_pair()?;
//! let (bob_public, bob_private) = generator.generate_key_pair()?;
//!
//! // A 128-bit key for AES-128 key wrap; the sender picks the UKM and sends it
//! // with the message.
//! let aes128_wrap = AlgorithmIdentifier::new("2.16.840.1.101.3.4.1.5".parse()?);
//! let ukm = vec![1, 2, 3, 4, 5, 6, 7, 8];
//! let agreement = || {
//!     let kdf = EcdhKek::new(Sha256Digest::default());
//!     AgreementWithKdf::new(EcdhBasicAgreement::new(), kdf, aes128_wrap.clone(), 128)
//! };
//!
//! let mut alice = agreement();
//! alice.init(&UkmParams::new(alice_private).with_ukm(ukm.clone()))?;
//! let mut alice_key = vec![0; alice.agreement_size()];
//! alice.calculate_agreement(&bob_public, &mut alice_key)?;
//!
//! let mut bob = agreement();
//! bob.init(&UkmParams::new(bob_private).with_ukm(ukm))?;
//! let mut bob_key = vec![0; bob.agreement_size()];
//! bob.calculate_agreement(&alice_public, &mut bob_key)?;
//!
//! assert_eq!(alice_key, bob_key);
//! # Ok::<(), Box<dyn std::error::Error>>(())
//! ```

#![no_std]

extern crate alloc;

mod agreement_with_kdf;
mod agreement_with_kdf_error;
mod ecdh_kek;
mod params;
mod raw_ukm_kek;
mod ukm_params;

pub use agreement_with_kdf::AgreementWithKdf;
pub use agreement_with_kdf_error::AgreementWithKdfError;
pub use ecdh_kek::EcdhKek;
pub use params::{EcdhKekParams, EcdhKekParamsRef};
pub use raw_ukm_kek::RawUkmKek;
pub use ukm_params::UkmParams;
