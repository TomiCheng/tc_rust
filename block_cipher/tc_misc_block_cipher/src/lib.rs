//! Less common block ciphers on the `tc_block_cipher` traits, one feature each:
//! `idea`, `noekeon`, `rijndael`, `skipjack` and `tea` (TEA and XTEA).

#![no_std]

#[cfg(feature = "idea")]
pub mod idea;
#[cfg(feature = "noekeon")]
pub mod noekeon;
#[cfg(feature = "rijndael")]
pub mod rijndael;
#[cfg(feature = "skipjack")]
pub mod skipjack;
#[cfg(feature = "tea")]
pub mod tea;
