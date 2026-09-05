//! FIPS 186-4 prime-generation and primality-testing utilities.
//!
//! This crate ports the algorithms exposed by Bouncy Castle C#'s `Primes`
//! utility. It is separate from the general-purpose probable-prime methods in
//! [`tc_bigint`]. The public API provides:
//!
//! - packed trial division by every prime through 211;
//! - Miller-Rabin testing with random or caller-selected bases;
//! - enhanced Miller-Rabin results which may include a discovered factor; and
//! - Shawe-Taylor provable-prime generation behind the `digest` feature.
//!
//! The integer-generic APIs work with both `tc_bigint::BigUint` when the
//! default `alloc` feature is enabled and allocation-free fixed-width integers
//! such as [`tc_bigint::U1024`].
//!
//! All algorithms in this crate are variable-time. They are intended to test
//! public prime candidates. The caller must provide a cryptographically secure
//! random generator when candidates or Miller-Rabin bases must be unpredictable.
//!
//! # Example
//!
//! ```
//! use tc_bigint::U64;
//! use tc_prime::{has_any_small_factors, is_mr_probable_prime_to_base};
//!
//! let candidate = U64::from(104_729_u32);
//! let base = U64::from(2_u8);
//!
//! assert!(!has_any_small_factors(&candidate)?);
//! assert!(is_mr_probable_prime_to_base(&candidate, &base)?);
//! # Ok::<(), tc_prime::PrimeError>(())
//! ```

#![no_std]

#[cfg(feature = "alloc")]
extern crate alloc;
#[cfg(test)]
extern crate std;

mod enhanced;
mod error;
mod integer;
mod miller_rabin;
#[cfg(feature = "digest")]
mod shawe_taylor;
mod small_factors;

pub use enhanced::{MrOutput, enhanced_mr_probable_prime_test};
pub use error::PrimeError;
pub use integer::PrimeInteger;
pub use miller_rabin::{is_mr_probable_prime, is_mr_probable_prime_to_base};
#[cfg(feature = "digest")]
pub use shawe_taylor::{StOutput, generate_st_random_prime};
pub use small_factors::{SMALL_FACTOR_LIMIT, has_any_small_factors};
