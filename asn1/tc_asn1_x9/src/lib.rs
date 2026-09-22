#![no_std]

//! X9.62 and SEC 1 elliptic curve encoding structures, without curve arithmetic.

extern crate alloc;

mod characteristic_two;
mod curve;
mod field_id;

pub use characteristic_two::{Basis, CharacteristicTwo, Pentanomial, UnknownBasis};
pub use curve::Curve;
pub use field_id::{FieldId, UnknownField};
