//! A platform-sized word with big-integer arithmetic semantics.

use crate::Word;

/// A single word of a multi-word integer.
#[repr(transparent)]
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct Limb(pub Word);
