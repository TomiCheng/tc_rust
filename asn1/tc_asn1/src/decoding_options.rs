//! Decoding options and nesting-depth budgets.
//!
//! Recursive decoding of deeply nested constructed values can exhaust the stack.
//! [`crate::DecodingContext`] tracks active nesting while borrowing these limits.
//! Limiting the depth of decoded trees also bounds their recursive destruction.
//!
//! [`DecodingOptions`] groups a maximum depth with content-length and child-count
//! limits. Nested decoders share a context without copying these options.
//! Definite-length opaque values are not traversed: limits on their descendants
//! apply when the caller decodes or iterates those descendants.

use crate::error::Asn1Error;

/// Configuration for decoding depth, content length, and direct child count.
///
/// Defaults to 32 levels, 16 MiB of contents per element, and 65,536 direct
/// children per constructed element. These are per-element limits, not a shared
/// budget for total allocations or total nodes in a decoded tree.
///
/// Fields are private. Use [`new`](Self::new) to select limits and the getters to
/// inspect them. Creating options does not consume any depth budget.
///
/// # Examples
///
/// ```
/// use tc_asn1::{DecodingOptions};
///
/// let options = DecodingOptions::default();
/// assert_eq!(options.depth(), 32);
/// assert_eq!(options.max_content_len(), 16 * 1024 * 1024);
/// assert_eq!(options.max_children(), 65_536);
/// ```
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct DecodingOptions {
    /// Maximum number of active constructed-content scopes.
    depth: u32,
    /// Maximum content length in bytes for a single element.
    max_content_len: usize,
    /// Maximum number of direct children of each constructed element.
    max_children: usize,
}

impl DecodingOptions {
    pub(crate) fn check_content_len(&self, len: usize) -> Result<(), Asn1Error> {
        if len > self.max_content_len {
            Err(Asn1Error::ContentLengthExceeded)
        } else {
            Ok(())
        }
    }

    /// Create options with the specified depth, content-length, and child-count limits.
    ///
    /// Stores all values unchanged, including zero. This constructor neither decodes
    /// input nor enforces the limits. Constant time: copies the supplied values.
    ///
    /// # Examples
    ///
    /// ```
    /// use tc_asn1::{DecodingOptions};
    ///
    /// const OPTIONS: DecodingOptions = DecodingOptions::new(8, 4096, 64);
    /// assert_eq!(OPTIONS.depth(), 8);
    /// assert_eq!(OPTIONS.max_content_len(), 4096);
    /// assert_eq!(OPTIONS.max_children(), 64);
    /// ```
    pub const fn new(depth: u32, max_content_len: usize, max_children: usize) -> Self {
        Self {
            depth,
            max_content_len,
            max_children,
        }
    }

    /// Return the configured maximum depth without changing the active context.
    /// Constant time: reads the stored budget.
    ///
    /// # Examples
    ///
    /// ```
    /// use tc_asn1::{DecodingOptions};
    ///
    /// let options = DecodingOptions::new(2, 1024, 16);
    /// assert_eq!(options.depth(), 2);
    /// ```
    pub const fn depth(&self) -> u32 {
        self.depth
    }

    /// Return the configured maximum content length of a single element, in bytes.
    ///
    /// Contents exclude the outer tag, length field, and end-of-contents marker;
    /// a constructed element's contents include its child TLVs.
    /// Constant time: reads the stored limit.
    ///
    /// # Examples
    ///
    /// ```
    /// use tc_asn1::{DecodingOptions};
    ///
    /// let options = DecodingOptions::new(32, 4096, 64);
    /// assert_eq!(options.max_content_len(), 4096);
    /// ```
    pub const fn max_content_len(&self) -> usize {
        self.max_content_len
    }

    /// Return the configured maximum number of direct children of a constructed element.
    ///
    /// This is not the total number of descendants across all nesting levels.
    /// Constant time: reads the stored limit.
    ///
    /// # Examples
    ///
    /// ```
    /// use tc_asn1::{DecodingOptions};
    ///
    /// let options = DecodingOptions::new(32, 4096, 64);
    /// assert_eq!(options.max_children(), 64);
    /// ```
    pub const fn max_children(&self) -> usize {
        self.max_children
    }
}

impl Default for DecodingOptions {
    /// Use the default depth budget, 16 MiB content limit, and 65,536-child limit.
    /// Constant time: initializes fixed configuration values.
    fn default() -> Self {
        Self {
            depth: 32,
            max_content_len: 16 * 1024 * 1024,
            max_children: 65_536,
        }
    }
}

/// Remaining nesting-depth budget.
///
/// Call [`descend`](Self::descend) to spend one level before processing nested
/// contents, then pass the returned budget to the child decoding path.
/// This type is [`Copy`]: descending returns a new budget and leaves other copies
/// unchanged. It limits nesting along a path rather than the total number of nodes.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Depth(u32);

impl Depth {
    /// Default nesting budget of 32 levels.
    ///
    /// This is a library default, not an ASN.1 format limit.
    ///
    /// # Examples
    ///
    /// ```
    /// use tc_asn1::Depth;
    ///
    /// assert_eq!(Depth::DEFAULT.get(), 32);
    /// assert_eq!(Depth::default(), Depth::DEFAULT);
    /// ```
    pub const DEFAULT: Self = Self(32);

    /// Create a budget with the specified number of remaining levels.
    ///
    /// Zero is allowed, but its next [`descend`](Self::descend) call will fail.
    /// Constant time: stores the supplied limit.
    ///
    /// # Examples
    ///
    /// ```
    /// use tc_asn1::Depth;
    ///
    /// const LIMIT: Depth = Depth::new(8);
    /// assert_eq!(LIMIT.get(), 8);
    /// ```
    pub const fn new(limit: u32) -> Self {
        Self(limit)
    }

    /// Return the number of remaining levels without consuming the budget.
    /// Constant time: reads the stored value.
    ///
    /// # Examples
    ///
    /// ```
    /// use tc_asn1::Depth;
    ///
    /// let depth = Depth::new(2);
    /// assert_eq!(depth.get(), 2);
    /// assert_eq!(depth.get(), 2);
    /// ```
    pub const fn get(self) -> u32 {
        self.0
    }

    /// Spend one level and return the remaining budget.
    ///
    /// Checks for exhaustion and decrements the budget in one operation.
    /// Variable time: branches on the public depth budget; no constant-time
    /// alternative is provided.
    ///
    /// # Errors
    ///
    /// Returns [`Asn1Error::DepthExceeded`] when the budget is zero, without wrapping.
    ///
    /// # Examples
    ///
    /// ```
    /// use tc_asn1::{Asn1Error, Depth};
    ///
    /// let depth = Depth::new(2).descend()?;
    /// assert_eq!(depth.get(), 1);
    /// let depth = depth.descend()?;
    /// assert_eq!(depth.get(), 0);
    /// assert_eq!(depth.descend(), Err(Asn1Error::DepthExceeded));
    /// # Ok::<(), Asn1Error>(())
    /// ```
    pub const fn descend(self) -> Result<Self, Asn1Error> {
        match self.0.checked_sub(1) {
            Some(remaining) => Ok(Self(remaining)),
            None => Err(Asn1Error::DepthExceeded),
        }
    }
}

impl Default for Depth {
    /// Return [`Depth::DEFAULT`]. Constant time: initializes a fixed budget.
    fn default() -> Self {
        Self::DEFAULT
    }
}

#[cfg(test)]
mod tests {

    use super::*;

    #[test]
    fn descending_spends_one_level_at_a_time() {
        let depth = Depth::new(2);
        let depth = depth.descend().unwrap();
        assert_eq!(depth.get(), 1);

        let depth = depth.descend().unwrap();
        assert_eq!(depth.get(), 0);
    }

    #[test]
    fn descending_past_the_budget_is_rejected() {
        assert_eq!(Depth::new(0).descend(), Err(Asn1Error::DepthExceeded));
    }

    #[test]
    fn the_default_budget_is_deeper_than_any_real_certificate() {
        assert!(Depth::DEFAULT.get() >= 16);
    }
}
