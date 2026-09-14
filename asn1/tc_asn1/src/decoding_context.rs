//! Borrowed decoding configuration and mutable nesting state.

use crate::{Asn1Error, DecodingOptions};

/// State for one decoding operation, borrowing its configuration.
///
/// The depth starts at zero and counts active constructed-content scopes. Call
/// [`Self::with_child`] once when entering constructed contents, then pass its
/// mutable context to the decoders inside that scope. Primitive contents do not
/// require another scope. Siblings therefore use the same depth, rather than
/// consuming each other's nesting budget.
///
/// The options are borrowed without copying or allocation. Their lifetime is
/// independent of the lifetime of the encoded input. This context is not `Copy`.
///
/// Inner decoders share the active depth. DER requirements are selected explicitly
/// through DER decoding methods, never stored in this context.
///
/// # Examples
/// ```
/// use tc_asn1::{DecodingContext, DecodingOptions};
/// let options = DecodingOptions::new(2, 4096, 64);
/// let mut context = DecodingContext::new(&options);
/// context.with_child(|context| {
///     assert_eq!(context.depth(), 1);
///     for _ in 0..2 {
///         context.with_child(|context| {
///             assert_eq!(context.depth(), 2);
///             Ok(())
///         })?;
///     }
///     Ok(())
/// })?;
/// assert_eq!(context.depth(), 0);
/// assert_eq!(options.depth(), 2);
/// # Ok::<(), tc_asn1::Asn1Error>(())
/// ```
#[derive(Debug)]
pub struct DecodingContext<'o> {
    options: &'o DecodingOptions,
    depth: u32,
}

impl<'o> DecodingContext<'o> {
    /// Borrow the options and initialize the active depth to zero. Constant time.
    /// A zero depth limit is allowed, but prevents entry into constructed contents.
    pub const fn new(options: &'o DecodingOptions) -> Self {
        Self { options, depth: 0 }
    }

    /// Borrow the original options without copying them. Constant time.
    ///
    /// # Examples
    /// ```
    /// use tc_asn1::{DecodingContext, DecodingOptions};
    /// let options = DecodingOptions::default();
    /// let context = DecodingContext::new(&options);
    /// assert!(core::ptr::eq(context.options(), &options));
    /// ```
    pub const fn options(&self) -> &'o DecodingOptions {
        self.options
    }

    /// Return the number of active constructed-content scopes. Constant time.
    /// This is the current depth, not the configured maximum or remaining budget.
    pub const fn depth(&self) -> u32 {
        self.depth
    }

    /// Run an operation one constructed-content level deeper.
    ///
    /// Restores the parent depth when the operation returns, including on error
    /// or panic unwinding. The original options are unchanged. An aborting panic
    /// terminates the process and does not unwind.
    /// Variable time: branches on public depth and executes the supplied operation;
    /// use only for public decoding data. No constant-time alternative is provided.
    ///
    /// # Errors
    /// Returns [`Asn1Error::DepthExceeded`] without calling the operation if the
    /// maximum depth has been reached. Otherwise propagates the operation's error.
    ///
    /// # Examples
    /// ```
    /// use tc_asn1::{Asn1Error, DecodingContext, DecodingOptions};
    /// let options = DecodingOptions::new(1, 4096, 64);
    /// let mut context = DecodingContext::new(&options);
    /// let result = context.with_child(|context| context.with_child(|_| Ok(())));
    /// assert_eq!(result, Err(Asn1Error::DepthExceeded));
    /// assert_eq!(context.depth(), 0);
    /// assert_eq!(context.with_child(|context| Ok(context.depth())), Ok(1));
    /// # Ok::<(), Asn1Error>(())
    /// ```
    pub fn with_child<T>(
        &mut self,
        operation: impl FnOnce(&mut Self) -> Result<T, Asn1Error>,
    ) -> Result<T, Asn1Error> {
        let mut scope = self.enter()?;
        operation(scope.context())
    }

    pub(crate) fn enter(&mut self) -> Result<DepthScope<'_, 'o>, Asn1Error> {
        if self.depth >= self.options.depth() {
            return Err(Asn1Error::DepthExceeded);
        }
        let parent_depth = self.depth;
        self.depth += 1;
        Ok(DepthScope {
            context: self,
            parent_depth,
        })
    }
}

/// Restore the parent depth on every unwinding exit from a child scope.
pub(crate) struct DepthScope<'c, 'o> {
    context: &'c mut DecodingContext<'o>,
    parent_depth: u32,
}

impl<'o> DepthScope<'_, 'o> {
    pub(crate) fn context(&mut self) -> &mut DecodingContext<'o> {
        self.context
    }

    pub(crate) fn options(&self) -> &'o DecodingOptions {
        self.context.options()
    }
}

impl Drop for DepthScope<'_, '_> {
    fn drop(&mut self) {
        self.context.depth = self.parent_depth;
    }
}

#[cfg(test)]
mod tests {
    extern crate std;

    use super::*;

    #[test]
    fn siblings_reuse_the_parent_depth_and_borrow_the_same_options() {
        let options = DecodingOptions::new(2, 4096, 64);
        let mut context = DecodingContext::new(&options);
        context
            .with_child(|context| {
                for _ in 0..3 {
                    context.with_child(|context| {
                        assert_eq!(context.depth(), 2);
                        assert!(core::ptr::eq(context.options(), &options));
                        Ok(())
                    })?;
                    assert_eq!(context.depth(), 1);
                }
                Ok(())
            })
            .unwrap();
        assert_eq!(context.depth(), 0);
        assert_eq!(options.depth(), 2);
    }

    #[test]
    fn depth_exhaustion_skips_the_operation_without_wrapping_or_changing_state() {
        for limit in [0, u32::MAX] {
            let options = DecodingOptions::new(limit, 4096, 64);
            let mut context = DecodingContext::new(&options);
            context.depth = limit;
            let result: Result<(), _> = context.with_child(|_| panic!("must not run"));
            assert_eq!(result, Err(Asn1Error::DepthExceeded));
            assert_eq!(context.depth(), limit);
        }
    }

    #[test]
    fn errors_restore_all_parent_scopes_and_allow_a_later_operation() {
        let options = DecodingOptions::new(2, 4096, 64);
        let mut context = DecodingContext::new(&options);
        let result: Result<(), _> =
            context.with_child(|context| context.with_child(|_| Err(Asn1Error::MalformedValue)));
        assert_eq!(result, Err(Asn1Error::MalformedValue));
        assert_eq!(context.depth(), 0);
        assert_eq!(context.with_child(|context| Ok(context.depth())), Ok(1));
        assert_eq!(context.depth(), 0);
    }

    #[test]
    fn panic_unwinding_restores_all_parent_scopes() {
        let options = DecodingOptions::new(2, 4096, 64);
        let mut context = DecodingContext::new(&options);
        let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            let _: Result<(), _> = context
                .with_child(|context| context.with_child(|_| panic!("failed decoding operation")));
        }));
        assert!(result.is_err());
        assert_eq!(context.depth(), 0);
        assert_eq!(context.with_child(|context| Ok(context.depth())), Ok(1));
    }
}
