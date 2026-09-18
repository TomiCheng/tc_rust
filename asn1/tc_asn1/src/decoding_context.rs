use crate::{Asn1Error, DecodingOptions};

#[derive(Debug)]
pub struct DecodingContext {
    options: DecodingOptions,
    depth: u32,
    is_der: bool,
}

impl DecodingContext {
    pub const fn new(options: DecodingOptions) -> Self {
        Self {
            options,
            depth: 0,
            is_der: false,
        }
    }

    /// A context that applies the DER rules from the start.
    pub const fn new_der(options: DecodingOptions) -> Self {
        Self {
            options,
            depth: 0,
            is_der: true,
        }
    }

    pub const fn options(&self) -> &DecodingOptions {
        &self.options
    }

    pub const fn depth(&self) -> u32 {
        self.depth
    }

    pub const fn is_der(&self) -> bool {
        self.is_der
    }

    pub(crate) fn enter(&mut self) -> Result<DepthScope<'_>, Asn1Error> {
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

    pub fn enter_der(&mut self) -> DerScope<'_> {
        let old_value = self.is_der;
        self.is_der = true;
        DerScope {
            context: self,
            old_value,
        }
    }
}

pub(crate) struct DepthScope<'c> {
    context: &'c mut DecodingContext,
    parent_depth: u32,
}

impl<'c> DepthScope<'c> {
    pub(crate) fn context(&mut self) -> &mut DecodingContext {
        self.context
    }

    pub(crate) fn options(&self) -> &DecodingOptions {
        self.context.options()
    }
}

impl Drop for DepthScope<'_> {
    fn drop(&mut self) {
        self.context.depth = self.parent_depth;
    }
}

pub struct DerScope<'c> {
    context: &'c mut DecodingContext,
    old_value: bool,
}

impl<'c> DerScope<'c> {
    pub fn context(&mut self) -> &mut DecodingContext {
        self.context
    }

    pub fn options(&self) -> &DecodingOptions {
        self.context.options()
    }
}

impl<'c> Drop for DerScope<'c> {
    fn drop(&mut self) {
        self.context.is_der = self.old_value;
    }
}
