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

    pub const fn options(&self) -> &DecodingOptions {
        &self.options
    }

    pub const fn depth(&self) -> u32 {
        self.depth
    }

    pub const fn is_der(&self) -> bool {
        self.is_der
    }

    // pub fn with_child<T>(
    //     &mut self,
    //     operation: impl FnOnce(&mut Self) -> Result<T, Asn1Error>,
    // ) -> Result<T, Asn1Error> {
    //     let mut scope = self.enter()?;
    //     operation(scope.context())
    // }
    //
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
