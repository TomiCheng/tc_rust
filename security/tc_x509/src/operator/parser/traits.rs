use std::io::Read;

use crate::X509Error;

/// Reads values of `T` from a source, one per call, in one format.
///
/// A parser keeps state between calls, such as the certificates of a PKCS#7 bundle not yet
/// given, so each source takes a parser of its own, given the same source on every call.
pub trait Parser<T> {
    /// The next value; `None` at the end of the input, with no value or no more of them.
    /// Variable time, for public values only.
    fn parse(&mut self, input: &mut dyn Read) -> Result<Option<T>, X509Error>;
}

/// A format of parser, registered by name, that makes a new parser for each source.
pub trait ParserEntry<T>: Send + Sync {
    /// The name the parser is found by, such as `"DER"`.
    fn name(&self) -> &str;

    /// Other names the parser is found by.
    fn aliases(&self) -> &[String] {
        &[]
    }

    /// A new parser, with no state.
    fn create(&self) -> Box<dyn Parser<T>>;
}

/// The parsers of `T` an operator knows, found by name.
pub trait ParserProvider<T> {
    /// A new parser of the format named `name`, the case of the name aside; an error when no
    /// format has the name.
    fn get_by_name(&self, name: &str) -> Result<Box<dyn Parser<T>>, X509Error>;

    /// The names of every format, without their aliases.
    fn names(&self) -> Vec<&str>;
}
