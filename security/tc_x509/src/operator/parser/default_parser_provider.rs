use super::{Parser, ParserEntry, ParserProvider};
use crate::X509Error;

// The parsers of T an operator was built with, the last registered first so that it takes over
// a built-in one of the same name
pub(crate) struct DefaultParserProvider<T> {
    rows: Vec<Box<dyn ParserEntry<T>>>,
}

impl<T> DefaultParserProvider<T> {
    pub(crate) fn new(rows: Vec<Box<dyn ParserEntry<T>>>) -> Self {
        Self { rows }
    }
}

impl<T> ParserProvider<T> for DefaultParserProvider<T> {
    fn get_by_name(&self, name: &str) -> Result<Box<dyn Parser<T>>, X509Error> {
        self.rows
            .iter()
            .find(|row| {
                row.name().eq_ignore_ascii_case(name)
                    || row
                        .aliases()
                        .iter()
                        .any(|alias| alias.eq_ignore_ascii_case(name))
            })
            .map(|row| row.create())
            .ok_or(X509Error::UnknownParser)
    }

    fn names(&self) -> Vec<&str> {
        let mut names: Vec<&str> = Vec::new();
        for row in &self.rows {
            if !names.iter().any(|name| name.eq_ignore_ascii_case(row.name())) {
                names.push(row.name());
            }
        }
        names
    }
}
