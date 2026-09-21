//! Field readers `tc_asn1::Children` does not have yet, as an extension
//! trait. Each is a candidate for the next tc_asn1 release; when it lands
//! there, the method here goes and the `use` at the call sites with it.

use tc_asn1::{Asn1Error, Children, DecodeInner};

pub(crate) trait ChildrenExt {
    /// A `[n] EXPLICIT T` field that must be present: `Truncated` when
    /// nothing is left, `UnexpectedTag` when the next element is not
    /// `tag`. The wrapper must hold exactly one element.
    fn get_explicit<T: DecodeInner>(&mut self, tag: &[u8]) -> Result<T, Asn1Error>;
}

impl ChildrenExt for Children<'_, '_> {
    fn get_explicit<T: DecodeInner>(&mut self, tag: &[u8]) -> Result<T, Asn1Error> {
        let wrapper = self.next().ok_or(Asn1Error::Truncated)??.assert_tag(tag)?;
        let mut inner = wrapper.children(self.context())?;
        let value = inner.get::<T>()?;
        inner.end()?;
        Ok(value)
    }
}

#[cfg(test)]
mod tests {
    use tc_asn1::{Asn1Error, Asn1Integer, Asn1Ref, DecodingContext, DecodingOptions};

    use super::ChildrenExt;

    fn fresh() -> DecodingContext {
        DecodingContext::new(DecodingOptions::default())
    }

    #[test]
    fn get_explicit_unwraps_exactly_one_element() {
        // SEQUENCE { [0] EXPLICIT INTEGER 5 }
        let wire = [0x30, 0x05, 0xA0, 0x03, 0x02, 0x01, 0x05];
        let mut context = fresh();
        let element = Asn1Ref::parse(&wire, &mut context).unwrap();
        let mut fields = element.children(&mut context).unwrap();
        assert_eq!(
            fields.get_explicit::<Asn1Integer>(&[0xA0]).unwrap(),
            Asn1Integer::from(5)
        );
        fields.end().unwrap();
    }

    #[test]
    fn a_missing_or_mistagged_field_and_a_crowded_wrapper_are_errors() {
        for (wire, error) in [
            (&[0x30, 0x00][..], Asn1Error::Truncated),
            (
                &[0x30, 0x05, 0xA1, 0x03, 0x02, 0x01, 0x05],
                Asn1Error::UnexpectedTag,
            ),
            (
                &[0x30, 0x08, 0xA0, 0x06, 0x02, 0x01, 0x05, 0x02, 0x01, 0x06],
                Asn1Error::TrailingData,
            ),
        ] {
            let mut context = fresh();
            let element = Asn1Ref::parse(wire, &mut context).unwrap();
            let mut fields = element.children(&mut context).unwrap();
            assert_eq!(
                fields.get_explicit::<Asn1Integer>(&[0xA0]).unwrap_err(),
                error,
                "{wire:02X?}"
            );
        }
    }
}
