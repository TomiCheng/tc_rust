//! Field readers `tc_asn1::Children` does not have yet, as an extension
//! trait: with these, every combination of EXPLICIT/IMPLICIT and
//! required/OPTIONAL/DEFAULT has a reader. Each is a candidate for the next
//! tc_asn1 release; when it lands there, the method here goes and the
//! `use` at the call sites with it.

use tc_asn1::{Asn1Error, Children, DecodeContent, DecodeInner};

#[allow(dead_code)] // the implicit readers wait for the fields that need them
pub(crate) trait ChildrenExt {
    /// A `[n] EXPLICIT T` field that must be present: `Truncated` when
    /// nothing is left, `UnexpectedTag` when the next element is not
    /// `tag`. The wrapper must hold exactly one element.
    fn get_explicit<T: DecodeInner>(&mut self, tag: &[u8]) -> Result<T, Asn1Error>;

    /// A `[n] IMPLICIT T` field that must be present: `Truncated` when
    /// nothing is left, `UnexpectedTag` when the next element is not
    /// `tag`; the contents are decoded as `T`.
    fn get_implicit<T: DecodeContent>(&mut self, tag: &[u8]) -> Result<T, Asn1Error>;

    /// A `[n] IMPLICIT T DEFAULT v` field: the value when the next element
    /// carries `tag`, `default` otherwise. Under DER a written value equal
    /// to the default is `NotDer` (X.690 §11.5).
    fn get_implicit_default<T: DecodeContent + PartialEq>(
        &mut self,
        tag: &[u8],
        default: T,
    ) -> Result<T, Asn1Error>;
}

impl ChildrenExt for Children<'_, '_> {
    fn get_explicit<T: DecodeInner>(&mut self, tag: &[u8]) -> Result<T, Asn1Error> {
        let wrapper = self.next().ok_or(Asn1Error::Truncated)??.assert_tag(tag)?;
        let mut inner = wrapper.children(self.context())?;
        let value = inner.get::<T>()?;
        inner.end()?;
        Ok(value)
    }

    fn get_implicit<T: DecodeContent>(&mut self, tag: &[u8]) -> Result<T, Asn1Error> {
        let element = self.next().ok_or(Asn1Error::Truncated)??.assert_tag(tag)?;
        T::decode_content(element.value(), self.context())
    }

    fn get_implicit_default<T: DecodeContent + PartialEq>(
        &mut self,
        tag: &[u8],
        default: T,
    ) -> Result<T, Asn1Error> {
        match self.get_implicit_opt::<T>(tag)? {
            Some(value) if value == default && self.context().is_der() => Err(Asn1Error::NotDer),
            Some(value) => Ok(value),
            None => Ok(default),
        }
    }
}

#[cfg(test)]
mod tests {
    use tc_asn1::{
        Asn1Error, Asn1Integer, Asn1OctetString, Asn1Ref, DecodingContext, DecodingOptions,
    };

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

    #[test]
    fn get_implicit_reads_the_contents_under_the_context_tag() {
        // SEQUENCE { [1] IMPLICIT OCTET STRING AA }
        let wire = [0x30, 0x03, 0x81, 0x01, 0xAA];
        let mut context = fresh();
        let element = Asn1Ref::parse(&wire, &mut context).unwrap();
        let mut fields = element.children(&mut context).unwrap();
        assert_eq!(
            fields.get_implicit::<Asn1OctetString>(&[0x81]).unwrap(),
            Asn1OctetString::new(&[0xAA])
        );
        fields.end().unwrap();

        let mut context = fresh();
        let element = Asn1Ref::parse(&wire, &mut context).unwrap();
        let mut fields = element.children(&mut context).unwrap();
        assert_eq!(
            fields.get_implicit::<Asn1OctetString>(&[0x82]).unwrap_err(),
            Asn1Error::UnexpectedTag
        );
    }

    #[test]
    fn get_implicit_default_supplies_the_default_and_rejects_it_written_under_der() {
        let absent = [0x30, 0x00];
        let written = [0x30, 0x03, 0x80, 0x01, 0x00]; // [0] IMPLICIT INTEGER 0
        let other = [0x30, 0x03, 0x80, 0x01, 0x07];
        let zero = Asn1Integer::from(0);

        let mut context = fresh();
        let element = Asn1Ref::parse(&absent, &mut context).unwrap();
        let mut fields = element.children(&mut context).unwrap();
        assert_eq!(
            fields.get_implicit_default(&[0x80], zero.clone()).unwrap(),
            zero
        );

        let mut context = fresh();
        let element = Asn1Ref::parse(&written, &mut context).unwrap();
        let mut fields = element.children(&mut context).unwrap();
        assert_eq!(
            fields.get_implicit_default(&[0x80], zero.clone()).unwrap(),
            zero
        );

        let mut context = DecodingContext::new_der(DecodingOptions::default());
        let element = Asn1Ref::parse(&written, &mut context).unwrap();
        let mut fields = element.children(&mut context).unwrap();
        assert_eq!(
            fields
                .get_implicit_default(&[0x80], zero.clone())
                .unwrap_err(),
            Asn1Error::NotDer
        );

        let mut context = DecodingContext::new_der(DecodingOptions::default());
        let element = Asn1Ref::parse(&other, &mut context).unwrap();
        let mut fields = element.children(&mut context).unwrap();
        assert_eq!(
            fields.get_implicit_default(&[0x80], zero).unwrap(),
            Asn1Integer::from(7)
        );
    }
}
