use crate::{F2mError, F2mFieldElement};
use tc_binpoly_v2::{BinField, PaddedBinPoly};

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct F2mField {
    field: BinField,
}

impl F2mField {
    /// GF(2^m) modulo `x^m + x^k + 1`, `0 < k < m`, for `3 <= m <= 2^20`. The polynomial is
    /// not checked to be irreducible. Variable time; only for public parameters.
    pub fn trinomial(m: u32, k: u32) -> Result<Self, F2mError> {
        let field = BinField::trinomial(m, k).map_err(F2mError::Field)?;
        Ok(Self { field })
    }

    /// GF(2^m) modulo `x^m + x^k3 + x^k2 + x^k1 + 1`, `0 < k1 < k2 < k3 < m`, for
    /// `5 <= m <= 2^20`. The polynomial is not checked to be irreducible. Variable time;
    /// only for public parameters.
    pub fn pentanomial(m: u32, k1: u32, k2: u32, k3: u32) -> Result<Self, F2mError> {
        let field = BinField::pentanomial(m, k1, k2, k3).map_err(F2mError::Field)?;
        Ok(Self { field })
    }

    pub(crate) fn m(&self) -> u32 {
        self.field.n()
    }

    /// From the big-endian octet string of `⌈m / 8⌉` bytes that SEC 1 encodes an element as.
    pub(crate) fn element(&self, bytes: &[u8]) -> Result<F2mFieldElement, F2mError> {
        let expected = (self.m() as usize).div_ceil(8);
        if bytes.len() != expected {
            return Err(F2mError::InvalidLength {
                expected,
                actual: bytes.len(),
            });
        }
        let value = PaddedBinPoly::from_be(self.field, bytes).map_err(|_| F2mError::NotReduced)?;
        Ok(F2mFieldElement::new(value))
    }

    pub(crate) fn zero(&self) -> F2mFieldElement {
        F2mFieldElement::new(PaddedBinPoly::zero(self.field))
    }

    pub(crate) fn one(&self) -> F2mFieldElement {
        F2mFieldElement::new(PaddedBinPoly::one(self.field))
    }
}

#[cfg(test)]
mod tests {
    use super::F2mField;
    use crate::F2mError;
    use tc_binpoly_v2::BinPolyError;

    fn sect163() -> F2mField {
        F2mField::pentanomial(163, 3, 6, 7).unwrap()
    }

    #[test]
    fn the_reduction_polynomial_is_checked_by_tc_binpoly() {
        assert!(F2mField::trinomial(233, 74).is_ok());
        assert_eq!(
            F2mField::trinomial(233, 233),
            Err(F2mError::Field(BinPolyError::InvalidTrinomialTap {
                n: 233,
                k: 233
            }))
        );
        assert!(matches!(
            F2mField::pentanomial(163, 7, 6, 3),
            Err(F2mError::Field(_))
        ));
    }

    #[test]
    fn an_element_is_read_from_ceil_m_over_8_big_endian_bytes() {
        let field = sect163();
        let mut bytes = [0; 21];
        bytes[20] = 1;
        assert_eq!(field.element(&bytes), Ok(field.one()));
        assert_eq!(field.element(&[0; 21]), Ok(field.zero()));

        bytes[0] = 0x07;
        assert!(field.element(&bytes).is_ok());
        bytes[0] = 0x08;
        assert_eq!(field.element(&bytes), Err(F2mError::NotReduced));
        assert_eq!(
            field.element(&[0; 20]),
            Err(F2mError::InvalidLength {
                expected: 21,
                actual: 20
            })
        );
    }
}
