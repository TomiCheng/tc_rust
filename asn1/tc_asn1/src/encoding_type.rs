#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum LengthForm {
    Definite,
    Indefinite,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum EncodingType {
    Ber(LengthForm),
    Cer,
    Der,
}

impl EncodingType {
    pub const fn is_canonical(self) -> bool {
        matches!(self, Self::Cer | Self::Der)
    }
}
