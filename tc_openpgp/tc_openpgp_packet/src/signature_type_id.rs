/// OpenPGP signature type identifier.
///
/// The value is the one-octet Signature Type ID in a Signature packet. Known
/// values are defined in [RFC 9580, Section 5.2.1][rfc9580-signature-types].
/// This open type also preserves IDs not yet named here.
///
/// [rfc9580-signature-types]: https://www.rfc-editor.org/rfc/rfc9580.html#section-5.2.1
#[derive(Clone, Copy, PartialEq, Eq, Hash, Debug)]
#[repr(transparent)]
pub struct SignatureTypeId(u8);

impl SignatureTypeId {
    /// Binary document signature (0x00).
    pub const BINARY_DOCUMENT: Self = Self(0x00);
    /// Canonical text document signature (0x01).
    pub const CANONICAL_TEXT_DOCUMENT: Self = Self(0x01);
    /// Standalone signature (0x02).
    pub const STANDALONE: Self = Self(0x02);

    /// Generic certification of a User ID and public key (0x10).
    pub const DEFAULT_CERTIFICATION: Self = Self(0x10);
    /// Persona certification (0x11); named `NoCertification` by Bouncy Castle.
    pub const PERSONA_CERTIFICATION: Self = Self(0x11);
    /// Bouncy Castle-compatible name for persona certification (0x11).
    pub const NO_CERTIFICATION: Self = Self::PERSONA_CERTIFICATION;
    /// Casual certification of a User ID and public key (0x12).
    pub const CASUAL_CERTIFICATION: Self = Self(0x12);
    /// Positive certification of a User ID and public key (0x13).
    pub const POSITIVE_CERTIFICATION: Self = Self(0x13);

    /// Subkey binding signature (0x18).
    pub const SUBKEY_BINDING: Self = Self(0x18);
    /// Primary-key binding signature (0x19).
    pub const PRIMARY_KEY_BINDING: Self = Self(0x19);
    /// Direct-key signature (0x1F).
    pub const DIRECT_KEY: Self = Self(0x1F);
    /// Key revocation signature (0x20).
    pub const KEY_REVOCATION: Self = Self(0x20);
    /// Subkey revocation signature (0x28).
    pub const SUBKEY_REVOCATION: Self = Self(0x28);
    /// Certification revocation signature (0x30).
    pub const CERTIFICATION_REVOCATION: Self = Self(0x30);
    /// Timestamp signature (0x40).
    pub const TIMESTAMP: Self = Self(0x40);
    /// Third-party confirmation signature (0x50).
    pub const THIRD_PARTY_CONFIRMATION: Self = Self(0x50);

    /// Creates a signature type from its wire ID.
    pub const fn new(id: u8) -> Self {
        Self(id)
    }

    /// Returns the one-octet wire ID.
    pub const fn id(self) -> u8 {
        self.0
    }
}

impl From<u8> for SignatureTypeId {
    fn from(id: u8) -> Self {
        Self(id)
    }
}

impl From<SignatureTypeId> for u8 {
    fn from(signature_type: SignatureTypeId) -> Self {
        signature_type.id()
    }
}