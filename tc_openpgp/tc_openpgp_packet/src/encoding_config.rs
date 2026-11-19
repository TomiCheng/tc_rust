/// Options for writing OpenPGP packet encodings.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct EncodingConfig {
    /// Requested packet header format, subject to the packet type's encoding rules.
    pub header_format: PacketHeaderFormat,
}

/// The framing format used for an OpenPGP packet header.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub enum PacketHeaderFormat {
    /// Current OpenPGP packet framing.
    #[default]
    OpenPgp,
    /// Legacy packet framing for packet types that support it.
    Legacy,
}
