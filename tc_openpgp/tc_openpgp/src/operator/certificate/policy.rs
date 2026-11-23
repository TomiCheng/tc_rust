use tc_openpgp_packet::SignaturePacket;

#[cfg(feature = "cfrg-curves")]
use std::io;

/// One verified key signature and the authenticated fields used for selection.
pub(super) struct KeySignature {
    pub(super) packet: SignaturePacket,
    created: u32,
    signature_lifetime: u32,
    key_lifetime: u32,
    key_flags: u8,
    revocation_reason: Option<u8>,
}

impl KeySignature {
    #[cfg(feature = "cfrg-curves")]
    pub(super) fn new(packet: SignaturePacket) -> io::Result<Self> {
        use crate::operator::signature_subpacket::Subpackets;

        let mut created = None;
        let mut signature_lifetime = None;
        let mut key_lifetime = None;
        let mut key_flags = None;
        let mut revocation_reason = None;
        for item in Subpackets::new(packet.hashed_subpackets()) {
            let (tag, value) = item?;
            match tag & 0x7f {
                2 => set_field(&mut created, seconds(value)?)?,
                3 => set_field(&mut signature_lifetime, seconds(value)?)?,
                9 => set_field(&mut key_lifetime, seconds(value)?)?,
                27 => {
                    let flag = *value.first().ok_or_else(invalid_policy)?;
                    set_field(&mut key_flags, flag)?;
                }
                29 => {
                    let (&reason, text) = value.split_first().ok_or_else(invalid_policy)?;
                    std::str::from_utf8(text).map_err(|_| invalid_policy())?;
                    set_field(&mut revocation_reason, reason)?;
                }
                _ => {}
            }
        }
        Ok(Self {
            packet,
            created: created.ok_or_else(invalid_policy)?,
            signature_lifetime: signature_lifetime.unwrap_or_default(),
            key_lifetime: key_lifetime.unwrap_or_default(),
            key_flags: key_flags.unwrap_or_default(),
            revocation_reason,
        })
    }

    pub(super) fn created(&self) -> u32 {
        self.created
    }

    pub(super) fn allows(&self, flag: u8) -> bool {
        self.key_flags & flag != 0
    }

    pub(super) fn key_is_current(&self, created: u32, at: u32) -> bool {
        alive(created, self.key_lifetime, at)
    }

    pub(super) fn revokes_at(&self, at: u32) -> bool {
        // Compromise, unspecified reasons, and unknown codes are treated as
        // retroactive. Superseded and retired keys are unusable from revocation onward.
        !matches!(self.revocation_reason, Some(1 | 3)) || at >= self.created
    }
}

pub(super) fn latest(signatures: &[KeySignature]) -> Option<&KeySignature> {
    signatures.iter().max_by_key(|signature| signature.created)
}

pub(super) fn current(
    signatures: &[KeySignature],
    key_created: u32,
    at: u32,
) -> Option<&KeySignature> {
    signatures
        .iter()
        .filter(|signature| {
            signature.created >= key_created
                && alive(signature.created, signature.signature_lifetime, at)
        })
        .max_by_key(|signature| signature.created)
        .filter(|signature| signature.key_is_current(key_created, at))
}

fn alive(created: u32, lifetime: u32, at: u32) -> bool {
    at >= created && (lifetime == 0 || at - created < lifetime)
}

#[cfg(feature = "cfrg-curves")]
fn set_field<T>(field: &mut Option<T>, value: T) -> io::Result<()> {
    if field.replace(value).is_some() {
        return Err(invalid_policy());
    }
    Ok(())
}

#[cfg(feature = "cfrg-curves")]
fn seconds(value: &[u8]) -> io::Result<u32> {
    Ok(u32::from_be_bytes(
        value.try_into().map_err(|_| invalid_policy())?,
    ))
}

#[cfg(feature = "cfrg-curves")]
fn invalid_policy() -> io::Error {
    io::Error::new(
        io::ErrorKind::InvalidData,
        "malformed or duplicate hashed key signature field",
    )
}
