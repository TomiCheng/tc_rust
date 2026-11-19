use crate::{LiteralData, PacketTag, UnknownPacket};

#[derive(Clone, PartialEq, Eq, Debug)]
#[non_exhaustive]
pub enum Packet {
    LiteralData(LiteralData),
    Unknown(UnknownPacket),
}

impl Packet {
    pub fn tag(&self) -> PacketTag {
        match self {
            Self::LiteralData(_) => PacketTag::LiteralData,
            Self::Unknown(packet) => packet.tag(),
        }
    }

    pub fn is_critical(&self) -> bool {
        self.tag().is_critical()
    }
}

#[cfg(test)]
mod tests {
    use super::Packet;
    use crate::{PacketTag, UnknownPacket};

    #[test]
    fn a_packet_reports_the_tag_and_criticality_of_what_it_holds() {
        let unknown = UnknownPacket::new(PacketTag::Unknown(40), true, vec![1, 2, 3]);
        let packet = Packet::Unknown(unknown);

        assert_eq!(packet.tag(), PacketTag::Unknown(40));
        assert!(!packet.is_critical());
    }
}
