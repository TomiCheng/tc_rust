use crate::{PacketTag, UnknownPacket};

#[derive(Clone, PartialEq, Eq, Debug)]
#[non_exhaustive]
pub enum Packet {
    Unknown(UnknownPacket),
}

impl Packet {
    pub fn tag(&self) -> PacketTag {
        match self {
            Self::Unknown(packet) => packet.tag(),
        }
    }

    pub fn has_new_packet_format(&self) -> bool {
        match self {
            Self::Unknown(packet) => packet.has_new_packet_format(),
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
    fn a_packet_reports_the_tag_and_format_of_what_it_holds() {
        let unknown = UnknownPacket::new(PacketTag::Unknown(40), true, vec![1, 2, 3]);
        let packet = Packet::Unknown(unknown);

        assert_eq!(packet.tag(), PacketTag::Unknown(40));
        assert!(packet.has_new_packet_format());
        assert!(!packet.is_critical());
    }
}
