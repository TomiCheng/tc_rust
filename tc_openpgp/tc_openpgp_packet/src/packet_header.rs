use crate::{BodyLength, PacketTag};

#[derive(Clone, Copy, PartialEq, Eq, Hash, Debug)]
pub struct PacketHeader {
    tag: PacketTag,
    new_packet_format: bool,
    body_length: BodyLength,
}

impl PacketHeader {
    pub fn new(tag: PacketTag, new_packet_format: bool, body_length: BodyLength) -> Self {
        Self {
            tag,
            new_packet_format,
            body_length,
        }
    }

    pub fn tag(&self) -> PacketTag {
        self.tag
    }

    pub fn has_new_packet_format(&self) -> bool {
        self.new_packet_format
    }

    pub fn body_length(&self) -> BodyLength {
        self.body_length
    }
}
