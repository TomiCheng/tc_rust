use crate::PacketTag;

#[derive(Clone, PartialEq, Eq, Debug)]
pub struct UnknownPacket {
    tag: PacketTag,
    new_packet_format: bool,
    contents: Vec<u8>,
}

impl UnknownPacket {
    pub fn new(tag: PacketTag, new_packet_format: bool, contents: Vec<u8>) -> Self {
        Self {
            tag,
            new_packet_format,
            contents,
        }
    }

    pub fn tag(&self) -> PacketTag {
        self.tag
    }

    pub fn has_new_packet_format(&self) -> bool {
        self.new_packet_format
    }

    pub fn contents(&self) -> &[u8] {
        &self.contents
    }
}
