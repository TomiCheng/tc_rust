use std::io::{self, Read, Write};

use tc_asn1::DecodingOptions;
use tc_asn1::io::Asn1Body;

use crate::CmsError;

// 串流讀取時內容不設上限：它不會留在記憶體裡
pub(crate) fn options() -> DecodingOptions {
    let default = DecodingOptions::default();
    DecodingOptions::new(default.depth(), usize::MAX, default.max_children())
}

pub(crate) fn required<T>(value: io::Result<Option<T>>) -> Result<T, CmsError> {
    value
        .map_err(CmsError::Io)?
        .ok_or(CmsError::UnexpectedContentType)
}

// OCTET STRING 的內容依序寫到 sink：單一段、BER 分段，或分段裡再分段
pub(crate) fn copy_octets<R: Read>(
    body: &mut Asn1Body<'_, R>,
    sink: &mut dyn Write,
) -> Result<(), CmsError> {
    while let Some(tag) = body.read_header().map_err(CmsError::Io)? {
        body.read_len().map_err(CmsError::Io)?;
        let mut inner = body.read_body().map_err(CmsError::Io)?;
        match tag.as_bytes() {
            [0x04] => {
                io::copy(&mut inner, sink).map_err(CmsError::Io)?;
            }
            [0x24] => copy_octets(&mut inner, sink)?,
            _ => return Err(tc_asn1::Asn1Error::UnexpectedTag.into()),
        }
    }
    Ok(())
}
