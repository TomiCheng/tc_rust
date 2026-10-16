// Byte encodings of the limbs, as tc_bigint's ArrayEncoding writes them: eight bytes to a
// limb, the top limb taking what is left of `length`.

use crate::BinPolyError;

pub(crate) fn read_le(input: &[u8], limbs: &mut [u64]) -> Result<(), BinPolyError> {
    for (chunk, limb) in input.chunks(8).zip(limbs.iter_mut()) {
        let mut word = [0; 8];
        word[..chunk.len()].copy_from_slice(chunk);
        *limb = u64::from_le_bytes(word);
    }
    check_beyond(input.get(8 * limbs.len()..))
}

pub(crate) fn read_be(input: &[u8], limbs: &mut [u64]) -> Result<(), BinPolyError> {
    for (chunk, limb) in input.rchunks(8).zip(limbs.iter_mut()) {
        let mut word = [0; 8];
        word[8 - chunk.len()..].copy_from_slice(chunk);
        *limb = u64::from_be_bytes(word);
    }
    let beyond = input.len().checked_sub(8 * limbs.len());
    check_beyond(beyond.map(|end| &input[..end]))
}

// Input past the limbs must be zero, as leading zeros a longer input may carry.
fn check_beyond(beyond: Option<&[u8]>) -> Result<(), BinPolyError> {
    match beyond {
        Some(bytes) if bytes.iter().any(|&byte| byte != 0) => Err(BinPolyError::UnreducedValue),
        _ => Ok(()),
    }
}

pub(crate) fn write_le(
    limbs: &[u64],
    length: usize,
    output: &mut [u8],
) -> Result<usize, BinPolyError> {
    let output = output
        .get_mut(..length)
        .ok_or(BinPolyError::BufferTooSmall)?;
    for (chunk, limb) in output.chunks_mut(8).zip(limbs) {
        chunk.copy_from_slice(&limb.to_le_bytes()[..chunk.len()]);
    }
    Ok(length)
}

pub(crate) fn write_be(
    limbs: &[u64],
    length: usize,
    output: &mut [u8],
) -> Result<usize, BinPolyError> {
    let output = output
        .get_mut(..length)
        .ok_or(BinPolyError::BufferTooSmall)?;
    for (chunk, limb) in output.rchunks_mut(8).zip(limbs) {
        let bytes = limb.to_be_bytes();
        chunk.copy_from_slice(&bytes[8 - chunk.len()..]);
    }
    Ok(length)
}
