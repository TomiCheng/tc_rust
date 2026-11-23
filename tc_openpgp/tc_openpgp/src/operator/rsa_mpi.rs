use std::io::{self, Read};

pub(super) fn write_mpi(out: &mut Vec<u8>, value: &[u8]) -> io::Result<()> {
    let bits = u16::try_from(bit_len(value)).map_err(|_| {
        io::Error::new(
            io::ErrorKind::InvalidInput,
            "RSA MPI exceeds its bit length field",
        )
    })?;
    out.extend_from_slice(&bits.to_be_bytes());
    out.extend_from_slice(value);
    Ok(())
}

pub(super) fn read_mpi<'a>(input: &mut &'a [u8]) -> io::Result<&'a [u8]> {
    let mut encoded_bits = [0; 2];
    input.read_exact(&mut encoded_bits)?;
    let bits = usize::from(u16::from_be_bytes(encoded_bits));
    let (value, remaining) = input
        .split_at_checked(bits.div_ceil(8))
        .ok_or_else(|| io::Error::new(io::ErrorKind::UnexpectedEof, "truncated RSA MPI"))?;
    if bit_len(value) != bits {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "noncanonical RSA MPI",
        ));
    }
    *input = remaining;
    Ok(value)
}

fn bit_len(value: &[u8]) -> usize {
    value
        .first()
        .map_or(0, |first| value.len() * 8 - first.leading_zeros() as usize)
}
