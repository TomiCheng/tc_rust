use std::io;
use tc_algo::{Algo, params::kdf::HkdfParamsOwned};
use tc_zeroize::Zeroizing;

pub(super) fn hkdf(
    algo: &dyn Algo,
    ikm: &[u8],
    salt: &[u8],
    info: &[u8],
    length: usize,
) -> io::Result<Zeroizing<Vec<u8>>> {
    let mut kdf = algo
        .kdf()
        .get_by_name("HKDF-SHA256")
        .map_err(io::Error::other)?;
    kdf.init(&HkdfParamsOwned::new(
        ikm.to_vec(),
        salt.to_vec(),
        info.to_vec(),
    ))
    .map_err(io::Error::other)?;
    let mut output = Zeroizing::new(vec![0; length]);
    if kdf.generate_bytes(&mut output).map_err(io::Error::other)? != length {
        return Err(io::Error::other("HKDF returned an invalid output length"));
    }
    Ok(output)
}
