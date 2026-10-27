use alloc::string::String;

// bcrypt 自己的字母表，不補位；64 位元組在同一條 cache line 內
const ALPHABET: &[u8; 64] = b"./ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789";

/// 附加 ceil(8n/6) 個字元，缺的位元補 0。
pub(super) fn encode(data: &[u8], out: &mut String) {
    let mut remaining = (data.len() * 8).div_ceil(6);
    for chunk in data.chunks(3) {
        let a = chunk[0];
        let b = chunk.get(1).copied().unwrap_or(0);
        let c = chunk.get(2).copied().unwrap_or(0);
        let sextets = [
            a >> 2,
            (a << 4 | b >> 4) & 0x3f,
            (b << 2 | c >> 6) & 0x3f,
            c & 0x3f,
        ];
        for sextet in sextets.into_iter().take(remaining) {
            out.push(char::from(ALPHABET[usize::from(sextet)]));
        }
        remaining = remaining.saturating_sub(4);
    }
}

/// 22 個字元解回 16 位元組的 salt；有字母表外的字元就是 `None`。
pub(super) fn decode_salt(text: &[u8]) -> Option<[u8; 16]> {
    let mut sextets = [0; 24];
    for (sextet, &c) in sextets.iter_mut().zip(text) {
        *sextet = match c {
            b'.' => 0,
            b'/' => 1,
            b'A'..=b'Z' => c - b'A' + 2,
            b'a'..=b'z' => c - b'a' + 28,
            b'0'..=b'9' => c - b'0' + 54,
            _ => return None,
        };
    }
    let mut bytes = [0; 18];
    for (out, s) in bytes.chunks_exact_mut(3).zip(sextets.chunks_exact(4)) {
        out[0] = s[0] << 2 | s[1] >> 4;
        out[1] = s[1] << 4 | s[2] >> 2;
        out[2] = s[2] << 6 | s[3];
    }
    let mut salt = [0; 16];
    salt.copy_from_slice(&bytes[..16]);
    Some(salt)
}
