//! 驗證 IPv4／IPv6 位址字串，對應 BC 的 `Utilities.Net.IPAddress`。
//!
//! 與 BC 不同的一處：BC 的 `GetDigitHexadecimal` 把 `g`／`G`、`:` 到 `?` 與部分控制
//! 字元也當成十六進位數字，這裡只接受 `0-9a-fA-F`。

/// IPv4 或 IPv6 位址。
/// 變動時間：依字元分支，只能用於公開值。
pub fn is_valid(address: &str) -> bool {
    is_valid_ipv4(address) || is_valid_ipv6(address)
}

/// 帶網路遮罩的 IPv4 或 IPv6 位址，例如 `10.0.0.0/8`。
/// 變動時間：依字元分支，只能用於公開值。
pub fn is_valid_with_netmask(address: &str) -> bool {
    is_valid_ipv4_with_netmask(address) || is_valid_ipv6_with_netmask(address)
}

/// 四段十進位的 IPv4 位址；每段 0 到 255，允許前導零。
/// 變動時間：依字元分支，只能用於公開值。
pub fn is_valid_ipv4(address: &str) -> bool {
    ipv4(address.as_bytes())
}

/// IPv4 位址加 `/`，後面是 IPv4 形式的遮罩或 0 到 32 的前綴長度。
/// 變動時間：依字元分支，只能用於公開值。
pub fn is_valid_ipv4_with_netmask(address: &str) -> bool {
    let Some((before, after)) = split_netmask(address.as_bytes()) else {
        return false;
    };
    ipv4(before) && (ipv4(after) || parseable_decimal(after, 2, false, 0, 32))
}

/// IPv6 位址，可用 `::` 省略，最後兩段可寫成 IPv4。
/// 變動時間：依字元分支，只能用於公開值。
pub fn is_valid_ipv6(address: &str) -> bool {
    ipv6(address.as_bytes())
}

/// IPv6 位址加 `/`，後面是 IPv6 形式的遮罩或 1 到 128 的前綴長度。
/// 變動時間：依字元分支，只能用於公開值。
pub fn is_valid_ipv6_with_netmask(address: &str) -> bool {
    let Some((before, after)) = split_netmask(address.as_bytes()) else {
        return false;
    };
    ipv6(before) && (ipv6(after) || parseable_decimal(after, 3, false, 1, 128))
}

/// 在第一個 `/` 切開；`/` 不能是第一個字元。
fn split_netmask(address: &[u8]) -> Option<(&[u8], &[u8])> {
    let index = index_of(address, b'/', 0)?;
    (index >= 1).then(|| (&address[..index], &address[index + 1..]))
}

fn index_of(s: &[u8], c: u8, from: usize) -> Option<usize> {
    s[from..].iter().position(|&b| b == c).map(|i| from + i)
}

fn ipv4(address: &[u8]) -> bool {
    if !(7..=15).contains(&address.len()) {
        return false;
    }
    let mut pos = 0;
    for _ in 0..3 {
        let Some(end) = index_of(address, b'.', pos) else {
            return false;
        };
        if !parseable_decimal(&address[pos..end], 3, true, 0, 255) {
            return false;
        }
        pos = end + 1;
    }
    parseable_decimal(&address[pos..], 3, true, 0, 255)
}

fn ipv6(address: &[u8]) -> bool {
    let Some(&first) = address.first() else {
        return false;
    };
    if first != b':' && digit_hexadecimal(first).is_none() {
        return false;
    }

    // BC 在 `address` 後面補一個 `:` 再切段；這裡把 `address.len()` 當成那個冒號。
    let len = address.len();
    let mut segment_count = 0;
    let mut double_colon_found = false;

    let mut pos = 0;
    while pos <= len {
        let end = index_of(address, b':', pos).unwrap_or(len);
        if segment_count == 8 {
            return false;
        }

        if pos != end {
            let value = &address[pos..end];
            if end == len && index_of(value, b'.', 0).is_some_and(|i| i > 0) {
                // 結尾的 IPv4 佔兩段。
                segment_count += 1;
                if segment_count == 8 {
                    return false;
                }
                if !ipv4(value) {
                    return false;
                }
            } else if !parseable_hexadecimal(value, 4) {
                return false;
            }
        } else {
            if end != 1 && end != len && double_colon_found {
                return false;
            }
            double_colon_found = true;
        }

        pos = end + 1;
        segment_count += 1;
    }

    segment_count == 8 || double_colon_found
}

fn parseable_decimal(
    s: &[u8],
    max_length: usize,
    allow_leading_zero: bool,
    min_value: u32,
    max_value: u32,
) -> bool {
    if s.is_empty() || s.len() > max_length {
        return false;
    }
    if s.len() > 1 && !allow_leading_zero && s[0] == b'0' {
        return false;
    }
    let mut value = 0;
    for &c in s {
        let Some(d) = digit_decimal(c) else {
            return false;
        };
        value = value * 10 + d;
    }
    (min_value..=max_value).contains(&value)
}

/// IPv6 的一段：一到四個十六進位數字，允許前導零。
fn parseable_hexadecimal(s: &[u8], max_length: usize) -> bool {
    !s.is_empty() && s.len() <= max_length && s.iter().all(|&c| digit_hexadecimal(c).is_some())
}

fn digit_decimal(c: u8) -> Option<u32> {
    c.is_ascii_digit().then(|| u32::from(c - b'0'))
}

fn digit_hexadecimal(c: u8) -> Option<u32> {
    char::from(c).to_digit(16)
}
