//! Whirlpool message digest, ported from Bouncy Castle's `WhirlpoolDigest`.
//!
//! Whirlpool is a 512-bit hash built from a 512-bit block cipher. Its
//! Miyaguchi–Preneel compression function performs ten rounds using an 8×8-byte
//! state, an S-box, a circulant diffusion matrix, and a 256-bit message-length
//! field.

use core::convert::Infallible;

use tc_digest::TryDigest;

use crate::md_buffer::MdBuffer;

const DIGEST_LENGTH: usize = 64;
const BYTE_LENGTH: usize = 64;
const ROUNDS: usize = 10;

#[rustfmt::skip]
const SBOX: [u8; 256] = [
    0x18, 0x23, 0xc6, 0xe8, 0x87, 0xb8, 0x01, 0x4f, 0x36, 0xa6, 0xd2, 0xf5, 0x79, 0x6f, 0x91, 0x52,
    0x60, 0xbc, 0x9b, 0x8e, 0xa3, 0x0c, 0x7b, 0x35, 0x1d, 0xe0, 0xd7, 0xc2, 0x2e, 0x4b, 0xfe, 0x57,
    0x15, 0x77, 0x37, 0xe5, 0x9f, 0xf0, 0x4a, 0xda, 0x58, 0xc9, 0x29, 0x0a, 0xb1, 0xa0, 0x6b, 0x85,
    0xbd, 0x5d, 0x10, 0xf4, 0xcb, 0x3e, 0x05, 0x67, 0xe4, 0x27, 0x41, 0x8b, 0xa7, 0x7d, 0x95, 0xd8,
    0xfb, 0xee, 0x7c, 0x66, 0xdd, 0x17, 0x47, 0x9e, 0xca, 0x2d, 0xbf, 0x07, 0xad, 0x5a, 0x83, 0x33,
    0x63, 0x02, 0xaa, 0x71, 0xc8, 0x19, 0x49, 0xd9, 0xf2, 0xe3, 0x5b, 0x88, 0x9a, 0x26, 0x32, 0xb0,
    0xe9, 0x0f, 0xd5, 0x80, 0xbe, 0xcd, 0x34, 0x48, 0xff, 0x7a, 0x90, 0x5f, 0x20, 0x68, 0x1a, 0xae,
    0xb4, 0x54, 0x93, 0x22, 0x64, 0xf1, 0x73, 0x12, 0x40, 0x08, 0xc3, 0xec, 0xdb, 0xa1, 0x8d, 0x3d,
    0x97, 0x00, 0xcf, 0x2b, 0x76, 0x82, 0xd6, 0x1b, 0xb5, 0xaf, 0x6a, 0x50, 0x45, 0xf3, 0x30, 0xef,
    0x3f, 0x55, 0xa2, 0xea, 0x65, 0xba, 0x2f, 0xc0, 0xde, 0x1c, 0xfd, 0x4d, 0x92, 0x75, 0x06, 0x8a,
    0xb2, 0xe6, 0x0e, 0x1f, 0x62, 0xd4, 0xa8, 0x96, 0xf9, 0xc5, 0x25, 0x59, 0x84, 0x72, 0x39, 0x4c,
    0x5e, 0x78, 0x38, 0x8c, 0xd1, 0xa5, 0xe2, 0x61, 0xb3, 0x21, 0x9c, 0x1e, 0x43, 0xc7, 0xfc, 0x04,
    0x51, 0x99, 0x6d, 0x0d, 0xfa, 0xdf, 0x7e, 0x24, 0x3b, 0xab, 0xce, 0x11, 0x8f, 0x4e, 0xb7, 0xeb,
    0x3c, 0x81, 0x94, 0xf7, 0xb9, 0x13, 0x2c, 0xd3, 0xe7, 0x6e, 0xc4, 0x03, 0x56, 0x44, 0x7f, 0xa9,
    0x2a, 0xbb, 0xc1, 0x53, 0xdc, 0x0b, 0x9d, 0x6c, 0x31, 0x74, 0xf6, 0x46, 0xac, 0x89, 0x14, 0xe1,
    0x16, 0x3a, 0x69, 0x09, 0x70, 0xb6, 0xd0, 0xed, 0xcc, 0x42, 0x98, 0xa4, 0x28, 0x5c, 0xf8, 0x86,
];

// BC 的十個 round constants;每個由連續八個 S-box 值組成。
const RC: [u64; ROUNDS + 1] = [
    0,
    0x1823_c6e8_87b8_014f,
    0x36a6_d2f5_796f_9152,
    0x60bc_9b8e_a30c_7b35,
    0x1de0_d7c2_2e4b_fe57,
    0x1577_37e5_9ff0_4ada,
    0x58c9_290a_b1a0_6b85,
    0xbd5d_10f4_cb3e_0567,
    0xe427_418b_a77d_95d8,
    0xfbee_7c66_dd17_479e,
    0xca2d_bf07_ad5a_8333,
];

const fn mul_x(input: u8) -> u8 {
    let reduction = if input & 0x80 != 0 { 0x011d } else { 0 };
    (((input as u16) << 1) ^ reduction) as u8
}

/// 由 Whirlpool S-box 與 diffusion row `[1,1,4,1,8,5,2,9]` 產生 C0。
/// C1..C7 分別是 C0 右旋 8..56 bits。
const fn generate_c0() -> [u64; 256] {
    let mut table = [0u64; 256];
    let mut i = 0;
    while i < 256 {
        let v1 = SBOX[i];
        let v2 = mul_x(v1);
        let v4 = mul_x(v2);
        let v5 = v4 ^ v1;
        let v8 = mul_x(v4);
        let v9 = v8 ^ v1;
        table[i] = ((v1 as u64) << 56)
            ^ ((v1 as u64) << 48)
            ^ ((v4 as u64) << 40)
            ^ ((v1 as u64) << 32)
            ^ ((v8 as u64) << 24)
            ^ ((v5 as u64) << 16)
            ^ ((v2 as u64) << 8)
            ^ (v9 as u64);
        i += 1;
    }
    table
}

static C0: [u64; 256] = generate_c0();

/// Whirlpool 的 SubBytes + ShiftColumns + MixRows 查表轉換。
fn transform(input: &[u64; 8]) -> [u64; 8] {
    let mut output = [0u64; 8];
    for (i, word) in output.iter_mut().enumerate() {
        let mut value = 0;
        for table in 0..8 {
            let source = input[(i + 8 - table) & 7];
            let shift = (56 - table * 8) as u32;
            let index = ((source >> shift) & 0xff) as usize;
            value ^= C0[index].rotate_right((table * 8) as u32);
        }
        *word = value;
    }
    output
}

/// 壓縮一個 512-bit block (Whirlpool cipher + Miyaguchi–Preneel feed-forward)。
fn compress(hash: &mut [u64; 8], block: &[u8; 64]) {
    let mut message = [0u64; 8];
    for (word, bytes) in message.iter_mut().zip(block.chunks_exact(8)) {
        *word = u64::from_be_bytes(bytes.try_into().expect("8-byte Whirlpool word"));
    }

    let mut key = *hash;
    let mut state = core::array::from_fn(|i| message[i] ^ key[i]);

    for &round_constant in &RC[1..=ROUNDS] {
        key = transform(&key);
        key[0] ^= round_constant;

        let transformed = transform(&state);
        for i in 0..8 {
            state[i] = transformed[i] ^ key[i];
        }
    }

    for i in 0..8 {
        hash[i] ^= state[i] ^ message[i];
    }
}

/// Adds `byte_length * 8` to a 256-bit big-endian bit counter.
fn increment_bit_count(bit_count: &mut [u8; 32], byte_length: usize) {
    let mut addend = (byte_length as u128) << 3;
    let mut i = bit_count.len();
    while addend != 0 && i != 0 {
        i -= 1;
        let sum = bit_count[i] as u128 + (addend & 0xff);
        bit_count[i] = sum as u8;
        addend = (addend >> 8) + (sum >> 8);
    }
}

/// The 512-bit Whirlpool message digest.
#[derive(Clone)]
pub struct WhirlpoolDigest {
    hash: [u64; 8],
    buf: MdBuffer<64>,
    /// 訊息位元長度，對齊 Whirlpool 規格與 BC 的 256-bit counter。
    bit_count: [u8; 32],
}

impl Default for WhirlpoolDigest {
    fn default() -> Self {
        WhirlpoolDigest {
            hash: [0; 8],
            buf: MdBuffer::new(),
            bit_count: [0; 32],
        }
    }
}

impl WhirlpoolDigest {
    /// Creates a fresh Whirlpool digest.
    pub fn new() -> Self {
        Self::default()
    }
}

impl TryDigest for WhirlpoolDigest {
    type Error = Infallible;

    fn algorithm_name(&self) -> &str {
        "Whirlpool"
    }

    fn digest_size(&self) -> usize {
        DIGEST_LENGTH
    }

    fn byte_length(&self) -> usize {
        BYTE_LENGTH
    }

    fn try_update(&mut self, input: &[u8]) -> Result<(), Self::Error> {
        increment_bit_count(&mut self.bit_count, input.len());
        let Self { hash, buf, .. } = self;
        buf.update(input, |block| compress(hash, block));
        Ok(())
    }

    fn try_do_final(&mut self, output: &mut [u8]) -> Result<usize, Self::Error> {
        {
            let Self {
                hash,
                buf,
                bit_count,
            } = self;
            buf.finish(bit_count, |block| compress(hash, block));
            for (i, word) in hash.iter().enumerate() {
                output[i * 8..i * 8 + 8].copy_from_slice(&word.to_be_bytes());
            }
        }
        self.try_reset()?;
        Ok(DIGEST_LENGTH)
    }

    fn try_reset(&mut self) -> Result<(), Self::Error> {
        self.hash = [0; 8];
        self.buf.reset();
        self.bit_count = [0; 32];
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use alloc::{format, string::String, vec, vec::Vec};

    use super::*;
    use tc_digest::Digest;

    fn whirlpool_hex(input: &[u8]) -> String {
        let mut digest = WhirlpoolDigest::new();
        digest.update(input);
        let mut output = [0u8; DIGEST_LENGTH];
        digest.do_final(&mut output);

        let mut encoded = String::with_capacity(DIGEST_LENGTH * 2);
        for byte in output {
            encoded.push_str(&format!("{byte:02x}"));
        }
        encoded
    }

    /// ISO/IEC 10118-3 vectors used by Bouncy Castle's `WhirlpoolDigestTest`.
    #[test]
    fn known_vectors() {
        let vectors: &[(&[u8], &str)] = &[
            (
                b"",
                "19fa61d75522a4669b44e39c1d2e1726c530232130d407f89afee0964997f7a7\
                 3e83be698b288febcf88e3e03c4f0757ea8964e59b63d93708b138cc42a66eb3",
            ),
            (
                b"a",
                "8aca2602792aec6f11a67206531fb7d7f0dff59413145e6973c45001d0087b42\
                 d11bc645413aeff63a42391a39145a591a92200d560195e53b478584fdae231a",
            ),
            (
                b"abc",
                "4e2448a4c6f486bb16b6562c73b4020bf3043e3a731bce721ae1b303d97e6d4c\
                 7181eebdb6c57e277d0e34957114cbd6c797fc9d95d8b582d225292076d4eef5",
            ),
            (
                b"message digest",
                "378c84a4126e2dc6e56dcc7458377aac838d00032230f53ce1f5700c0ffb4d3b\
                 8421557659ef55c106b4b52ac5a4aaa692ed920052838f3362e86dbd37a8903e",
            ),
            (
                b"abcdefghijklmnopqrstuvwxyz",
                "f1d754662636ffe92c82ebb9212a484a8d38631ead4238f5442ee13b8054e41b\
                 08bf2a9251c30b6a0b8aae86177ab4a6f68f673e7207865d5d9819a3dba4eb3b",
            ),
            (
                b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789",
                "dc37e008cf9ee69bf11f00ed9aba26901dd7c28cdec066cc6af42e40f82f3a1e\
                 08eba26629129d8fb7cb57211b9281a65517cc879d7b962142c65f5a7af01467",
            ),
            (
                b"12345678901234567890123456789012345678901234567890123456789012345678901234567890",
                "466ef18babb0154d25b9d38a6414f5c08784372bccb204d6549c4afadb601429\
                 4d5bd8df2a6c44e538cd047b2681a51a2c60481e88c5a20b2c2a80cf3a9a083b",
            ),
            (
                b"abcdbcdecdefdefgefghfghighijhijk",
                "2a987ea40f917061f5d6f0a0e4644f488a7a5a52deee656207c562f988e95c69\
                 16bdc8031bc5be1b7b947639fe050b56939baaa0adff9ae6745b7b181c3be3fd",
            ),
        ];

        for &(message, expected) in vectors {
            assert_eq!(whirlpool_hex(message), expected);
        }
    }

    #[test]
    fn padding_boundary_and_million_a_vectors() {
        assert_eq!(
            whirlpool_hex(&[0; 31]),
            "3e3f188f8febbeb17a933feaf7fe53a4858d80c915ad6a1418f0318e68d49b4e\
             459223cd414e0fbc8a57578fd755d86e827abef4070fc1503e25d99e382f72ba"
        );

        let million_a = vec![b'a'; 1_000_000];
        assert_eq!(
            whirlpool_hex(&million_a),
            "0c99005beb57eff50a7cf005560ddf5d29057fd86b20bfd62deca0f1ccea4af51\
             fc15490eddc47af32bb2b66c34ff9ad8c6008ad677f77126953b226e4ed8b01"
        );
    }

    #[test]
    fn accessors_clone_chunking_and_reset() {
        let message: Vec<u8> = (0..200).map(|i| i as u8).collect();
        let mut whole = WhirlpoolDigest::new();
        assert_eq!(whole.algorithm_name(), "Whirlpool");
        assert_eq!(whole.digest_size(), 64);
        assert_eq!(whole.byte_length(), 64);
        whole.update(&message);

        let mut cloned = whole.clone();
        let mut expected = [0u8; DIGEST_LENGTH];
        let mut cloned_output = [0u8; DIGEST_LENGTH];
        whole.do_final(&mut expected);
        cloned.do_final(&mut cloned_output);
        assert_eq!(cloned_output, expected);

        let mut chunked = WhirlpoolDigest::new();
        chunked.update(&message[..31]);
        chunked.update(&message[31..64]);
        chunked.update(&message[64..]);
        let mut actual = [0u8; DIGEST_LENGTH];
        chunked.do_final(&mut actual);
        assert_eq!(actual, expected);

        chunked.do_final(&mut actual);
        assert_eq!(
            actual,
            hex_to_array(
                "19fa61d75522a4669b44e39c1d2e1726c530232130d407f89afee0964997f7a7\
             3e83be698b288febcf88e3e03c4f0757ea8964e59b63d93708b138cc42a66eb3"
            )
        );
    }

    #[test]
    fn bit_counter_carries_across_bytes() {
        let mut count = [0u8; 32];
        count[30] = 0xff;
        count[31] = 0xf8;
        increment_bit_count(&mut count, 1);
        assert_eq!(count[29], 1);
        assert_eq!(count[30], 0);
        assert_eq!(count[31], 0);
    }

    fn hex_to_array(input: &str) -> [u8; DIGEST_LENGTH] {
        let mut output = [0u8; DIGEST_LENGTH];
        for (i, byte) in output.iter_mut().enumerate() {
            *byte = u8::from_str_radix(&input[i * 2..i * 2 + 2], 16).unwrap();
        }
        output
    }
}
