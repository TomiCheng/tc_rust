//! ESCH-256 and ESCH-384, ported from Bouncy Castle's `SparkleDigest`.
//!
//! The SPARKLE-384 and SPARKLE-512 permutations used by ESCH live directly in
//! this module. This crate does not depend on the SCHWAEMM AEAD engine.

use core::convert::Infallible;

use tc_digest::TryDigest;

const RATE_BYTES: usize = 16;
const RATE_WORDS: usize = 4;

const RCON: [u32; 8] = [
    0xb7e1_5162,
    0xbf71_5880,
    0x38b4_da56,
    0x324e_7738,
    0xbb11_85eb,
    0x4f7c_7b57,
    0xcfbf_a1c8,
    0xc2b3_293d,
];

/// Selects an ESCH digest variant.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum SparkleParameters {
    /// ESCH-256, using the 384-bit SPARKLE permutation.
    Esch256,
    /// ESCH-384, using the 512-bit SPARKLE permutation.
    Esch384,
}

impl SparkleParameters {
    const fn digest_bytes(self) -> usize {
        match self {
            Self::Esch256 => 32,
            Self::Esch384 => 48,
        }
    }

    const fn state_words(self) -> usize {
        match self {
            Self::Esch256 => 12,
            Self::Esch384 => 16,
        }
    }

    const fn slim_steps(self) -> usize {
        match self {
            Self::Esch256 => 7,
            Self::Esch384 => 8,
        }
    }

    const fn big_steps(self) -> usize {
        match self {
            Self::Esch256 => 11,
            Self::Esch384 => 12,
        }
    }
}

/// The ESCH-256 or ESCH-384 message digest.
#[derive(Clone)]
pub struct SparkleDigest {
    parameters: SparkleParameters,
    state: [u32; 16],
    buffer: [u8; RATE_BYTES],
    buffer_position: usize,
}

impl SparkleDigest {
    /// Creates an ESCH digest with the selected output size.
    pub const fn new(parameters: SparkleParameters) -> Self {
        Self {
            parameters,
            state: [0; 16],
            buffer: [0; RATE_BYTES],
            buffer_position: 0,
        }
    }

    fn permute(&mut self, steps: usize) {
        match self.parameters {
            SparkleParameters::Esch256 => sparkle_opt12(&mut self.state, steps),
            SparkleParameters::Esch384 => sparkle_opt16(&mut self.state, steps),
        }
    }

    fn process_block(&mut self, block: &[u8; RATE_BYTES], steps: usize) {
        let t0 = u32::from_le_bytes([block[0], block[1], block[2], block[3]]);
        let t1 = u32::from_le_bytes([block[4], block[5], block[6], block[7]]);
        let t2 = u32::from_le_bytes([block[8], block[9], block[10], block[11]]);
        let t3 = u32::from_le_bytes([block[12], block[13], block[14], block[15]]);

        let tx = ell(t0 ^ t2);
        let ty = ell(t1 ^ t3);
        self.state[0] ^= t0 ^ ty;
        self.state[1] ^= t1 ^ tx;
        self.state[2] ^= t2 ^ ty;
        self.state[3] ^= t3 ^ tx;
        self.state[4] ^= ty;
        self.state[5] ^= tx;
        if self.parameters == SparkleParameters::Esch384 {
            self.state[6] ^= ty;
            self.state[7] ^= tx;
        }

        self.permute(steps);
    }

    fn write_rate(&self, output: &mut [u8]) {
        for (word, chunk) in self.state[..RATE_WORDS]
            .iter()
            .zip(output[..RATE_BYTES].chunks_exact_mut(4))
        {
            chunk.copy_from_slice(&word.to_le_bytes());
        }
    }

    fn reset_state(&mut self) {
        self.state.fill(0);
        self.buffer.fill(0);
        self.buffer_position = 0;
    }
}

impl TryDigest for SparkleDigest {
    type Error = Infallible;

    fn algorithm_name(&self) -> &str {
        match self.parameters {
            SparkleParameters::Esch256 => "ESCH-256",
            SparkleParameters::Esch384 => "ESCH-384",
        }
    }

    fn digest_size(&self) -> usize {
        self.parameters.digest_bytes()
    }

    fn byte_length(&self) -> usize {
        RATE_BYTES
    }

    fn try_update(&mut self, mut input: &[u8]) -> Result<(), Self::Error> {
        if input.is_empty() {
            return Ok(());
        }

        let available = RATE_BYTES - self.buffer_position;
        if input.len() <= available {
            self.buffer[self.buffer_position..self.buffer_position + input.len()]
                .copy_from_slice(input);
            self.buffer_position += input.len();
            return Ok(());
        }

        if self.buffer_position != 0 {
            self.buffer[self.buffer_position..].copy_from_slice(&input[..available]);
            let block = self.buffer;
            self.process_block(&block, self.parameters.slim_steps());
            self.buffer_position = 0;
            input = &input[available..];
        }

        while input.len() > RATE_BYTES {
            let mut block = [0u8; RATE_BYTES];
            block.copy_from_slice(&input[..RATE_BYTES]);
            self.process_block(&block, self.parameters.slim_steps());
            input = &input[RATE_BYTES..];
        }

        self.buffer[..input.len()].copy_from_slice(input);
        self.buffer_position = input.len();
        Ok(())
    }

    fn try_do_final(&mut self, output: &mut [u8]) -> Result<usize, Self::Error> {
        let digest_bytes = self.parameters.digest_bytes();
        let state_words = self.parameters.state_words();

        if self.buffer_position < RATE_BYTES {
            self.state[(state_words >> 1) - 1] ^= 1 << 24;
            self.buffer[self.buffer_position] = 0x80;
            self.buffer[self.buffer_position + 1..].fill(0);
        } else {
            self.state[(state_words >> 1) - 1] ^= 1 << 25;
        }

        let block = self.buffer;
        self.process_block(&block, self.parameters.big_steps());
        self.write_rate(output);

        self.permute(self.parameters.slim_steps());
        self.write_rate(&mut output[RATE_BYTES..]);

        if self.parameters == SparkleParameters::Esch384 {
            self.permute(self.parameters.slim_steps());
            self.write_rate(&mut output[RATE_BYTES * 2..]);
        }

        self.reset_state();
        Ok(digest_bytes)
    }

    fn try_reset(&mut self) -> Result<(), Self::Error> {
        self.reset_state();
        Ok(())
    }
}

#[inline]
fn ell(x: u32) -> u32 {
    x.rotate_right(16) ^ (x & 0xffff)
}

#[inline]
fn arx_box(state: &mut [u32; 16], index: usize, round_constant: u32) {
    let mut x = state[index];
    let mut y = state[index + 1];

    x = x.wrapping_add(y.rotate_right(31));
    y ^= x.rotate_right(24);
    x ^= round_constant;
    x = x.wrapping_add(y.rotate_right(17));
    y ^= x.rotate_right(17);
    x ^= round_constant;
    x = x.wrapping_add(y);
    y ^= x.rotate_right(31);
    x ^= round_constant;
    x = x.wrapping_add(y.rotate_right(24));
    y ^= x.rotate_right(16);
    x ^= round_constant;

    state[index] = x;
    state[index + 1] = y;
}

fn sparkle_opt12(state: &mut [u32; 16], steps: usize) {
    for step in 0..steps {
        state[1] ^= RCON[step & 7];
        state[3] ^= step as u32;

        for (branch, round_constant) in RCON[..6].iter().copied().enumerate() {
            arx_box(state, branch * 2, round_constant);
        }

        let t024 = ell(state[0] ^ state[2] ^ state[4]);
        let t135 = ell(state[1] ^ state[3] ^ state[5]);
        let first = [state[0], state[1], state[2], state[3], state[4], state[5]];
        let u = [
            state[0] ^ state[6],
            state[1] ^ state[7],
            state[2] ^ state[8],
            state[3] ^ state[9],
            state[4] ^ state[10],
            state[5] ^ state[11],
        ];

        state[6..12].copy_from_slice(&first);
        state[0] = u[2] ^ t135;
        state[1] = u[3] ^ t024;
        state[2] = u[4] ^ t135;
        state[3] = u[5] ^ t024;
        state[4] = u[0] ^ t135;
        state[5] = u[1] ^ t024;
    }
}

fn sparkle_opt16(state: &mut [u32; 16], steps: usize) {
    for step in 0..steps {
        state[1] ^= RCON[step & 7];
        state[3] ^= step as u32;

        for (branch, round_constant) in RCON.iter().copied().enumerate() {
            arx_box(state, branch * 2, round_constant);
        }

        let t0246 = ell(state[0] ^ state[2] ^ state[4] ^ state[6]);
        let t1357 = ell(state[1] ^ state[3] ^ state[5] ^ state[7]);
        let first = [
            state[0], state[1], state[2], state[3], state[4], state[5], state[6], state[7],
        ];
        let u = [
            state[0] ^ state[8],
            state[1] ^ state[9],
            state[2] ^ state[10],
            state[3] ^ state[11],
            state[4] ^ state[12],
            state[5] ^ state[13],
            state[6] ^ state[14],
            state[7] ^ state[15],
        ];

        state[8..].copy_from_slice(&first);
        state[0] = u[2] ^ t1357;
        state[1] = u[3] ^ t0246;
        state[2] = u[4] ^ t1357;
        state[3] = u[5] ^ t0246;
        state[4] = u[6] ^ t1357;
        state[5] = u[7] ^ t0246;
        state[6] = u[0] ^ t1357;
        state[7] = u[1] ^ t0246;
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tc_digest::Digest;

    fn decode_hex<const N: usize>(encoded: &str) -> [u8; N] {
        assert_eq!(encoded.len(), N * 2);
        let bytes = encoded.as_bytes();
        let mut decoded = [0u8; N];
        let mut index = 0;
        while index < N {
            decoded[index] = (hex_digit(bytes[index * 2]) << 4) | hex_digit(bytes[index * 2 + 1]);
            index += 1;
        }
        decoded
    }

    fn hex_digit(digit: u8) -> u8 {
        match digit {
            b'0'..=b'9' => digit - b'0',
            b'a'..=b'f' => digit - b'a' + 10,
            b'A'..=b'F' => digit - b'A' + 10,
            _ => panic!("invalid hex digit"),
        }
    }

    fn message() -> [u8; 1024] {
        let mut message = [0u8; 1024];
        for (index, byte) in message.iter_mut().enumerate() {
            *byte = index as u8;
        }
        message
    }

    #[test]
    fn esch256_nist_lwc_vectors() {
        let vectors = [
            (
                0,
                "C0E815D78B875DC768C6C8B3AFA51987CD69E5C087D387368628A511CFAD5730",
            ),
            (
                1,
                "D515FD9C2852D9D6F00C9CF01D858AF467EEDF21FF68CC14C005B3EFF7A6ECD3",
            ),
            (
                15,
                "5753E34E3FC970881E1752B59C573E89448D08A93EAE46DA2A5D8AB04790A60C",
            ),
            (
                16,
                "ACFF841E2A526D83D6E94AB5564D6D64C98F5E8016BB1C2950386ED156C6C174",
            ),
            (
                17,
                "E6BF73941A7417FEFD2DD5882FFCBFAEA22B4C131EF155943FC817F61AD05B85",
            ),
            (
                31,
                "8F9FDD4C85AAF7775025300D8E60C1AFE77524F51C5C7BD00B656D0FD07D26B1",
            ),
            (
                32,
                "78B905B2E2D4110B76EF8AFD2495F58AD6FFD6B9727377F3E5DFCEEBF3031E24",
            ),
            (
                33,
                "DCCFEADCDD16AB5859EE571A2A669EDFF5581E2093BA3B979B73A9D73D848B27",
            ),
            (
                255,
                "8D1DD53F1A6E814EFE07472BE9EFEFED63AF169ED5DE667DC5A55D5F61FC66C3",
            ),
            (
                511,
                "95D4CB18C632DF6246775179B70F279747FC175C9D43C417574EB7B82ED746BB",
            ),
            (
                1024,
                "2EFD300525B3A4FE87933334E2C87AFFEFB65B4F59BD72C2AF3F7A69740D0D15",
            ),
        ];
        let message = message();

        for (length, expected) in vectors {
            let expected = decode_hex::<32>(expected);
            let mut digest = SparkleDigest::new(SparkleParameters::Esch256);
            digest.update(&message[..length]);
            let mut output = [0u8; 32];
            assert_eq!(digest.do_final(&mut output), output.len());
            assert_eq!(output, expected, "length {length}");

            for chunk in message[..length].chunks(7) {
                digest.update(chunk);
            }
            digest.do_final(&mut output);
            assert_eq!(output, expected, "chunked length {length}");
        }
    }

    #[test]
    fn esch384_nist_lwc_vectors() {
        let vectors = [
            (
                0,
                "2981715E2263EBD0CB6E5C2C99D0776D5E691EE737FDE05247895E75D02E7447FD6AB707E2EC8385A539777965E472EE",
            ),
            (
                1,
                "CA78366C86E82726C19EBD1DBBB1375CEF93C570F856CE2FF5DA0CA87140DACD65F3E1C5AF5F84B3F6390B9AC1A2FA4D",
            ),
            (
                15,
                "C61174073AE9E1DFF4698369FEDB8ED785F4873EB0CBDC16FF0A23D2E7A985A165EC76DAEE03B9D14C91AC316A5B6C0F",
            ),
            (
                16,
                "0008F97D6BBB701D5E33FCC178EFE3E3D5E77915D4A4DAF6E1AE34CD28EDB895A053E19D930B50F72837E1A8F5B1F450",
            ),
            (
                17,
                "4D5607783A26B83FD478C8EAC31634DD3641ADB61C6DF964D6935E716D6826397C01AAEC57F584E6FB293EC26B547CE8",
            ),
            (
                31,
                "A3B8F52AF30CA05BBF9ACDA603278A05E369AD0670948137273BE67019407A57E036098AA0070C7EA74D8CB2AA9B3C1E",
            ),
            (
                32,
                "55BA6E68B5EF92458C75E4888B25B31DC6212933B138C9623217AF9AAFF2A4691B81331DE422387D12F170EF088E0EA1",
            ),
            (
                33,
                "EC526F22147A290B6FADCDBC74EA9C2205D68C86B8616E7DA10179CD177670C5BAC2B60828147649852FDEECE04E2A6B",
            ),
            (
                255,
                "90B4C55929AE6DE7F01FA6C88D20E9727AC5551CF7B5F5DE8FFA67FA47BA1EC560E227F0B5AAC75FC5F94A69AE8221B6",
            ),
            (
                511,
                "5558E17E134BBEC2B20097AD51E9772AD10708D18171E8A46A643A8D2388236C13BAA2361B04F0A7B937A0887461E0B1",
            ),
            (
                1024,
                "167488DF37DD406C729328A451D79DCA2AE1FA1FFF03888C2AD86DB507A92E46769CB07C7D31A18ECBF5A0B3E3F1F678",
            ),
        ];
        let message = message();

        for (length, expected) in vectors {
            let expected = decode_hex::<48>(expected);
            let mut digest = SparkleDigest::new(SparkleParameters::Esch384);
            digest.update(&message[..length]);
            let mut output = [0u8; 48];
            assert_eq!(digest.do_final(&mut output), output.len());
            assert_eq!(output, expected, "length {length}");

            for chunk in message[..length].chunks(7) {
                digest.update(chunk);
            }
            digest.do_final(&mut output);
            assert_eq!(output, expected, "chunked length {length}");
        }
    }

    #[test]
    fn accessors_clone_bytewise_and_reset() {
        let message = message();
        let mut digest = SparkleDigest::new(SparkleParameters::Esch256);
        assert_eq!(digest.algorithm_name(), "ESCH-256");
        assert_eq!(digest.digest_size(), 32);
        assert_eq!(digest.byte_length(), RATE_BYTES);

        digest.update(&message[..37]);
        let mut cloned = digest.clone();
        digest.update(&message[37..129]);
        cloned.update(&message[37..129]);
        let mut output = [0u8; 32];
        let mut cloned_output = [0u8; 32];
        digest.do_final(&mut output);
        cloned.do_final(&mut cloned_output);
        assert_eq!(output, cloned_output);

        for byte in &message[..129] {
            digest.update_byte(*byte);
        }
        digest.do_final(&mut cloned_output);
        assert_eq!(output, cloned_output);

        digest.update(b"discarded state");
        digest.reset();
        digest.update(&message[..129]);
        digest.do_final(&mut cloned_output);
        assert_eq!(output, cloned_output);

        let digest = SparkleDigest::new(SparkleParameters::Esch384);
        assert_eq!(digest.algorithm_name(), "ESCH-384");
        assert_eq!(digest.digest_size(), 48);
    }
}
