// Licensed to the Apache Software Foundation (ASF) under one or more
// contributor license agreements. See the NOTICE file distributed with
// this work for additional information regarding copyright ownership.
// The ASF licenses this file to You under the Apache License, Version 2.0
// (the "License"); you may not use this file except in compliance with
// the License. You may obtain a copy of the License at
//
// http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

// This package is based on the work done by Keiron Liddle, Aftex Software
// <keiron@aftexsw.com> to whom the Ant project is very grateful for his
// great code.

//! BZip2-specific CRC-32 implementation.
//!
//! Port of `CRC.cs` from bc-csharp.
//!
//! This is **not** the standard CRC-32 (IEEE 802.3 / ZIP / PNG).
//! It uses the non-reflected polynomial 0x04C11DB7 with byte-reversed
//! table entries and a byte-swap in [`Crc::get_final`], matching the
//! bzip2 format specification.

/// Byte-reversed CRC-32 lookup table (polynomial 0x04C11DB7, MSB-first).
const CRC32_TABLE: [u32; 256] = [
    0x00000000, 0xB71DC104, 0x6E3B8209, 0xD926430D, 0xDC760413, 0x6B6BC517, 0xB24D861A, 0x0550471E,
    0xB8ED0826, 0x0FF0C922, 0xD6D68A2F, 0x61CB4B2B, 0x649B0C35, 0xD386CD31, 0x0AA08E3C, 0xBDBD4F38,
    0x70DB114C, 0xC7C6D048, 0x1EE09345, 0xA9FD5241, 0xACAD155F, 0x1BB0D45B, 0xC2969756, 0x758B5652,
    0xC836196A, 0x7F2BD86E, 0xA60D9B63, 0x11105A67, 0x14401D79, 0xA35DDC7D, 0x7A7B9F70, 0xCD665E74,
    0xE0B62398, 0x57ABE29C, 0x8E8DA191, 0x39906095, 0x3CC0278B, 0x8BDDE68F, 0x52FBA582, 0xE5E66486,
    0x585B2BBE, 0xEF46EABA, 0x3660A9B7, 0x817D68B3, 0x842D2FAD, 0x3330EEA9, 0xEA16ADA4, 0x5D0B6CA0,
    0x906D32D4, 0x2770F3D0, 0xFE56B0DD, 0x494B71D9, 0x4C1B36C7, 0xFB06F7C3, 0x2220B4CE, 0x953D75CA,
    0x28803AF2, 0x9F9DFBF6, 0x46BBB8FB, 0xF1A679FF, 0xF4F63EE1, 0x43EBFFE5, 0x9ACDBCE8, 0x2DD07DEC,
    0x77708634, 0xC06D4730, 0x194B043D, 0xAE56C539, 0xAB068227, 0x1C1B4323, 0xC53D002E, 0x7220C12A,
    0xCF9D8E12, 0x78804F16, 0xA1A60C1B, 0x16BBCD1F, 0x13EB8A01, 0xA4F64B05, 0x7DD00808, 0xCACDC90C,
    0x07AB9778, 0xB0B6567C, 0x69901571, 0xDE8DD475, 0xDBDD936B, 0x6CC0526F, 0xB5E61162, 0x02FBD066,
    0xBF469F5E, 0x085B5E5A, 0xD17D1D57, 0x6660DC53, 0x63309B4D, 0xD42D5A49, 0x0D0B1944, 0xBA16D840,
    0x97C6A5AC, 0x20DB64A8, 0xF9FD27A5, 0x4EE0E6A1, 0x4BB0A1BF, 0xFCAD60BB, 0x258B23B6, 0x9296E2B2,
    0x2F2BAD8A, 0x98366C8E, 0x41102F83, 0xF60DEE87, 0xF35DA999, 0x4440689D, 0x9D662B90, 0x2A7BEA94,
    0xE71DB4E0, 0x500075E4, 0x892636E9, 0x3E3BF7ED, 0x3B6BB0F3, 0x8C7671F7, 0x555032FA, 0xE24DF3FE,
    0x5FF0BCC6, 0xE8ED7DC2, 0x31CB3ECF, 0x86D6FFCB, 0x8386B8D5, 0x349B79D1, 0xEDBD3ADC, 0x5AA0FBD8,
    0xEEE00C69, 0x59FDCD6D, 0x80DB8E60, 0x37C64F64, 0x3296087A, 0x858BC97E, 0x5CAD8A73, 0xEBB04B77,
    0x560D044F, 0xE110C54B, 0x38368646, 0x8F2B4742, 0x8A7B005C, 0x3D66C158, 0xE4408255, 0x535D4351,
    0x9E3B1D25, 0x2926DC21, 0xF0009F2C, 0x471D5E28, 0x424D1936, 0xF550D832, 0x2C769B3F, 0x9B6B5A3B,
    0x26D61503, 0x91CBD407, 0x48ED970A, 0xFFF0560E, 0xFAA01110, 0x4DBDD014, 0x949B9319, 0x2386521D,
    0x0E562FF1, 0xB94BEEF5, 0x606DADF8, 0xD7706CFC, 0xD2202BE2, 0x653DEAE6, 0xBC1BA9EB, 0x0B0668EF,
    0xB6BB27D7, 0x01A6E6D3, 0xD880A5DE, 0x6F9D64DA, 0x6ACD23C4, 0xDDD0E2C0, 0x04F6A1CD, 0xB3EB60C9,
    0x7E8D3EBD, 0xC990FFB9, 0x10B6BCB4, 0xA7AB7DB0, 0xA2FB3AAE, 0x15E6FBAA, 0xCCC0B8A7, 0x7BDD79A3,
    0xC660369B, 0x717DF79F, 0xA85BB492, 0x1F467596, 0x1A163288, 0xAD0BF38C, 0x742DB081, 0xC3307185,
    0x99908A5D, 0x2E8D4B59, 0xF7AB0854, 0x40B6C950, 0x45E68E4E, 0xF2FB4F4A, 0x2BDD0C47, 0x9CC0CD43,
    0x217D827B, 0x9660437F, 0x4F460072, 0xF85BC176, 0xFD0B8668, 0x4A16476C, 0x93300461, 0x242DC565,
    0xE94B9B11, 0x5E565A15, 0x87701918, 0x306DD81C, 0x353D9F02, 0x82205E06, 0x5B061D0B, 0xEC1BDC0F,
    0x51A69337, 0xE6BB5233, 0x3F9D113E, 0x8880D03A, 0x8DD09724, 0x3ACD5620, 0xE3EB152D, 0x54F6D429,
    0x7926A9C5, 0xCE3B68C1, 0x171D2BCC, 0xA000EAC8, 0xA550ADD6, 0x124D6CD2, 0xCB6B2FDF, 0x7C76EEDB,
    0xC1CBA1E3, 0x76D660E7, 0xAFF023EA, 0x18EDE2EE, 0x1DBDA5F0, 0xAAA064F4, 0x738627F9, 0xC49BE6FD,
    0x09FDB889, 0xBEE0798D, 0x67C63A80, 0xD0DBFB84, 0xD58BBC9A, 0x62967D9E, 0xBBB03E93, 0x0CADFF97,
    0xB110B0AF, 0x060D71AB, 0xDF2B32A6, 0x6836F3A2, 0x6D66B4BC, 0xDA7B75B8, 0x035D36B5, 0xB440F7B1,
];

/// BZip2-specific CRC-32 calculator.
pub(super) struct Crc {
    value: u32,
}

impl Crc {
    pub(super) fn new() -> Self {
        Self { value: 0 }
    }

    /// Reset the CRC state ready for a new block.
    pub(super) fn initialise(&mut self) {
        self.value = 0xFFFF_FFFF;
    }

    /// Return the final CRC value for the current block.
    ///
    /// Byte-swaps before inverting to match the bzip2 big-endian CRC format.
    pub(super) fn get_final(&self) -> u32 {
        !self.value.swap_bytes()
    }

    /// Update the CRC with a single byte.
    pub(super) fn update(&mut self, ch: u8) {
        self.value = (self.value >> 8) ^ CRC32_TABLE[(self.value as u8 ^ ch) as usize];
    }

    /// Update the CRC with `run_length` repetitions of the same byte.
    ///
    /// Processes four bytes at a time for efficiency. `run_length` must be >= 4.
    pub(super) fn update_run(&mut self, ch: u8, mut run_length: usize) {
        debug_assert!(run_length >= 4);

        let ch2 = (ch as u32) << 8 | ch as u32;
        let ch4 = ch2 << 16 | ch2;

        loop {
            self.value ^= ch4;
            self.value = (self.value >> 8) ^ CRC32_TABLE[self.value as u8 as usize];
            self.value = (self.value >> 8) ^ CRC32_TABLE[self.value as u8 as usize];
            self.value = (self.value >> 8) ^ CRC32_TABLE[self.value as u8 as usize];
            self.value = (self.value >> 8) ^ CRC32_TABLE[self.value as u8 as usize];

            run_length -= 4;
            if run_length < 4 {
                break;
            }
        }

        match run_length & 3 {
            1 => self.update(ch),
            2 => {
                self.update(ch);
                self.update(ch);
            }
            3 => {
                self.update(ch);
                self.update(ch);
                self.update(ch);
            }
            _ => {}
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn crc_of(data: &[u8]) -> u32 {
        let mut crc = Crc::new();
        crc.initialise();
        for &b in data {
            crc.update(b);
        }
        crc.get_final()
    }

    /// `update_run(ch, n)` must produce the same CRC as n individual `update(ch)` calls.
    #[test]
    fn update_run_matches_update() {
        for &len in &[4usize, 5, 7, 8, 9, 15, 16, 100] {
            let ch = 0xA5u8;

            let mut by_update = Crc::new();
            by_update.initialise();
            for _ in 0..len {
                by_update.update(ch);
            }

            let mut by_run = Crc::new();
            by_run.initialise();
            by_run.update_run(ch, len);

            assert_eq!(
                by_update.get_final(),
                by_run.get_final(),
                "mismatch for run_length = {len}"
            );
        }
    }

    /// CRC of the same data computed two different ways must agree.
    #[test]
    fn update_then_run_consistent() {
        // prefix "AB" then a run of 0xFF × 8
        let mut c1 = Crc::new();
        c1.initialise();
        c1.update(b'A');
        c1.update(b'B');
        for _ in 0..8 {
            c1.update(0xFF);
        }

        let mut c2 = Crc::new();
        c2.initialise();
        c2.update(b'A');
        c2.update(b'B');
        c2.update_run(0xFF, 8);

        assert_eq!(c1.get_final(), c2.get_final());
    }

    /// Two different byte sequences must produce different CRC values (collision
    /// sanity check — not a proof of correctness, but catches obvious bugs).
    #[test]
    fn different_data_different_crc() {
        assert_ne!(crc_of(b"hello"), crc_of(b"world"));
        assert_ne!(crc_of(b"abc"), crc_of(b"abd"));
        assert_ne!(crc_of(b""), crc_of(b"\x00"));
    }

    /// CRC must change when byte order changes.
    #[test]
    fn crc_is_order_sensitive() {
        assert_ne!(crc_of(b"\x01\x02"), crc_of(b"\x02\x01"));
    }
}
