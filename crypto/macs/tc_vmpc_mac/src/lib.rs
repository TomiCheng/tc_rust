//! VMPC-MAC message authentication code.

#![no_std]

use core::fmt;

use tc_crypto::AlgorithmName;
use tc_macs::{Mac, MacError, MacInit, MacInitError};
use tc_params::{IvParams, KeyParams};

const STATE_BYTES: usize = 256;
const TABLE_BYTES: usize = 32;
const KSA_STEPS: usize = 768;
const MIN_KEY_BYTES: usize = 16;
const MAX_KEY_BYTES: usize = 64;
const MIN_IV_BYTES: usize = 16;
const MAX_IV_BYTES: usize = 64;

/// VMPC-MAC authentication-tag length in bytes.
pub const TAG_BYTES: usize = 20;

/// Allocation-free VMPC-MAC.
pub struct VmpcMac {
    permutation: [u8; STATE_BYTES],
    table: [u8; TABLE_BYTES],
    key: [u8; MAX_KEY_BYTES],
    key_len: usize,
    iv: [u8; MAX_IV_BYTES],
    iv_len: usize,
    g: u8,
    n: u8,
    s: u8,
    x1: u8,
    x2: u8,
    x3: u8,
    x4: u8,
    initialized: bool,
}

impl VmpcMac {
    /// Creates an uninitialized VMPC-MAC instance.
    pub const fn new() -> Self {
        Self {
            permutation: [0; STATE_BYTES],
            table: [0; TABLE_BYTES],
            key: [0; MAX_KEY_BYTES],
            key_len: 0,
            iv: [0; MAX_IV_BYTES],
            iv_len: 0,
            g: 0,
            n: 0,
            s: 0,
            x1: 0,
            x2: 0,
            x3: 0,
            x4: 0,
            initialized: false,
        }
    }

    fn ksa_round(&mut self, input: &[u8]) {
        for step in 0..KSA_STEPS {
            let index = step & 0xff;
            self.s = self.permutation[self
                .s
                .wrapping_add(self.permutation[index])
                .wrapping_add(input[step % input.len()])
                as usize];
            self.permutation.swap(index, self.s as usize);
        }
    }

    fn reset_state(&mut self) {
        self.n = 0;
        self.s = 0;
        for (index, byte) in self.permutation.iter_mut().enumerate() {
            *byte = index as u8;
        }
        let key = self.key;
        self.ksa_round(&key[..self.key_len]);
        let iv = self.iv;
        self.ksa_round(&iv[..self.iv_len]);
        self.g = 0;
        self.x1 = 0;
        self.x2 = 0;
        self.x3 = 0;
        self.x4 = 0;
        self.n = 0;
        self.table.fill(0);
    }

    fn update_byte(&mut self, input: u8) {
        let n = self.n as usize;
        let pn = self.permutation[n];
        self.s = self.permutation[self.s.wrapping_add(pn) as usize];
        let ps = self.permutation[self.s as usize];
        let cipher_byte =
            input ^ self.permutation[self.permutation[ps as usize].wrapping_add(1) as usize];

        self.x4 = self.permutation[self.x4.wrapping_add(self.x3) as usize];
        self.x3 = self.permutation[self.x3.wrapping_add(self.x2) as usize];
        self.x2 = self.permutation[self.x2.wrapping_add(self.x1) as usize];
        self.x1 = self.permutation[self.x1.wrapping_add(self.s).wrapping_add(cipher_byte) as usize];
        self.table[self.g as usize] ^= self.x1;
        self.table[self.g.wrapping_add(1) as usize & 0x1f] ^= self.x2;
        self.table[self.g.wrapping_add(2) as usize & 0x1f] ^= self.x3;
        self.table[self.g.wrapping_add(3) as usize & 0x1f] ^= self.x4;
        self.g = self.g.wrapping_add(4) & 0x1f;

        self.permutation[n] = ps;
        self.permutation[self.s as usize] = pn;
        self.n = self.n.wrapping_add(1);
    }
}

impl Default for VmpcMac {
    fn default() -> Self {
        Self::new()
    }
}

impl AlgorithmName for VmpcMac {
    fn write_algo_name(&self, output: &mut dyn fmt::Write) -> fmt::Result {
        output.write_str("VMPC-MAC")
    }
}

impl Mac for VmpcMac {
    type Error = MacError;

    fn mac_size(&self) -> usize {
        TAG_BYTES
    }

    fn update(&mut self, input: &[u8]) -> Result<(), Self::Error> {
        if !self.initialized {
            return Err(MacError::NotInitialised);
        }
        for &byte in input {
            self.update_byte(byte);
        }
        Ok(())
    }

    fn do_final(&mut self, output: &mut [u8]) -> Result<usize, Self::Error> {
        if !self.initialized {
            return Err(MacError::NotInitialised);
        }
        if output.len() < TAG_BYTES {
            return Err(MacError::OutputTooShort {
                required: TAG_BYTES,
                available: output.len(),
            });
        }

        for round in 1_u8..25 {
            self.s =
                self.permutation[self.s.wrapping_add(self.permutation[self.n as usize]) as usize];
            self.x4 = self.permutation[self.x4.wrapping_add(self.x3).wrapping_add(round) as usize];
            self.x3 = self.permutation[self.x3.wrapping_add(self.x2).wrapping_add(round) as usize];
            self.x2 = self.permutation[self.x2.wrapping_add(self.x1).wrapping_add(round) as usize];
            self.x1 = self.permutation[self.x1.wrapping_add(self.s).wrapping_add(round) as usize];
            self.table[self.g as usize] ^= self.x1;
            self.table[self.g.wrapping_add(1) as usize & 0x1f] ^= self.x2;
            self.table[self.g.wrapping_add(2) as usize & 0x1f] ^= self.x3;
            self.table[self.g.wrapping_add(3) as usize & 0x1f] ^= self.x4;
            self.g = self.g.wrapping_add(4) & 0x1f;
            self.permutation.swap(self.n as usize, self.s as usize);
            self.n = self.n.wrapping_add(1);
        }

        for step in 0..KSA_STEPS {
            let index = step & 0xff;
            self.s = self.permutation[self
                .s
                .wrapping_add(self.permutation[index])
                .wrapping_add(self.table[step & 0x1f])
                as usize];
            self.permutation.swap(index, self.s as usize);
        }

        for (index, byte) in output[..TAG_BYTES].iter_mut().enumerate() {
            self.s = self.permutation[self.s.wrapping_add(self.permutation[index]) as usize];
            *byte = self.permutation[self.permutation[self.permutation[self.s as usize] as usize]
                .wrapping_add(1) as usize];
            self.permutation.swap(index, self.s as usize);
        }

        self.reset_state();
        Ok(TAG_BYTES)
    }

    fn reset(&mut self) {
        if self.initialized {
            self.reset_state();
        }
    }
}

impl<P: KeyParams + IvParams + ?Sized> MacInit<P> for VmpcMac {
    type Error = MacInitError;

    fn init(&mut self, params: &P) -> Result<(), Self::Error> {
        self.initialized = false;
        let key = params.key();
        if !(MIN_KEY_BYTES..=MAX_KEY_BYTES).contains(&key.len()) {
            return Err(MacInitError::InvalidKeyLength(key.len()));
        }
        let iv = params.iv();
        if !(MIN_IV_BYTES..=MAX_IV_BYTES).contains(&iv.len()) {
            return Err(MacInitError::InvalidIvLength(iv.len()));
        }

        self.key.fill(0);
        self.key[..key.len()].copy_from_slice(key);
        self.key_len = key.len();
        self.iv.fill(0);
        self.iv[..iv.len()].copy_from_slice(iv);
        self.iv_len = iv.len();
        self.initialized = true;
        self.reset_state();
        Ok(())
    }
}

impl Drop for VmpcMac {
    fn drop(&mut self) {
        self.permutation.fill(0);
        self.table.fill(0);
        self.key.fill(0);
        self.iv.fill(0);
    }
}
