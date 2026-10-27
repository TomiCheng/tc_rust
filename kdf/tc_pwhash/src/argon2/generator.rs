use alloc::vec::Vec;

use tc_blake::Blake2bDigest;
use tc_digest::Digest;
use tc_zeroize::{Zeroize, Zeroizing};

use super::block::{Block, Filler, block_from_bytes, block_to_bytes};
use super::hash::variable_hash;
use super::{Argon2Error, Argon2ParamsRef, Argon2Type, Argon2Version};

const SYNC_POINTS: usize = 4;
const MAX_PARALLELISM: u32 = (1 << 24) - 1;
const MIN_OUTPUT_BYTES: usize = 4;

/// Argon2 of RFC 9106, BC's `Argon2BytesGenerator`: [`init`](Self::init) takes the parameters
/// and each [`generate_bytes`](Self::generate_bytes) hashes a password under them.
///
/// The lanes are filled in turn rather than on threads, which gives the same result. As in BC,
/// the memory is kept between calls, wiped; the salt, secret and associated data copied at
/// `init` are wiped when replaced and on drop.
pub struct Argon2 {
    state: Option<State>,
    memory: Vec<Block>,
}

struct State {
    kind: Argon2Type,
    version: Argon2Version,
    iterations: u32,
    memory_kib: u32,
    lanes: u32,
    salt: Zeroizing<Vec<u8>>,
    secret: Zeroizing<Vec<u8>>,
    additional: Zeroizing<Vec<u8>>,
    segment_length: usize,
    lane_length: usize,
    block_count: usize,
}

impl Default for Argon2 {
    fn default() -> Self {
        Self::new()
    }
}

impl Argon2 {
    /// A generator, not yet initialized. Constant time.
    pub const fn new() -> Self {
        Self {
            state: None,
            memory: Vec::new(),
        }
    }

    /// Checks `params` and copies the salt, secret and associated data, BC's `Init` together
    /// with the checks of its builder.
    ///
    /// Fails when there are no passes, the lanes are 0 or `2^24` or more, the memory is 0 KiB
    /// or more blocks than the address space holds, or a byte string is longer than
    /// `2^32 - 1`; nothing changes then. Memory under 8 KiB per lane is raised to that, as in
    /// BC, while the hash still takes in the value given.
    ///
    /// Constant time with respect to the salt, secret and associated data.
    pub fn init(&mut self, params: &Argon2ParamsRef<'_>) -> Result<(), Argon2Error> {
        let iterations = params.iterations();
        if iterations == 0 {
            return Err(Argon2Error::InvalidIterations(iterations));
        }
        let lanes = params.parallelism();
        if lanes == 0 || lanes > MAX_PARALLELISM {
            return Err(Argon2Error::InvalidParallelism(lanes));
        }
        let memory_kib = params.memory_kib();
        if memory_kib == 0 {
            return Err(Argon2Error::InvalidMemory(memory_kib));
        }
        for bytes in [params.salt(), params.secret(), params.additional()] {
            if u32::try_from(bytes.len()).is_err() {
                return Err(Argon2Error::InputTooLong);
            }
        }

        // 每條 lane 分 4 段等長，至少 8 塊（BC 照參考實作）
        let segment_length = u64::from(memory_kib.max(8 * lanes) / (4 * lanes));
        let block_count = segment_length * SYNC_POINTS as u64 * u64::from(lanes);
        let block_count =
            usize::try_from(block_count).map_err(|_| Argon2Error::InvalidMemory(memory_kib))?;
        let segment_length = segment_length as usize;

        self.state = Some(State {
            kind: params.kind(),
            version: params.version(),
            iterations,
            memory_kib,
            lanes,
            salt: Zeroizing::new(params.salt().to_vec()),
            secret: Zeroizing::new(params.secret().to_vec()),
            additional: Zeroizing::new(params.additional().to_vec()),
            segment_length,
            lane_length: segment_length * SYNC_POINTS,
            block_count,
        });
        Ok(())
    }

    /// Fills `out` with the Argon2 tag of `password` under the parameters given to `init`,
    /// BC's `GenerateBytes`.
    ///
    /// Fails before `init`, when `out` is shorter than 4 bytes or longer than `2^32 - 1`, when
    /// the password is longer than `2^32 - 1` bytes, or when the memory cannot be allocated,
    /// all before any work.
    ///
    /// **Variable time (cache timing) for Argon2d and Argon2id; constant time for Argon2i.**
    /// Argon2d, and Argon2id after the first half of the first pass, read memory at indices
    /// taken from blocks that depend on the password, so where a cache is shared the timing
    /// can leak about it; Argon2i's indices depend only on the parameters. The rest depends
    /// only on the parameters and the lengths. The memory and the working blocks are wiped
    /// before returning.
    pub fn generate_bytes(&mut self, password: &[u8], out: &mut [u8]) -> Result<(), Argon2Error> {
        let Self { state, memory } = self;
        let state = state.as_ref().ok_or(Argon2Error::NotInitialised)?;
        if out.len() < MIN_OUTPUT_BYTES || u32::try_from(out.len()).is_err() {
            return Err(Argon2Error::InvalidOutputLength(out.len()));
        }
        if u32::try_from(password.len()).is_err() {
            return Err(Argon2Error::InputTooLong);
        }
        if memory.len() != state.block_count {
            *memory = Vec::new();
            memory
                .try_reserve_exact(state.block_count)
                .map_err(|_| Argon2Error::OutOfMemory)?;
            memory.resize(state.block_count, [0; 128]);
        }

        state.initialize(memory, password, out.len());
        state.fill_memory(memory);
        state.finalize(memory, out);
        memory.as_mut_slice().zeroize();
        Ok(())
    }
}

impl State {
    /// H0 與每條 lane 的前兩塊。
    fn initialize(&self, memory: &mut [Block], password: &[u8], tag_length: usize) {
        let mut h0 = Blake2bDigest::new();
        for value in [
            self.lanes,
            tag_length as u32,
            self.memory_kib,
            self.iterations,
            self.version.id(),
            self.kind.id(),
        ] {
            h0.update(&value.to_le_bytes());
        }
        for bytes in [password, &self.salt, &self.secret, &self.additional] {
            h0.update(&(bytes.len() as u32).to_le_bytes());
            h0.update(bytes);
        }

        let mut seed = [0; 72];
        h0.do_final(&mut seed[..64]);
        let mut bytes = [0; 1024];
        for lane in 0..self.lanes as usize {
            seed[68..].copy_from_slice(&(lane as u32).to_le_bytes());
            for column in 0..2 {
                seed[64..68].copy_from_slice(&(column as u32).to_le_bytes());
                variable_hash(&seed, &mut bytes);
                block_from_bytes(&mut memory[lane * self.lane_length + column], &bytes);
            }
        }
        seed.zeroize();
        bytes.zeroize();
    }

    fn fill_memory(&self, memory: &mut [Block]) {
        let mut filler = Filler::new();
        for pass in 0..self.iterations {
            for slice in 0..SYNC_POINTS {
                for lane in 0..self.lanes as usize {
                    self.fill_segment(memory, &mut filler, pass, slice, lane);
                }
            }
        }
    }

    fn fill_segment(
        &self,
        memory: &mut [Block],
        filler: &mut Filler,
        pass: u32,
        slice: usize,
        lane: usize,
    ) {
        let first_slice = pass == 0 && slice == 0;
        let data_independent = match self.kind {
            Argon2Type::Argon2i => true,
            Argon2Type::Argon2id => pass == 0 && slice < SYNC_POINTS / 2,
            Argon2Type::Argon2d => false,
        };
        let start = if first_slice { 2 } else { 0 };
        let segment_start = lane * self.lane_length + slice * self.segment_length;
        let first = segment_start + start;
        let mut prev = if first % self.lane_length == 0 {
            first + self.lane_length - 1
        } else {
            first - 1
        };

        if data_independent {
            filler.address = [0; 128];
            filler.input = [0; 128];
            filler.input[..6].copy_from_slice(&[
                u64::from(pass),
                lane as u64,
                slice as u64,
                self.block_count as u64,
                u64::from(self.iterations),
                u64::from(self.kind.id()),
            ]);
            if first_slice {
                filler.next_addresses();
            }
        }

        let with_xor = pass != 0 && self.version == Argon2Version::V13;
        for index in start..self.segment_length {
            let pseudo_random = if data_independent {
                if index % 128 == 0 {
                    filler.next_addresses();
                }
                filler.address[index % 128]
            } else {
                memory[prev][0]
            };
            let ref_lane = if first_slice {
                lane
            } else {
                ((pseudo_random >> 32) % u64::from(self.lanes)) as usize
            };
            let ref_column = self.ref_column(pass, slice, index, pseudo_random, ref_lane == lane);

            filler.load(
                &memory[prev],
                &memory[ref_lane * self.lane_length + ref_column],
            );
            let current = segment_start + index;
            filler.store(&mut memory[current], with_xor);
            prev = current;
        }
    }

    /// RFC 9106 §3.4.1.2：可參照的範圍與 J1 的非均勻對映。
    fn ref_column(
        &self,
        pass: u32,
        slice: usize,
        index: usize,
        pseudo_random: u64,
        same_lane: bool,
    ) -> usize {
        let segment = self.segment_length as u64;
        let lane_length = self.lane_length as u64;
        let (slice, index) = (slice as u64, index as u64);
        let (start, area) = if pass == 0 {
            let done = slice * segment;
            (
                0,
                if same_lane {
                    done + index - 1
                } else {
                    done - u64::from(index == 0)
                },
            )
        } else {
            let done = lane_length - segment;
            (
                (slice + 1) * segment % lane_length,
                if same_lane {
                    done + index - 1
                } else {
                    done - u64::from(index == 0)
                },
            )
        };
        let x = pseudo_random & 0xffff_ffff;
        let y = (x * x) >> 32;
        let relative = area - 1 - ((area * y) >> 32);
        ((start + relative) % lane_length) as usize
    }

    /// 各 lane 最後一塊 XOR 起來，以 H' 得出 tag。
    fn finalize(&self, memory: &[Block], out: &mut [u8]) {
        let last = self.lane_length - 1;
        let mut block = memory[last];
        for lane in 1..self.lanes as usize {
            for (b, m) in block
                .iter_mut()
                .zip(&memory[lane * self.lane_length + last])
            {
                *b ^= m;
            }
        }
        let mut bytes = [0; 1024];
        block_to_bytes(&block, &mut bytes);
        variable_hash(&bytes, out);
        block.zeroize();
        bytes.zeroize();
    }
}
