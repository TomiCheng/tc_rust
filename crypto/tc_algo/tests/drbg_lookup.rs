use std::convert::Infallible;

use rand_core::{Rng, TryCryptoRng, TryRng};
use tc_algo::drbg::{Drbg, DrbgEntry};
use tc_algo::{
    AlgoBuilder, AlgoError, DefaultAlgoBuilder, DefaultAlgoContext, EntryBase, ErrorKind, Params,
};

// Counts up from a start, which is enough to tell rows and calls apart
struct Counter(u64);

impl TryRng for Counter {
    type Error = Infallible;

    fn try_next_u32(&mut self) -> Result<u32, Infallible> {
        Ok(self.try_next_u64()? as u32)
    }

    fn try_next_u64(&mut self) -> Result<u64, Infallible> {
        self.0 += 1;
        Ok(self.0)
    }

    fn try_fill_bytes(&mut self, dest: &mut [u8]) -> Result<(), Infallible> {
        for chunk in dest.chunks_mut(8) {
            let bytes = self.try_next_u64()?.to_le_bytes();
            chunk.copy_from_slice(&bytes[..chunk.len()]);
        }
        Ok(())
    }
}

impl TryCryptoRng for Counter {}

impl Drbg for Counter {
    fn init(&mut self, _params: &dyn Params) -> Result<(), AlgoError> {
        Ok(())
    }

    fn reseed(&mut self, _additional_input: &[u8]) -> Result<(), AlgoError> {
        self.0 = 0;
        Ok(())
    }
}

// A row from outside the crate, as anyone could write one
struct Row;

impl EntryBase for Row {
    fn name(&self) -> &str {
        "COUNTER-DRBG"
    }
}

impl DrbgEntry for Row {
    fn create(&self) -> Box<dyn Drbg> {
        Box::new(Counter(100))
    }
}

fn rows(_context: &DefaultAlgoContext) -> Vec<Box<dyn DrbgEntry>> {
    vec![Box::new(Row)]
}

#[test]
fn a_registered_drbg_is_found_by_its_name_and_gives_random_numbers() {
    let mut builder = DefaultAlgoBuilder::default();
    builder.reg_drbg(rows);
    let algo = builder.build();

    let mut drbg = algo.drbg().get_by_name("counter-drbg").unwrap();
    assert_eq!(drbg.next_u64(), 101);
    assert_eq!(drbg.next_u64(), 102);

    drbg.reseed(b"").unwrap();
    assert_eq!(drbg.next_u64(), 1);
}

#[test]
fn an_unknown_name_is_an_unknown_drbg() {
    let algo = DefaultAlgoBuilder::default().build();

    let error = algo.drbg().get_by_name("COUNTER-DRBG").err().unwrap();
    assert_eq!(error.kind(), ErrorKind::UnknownDrbg);
}
