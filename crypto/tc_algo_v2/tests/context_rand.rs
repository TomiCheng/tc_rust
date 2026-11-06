use std::any::Any;
use std::convert::Infallible;

use rand_core::{CryptoRng, TryCryptoRng, TryRng};
use tc_algo_v2::generate::{KeyGenerator, KeyGeneratorEntry};
use tc_algo_v2::{
    AlgoBuilder, AlgoError, DefaultAlgoBuilder, DefaultAlgoContext, EntryBase, Params,
};

// Every byte is 7
struct Sevens;

impl TryRng for Sevens {
    type Error = Infallible;

    fn try_next_u32(&mut self) -> Result<u32, Infallible> {
        Ok(0x0707_0707)
    }

    fn try_next_u64(&mut self) -> Result<u64, Infallible> {
        Ok(0x0707_0707_0707_0707)
    }

    fn try_fill_bytes(&mut self, dest: &mut [u8]) -> Result<(), Infallible> {
        dest.fill(7);
        Ok(())
    }
}

impl TryCryptoRng for Sevens {}

fn sevens() -> Box<dyn CryptoRng> {
    Box::new(Sevens)
}

struct Key([u8; 4]);

impl Params for Key {
    fn as_any(&self) -> &dyn Any {
        self
    }
}

// A row from outside the crate, as anyone could write one
struct Row {
    rand: fn() -> Box<dyn CryptoRng>,
}

impl EntryBase for Row {
    fn name(&self) -> &str {
        "TEST-KEY"
    }
}

impl KeyGeneratorEntry for Row {
    fn create(&self) -> Box<dyn KeyGenerator> {
        Box::new(Generator((self.rand)()))
    }
}

struct Generator(Box<dyn CryptoRng>);

impl KeyGenerator for Generator {
    fn generate(&mut self) -> Result<Box<dyn Params>, AlgoError> {
        let mut key = [0; 4];
        self.0.fill_bytes(&mut key);
        Ok(Box::new(Key(key)))
    }
}

fn rows(context: &DefaultAlgoContext) -> Vec<Box<dyn KeyGeneratorEntry>> {
    vec![Box::new(Row {
        rand: context.rand(),
    })]
}

#[test]
fn a_row_from_outside_the_crate_draws_from_the_builders_random_source() {
    let mut builder = DefaultAlgoBuilder::default();
    builder.set_rand(sevens);
    builder.reg_key_generator(rows);
    let algo = builder.build();

    let key = algo.key_generator().generate_by_name("TEST-KEY").unwrap();
    let key = key.as_any().downcast_ref::<Key>().unwrap();
    assert_eq!(key.0, [7; 4]);
}
