use std::io::{self, Write};

use clap::Subcommand;
use tc_algo::{AlgoBuilder, DefaultAlgoBuilder, EntryBase};

#[derive(Subcommand)]
pub(crate) enum AlgoCommand {
    /// Message digests
    Digest {
        /// List the digest names and their aliases
        #[arg(long, required = true)]
        list: bool,
    },
    /// MACs
    Mac {
        /// List the MAC names and their aliases
        #[arg(long, required = true)]
        list: bool,
    },
    /// Key derivation functions
    Kdf {
        /// List the KDF names and their aliases
        #[arg(long, required = true)]
        list: bool,
    },
}

pub(crate) fn run(command: AlgoCommand) -> io::Result<()> {
    let algo = DefaultAlgoBuilder::default().build();
    match command {
        AlgoCommand::Digest { .. } => list(algo.digest().algorithms().map(|e| e as &dyn EntryBase)),
        AlgoCommand::Mac { .. } => list(algo.mac().algorithms().map(|e| e as &dyn EntryBase)),
        AlgoCommand::Kdf { .. } => list(algo.kdf().algorithms().map(|e| e as &dyn EntryBase)),
    }
}

fn list<'a>(entries: impl Iterator<Item = &'a dyn EntryBase>) -> io::Result<()> {
    let mut out = io::stdout().lock();
    for entry in entries {
        writeln!(out, "{}\t{}", entry.name(), entry.aliases().join(", "))?;
    }
    Ok(())
}
