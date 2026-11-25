mod algo;
mod util;

use std::io;
use std::process::ExitCode;

use clap::{Parser, Subcommand};

#[derive(Parser)]
#[command(
    name = "tcx",
    version,
    about = "Command-line front end to the tc_* crates"
)]
struct Cli {
    #[command(subcommand)]
    group: Group,
}

#[derive(Subcommand)]
enum Group {
    /// Algorithms of tc_algo, by name
    Algo {
        #[command(subcommand)]
        command: algo::AlgoCommand,
    },
    /// Encodings and other utilities
    Util {
        #[command(subcommand)]
        command: util::UtilCommand,
    },
}

fn main() -> ExitCode {
    match run(Cli::parse()) {
        Ok(()) => ExitCode::SUCCESS,
        Err(error) => {
            eprintln!("tcx: {error}");
            ExitCode::FAILURE
        }
    }
}

fn run(cli: Cli) -> io::Result<()> {
    match cli.group {
        Group::Algo { command } => algo::run(command),
        Group::Util { command } => util::run(command),
    }
}
