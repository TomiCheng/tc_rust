use std::io::{self, Write};

use clap::Args;
use tc_encoders::Encoder;
use tc_encoders::hex::Hex;

#[derive(Args)]
pub(crate) struct HexArgs {
    /// Decode hex to bytes; whitespace is skipped
    #[arg(short, long)]
    decode: bool,
    /// Encode with upper-case digits
    #[arg(short, long, conflicts_with = "decode")]
    upper: bool,
}

pub(crate) fn run(args: HexArgs) -> io::Result<()> {
    let mut input = io::stdin().lock();
    let mut out = io::stdout().lock();
    if args.decode {
        Hex::LOWER.decode_from(&mut input, &mut out)?;
    } else {
        let encoder = if args.upper { Hex::UPPER } else { Hex::LOWER };
        encoder.encode_from(&mut input, &mut out)?;
        writeln!(out)?;
    }
    out.flush()
}
