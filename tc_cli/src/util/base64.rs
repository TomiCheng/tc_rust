use std::io::{self, Write};

use clap::Args;
use tc_encoders::Encoder;
use tc_encoders::base64::{self, Base64};

#[derive(Args)]
pub(crate) struct Base64Args {
    /// Decode Base64 to bytes; whitespace is skipped
    #[arg(short, long)]
    decode: bool,
    /// Use the base64url alphabet of RFC 4648, with `-` and `_`
    #[arg(long)]
    url: bool,
    /// Leave out the `=` padding, as JWS does; needs --url
    #[arg(long, requires = "url")]
    no_pad: bool,
}

pub(crate) fn run(args: Base64Args) -> io::Result<()> {
    let encoder: Base64 = match (args.url, args.no_pad) {
        (false, _) => base64::DEFAULT,
        (true, false) => base64::RFC4648_URL,
        (true, true) => base64::RFC4648_URL_NO_PAD,
    };
    let mut input = io::stdin().lock();
    let mut out = io::stdout().lock();
    if args.decode {
        encoder.decode_from(&mut input, &mut out)?;
    } else {
        encoder.encode_from(&mut input, &mut out)?;
        writeln!(out)?;
    }
    out.flush()
}
