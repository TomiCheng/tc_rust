mod base64;
mod hex;
mod zlib;

use std::io;

use clap::Subcommand;

#[derive(Subcommand)]
pub(crate) enum UtilCommand {
    /// Base64-encode standard input, or decode it with -d
    Base64(base64::Base64Args),
    /// Hex-encode standard input, or decode it with -d
    Hex(hex::HexArgs),
    /// Compress standard input with zlib, or decompress it with -d
    Zlib(zlib::ZlibArgs),
}

pub(crate) fn run(command: UtilCommand) -> io::Result<()> {
    match command {
        UtilCommand::Base64(args) => base64::run(args),
        UtilCommand::Hex(args) => hex::run(args),
        UtilCommand::Zlib(args) => zlib::run(args),
    }
}
