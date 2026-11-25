use std::io::{self, Write};

use clap::{Args, ValueEnum};
use tc_zlib::{CompressionLevel, DeflateOptions, InflateOptions, ZlibWriter};

#[derive(Args)]
pub(crate) struct ZlibArgs {
    /// Decompress instead of compressing
    #[arg(short, long)]
    decompress: bool,
    /// Raw deflate, without the zlib header and checksum
    #[arg(long)]
    raw: bool,
    /// Compression level
    #[arg(long, value_enum, default_value_t = Level::Default, conflicts_with = "decompress")]
    level: Level,
}

#[derive(Clone, Copy, ValueEnum)]
enum Level {
    /// Store the input without compressing it
    None,
    /// Favour speed
    Fast,
    /// The zlib default, level 6
    Default,
    /// Favour size
    Best,
}

pub(crate) fn run(args: ZlibArgs) -> io::Result<()> {
    let out = io::stdout().lock();
    let mut writer = if args.decompress {
        ZlibWriter::decompress(out, InflateOptions::default().nowrap(args.raw))
    } else {
        let level = match args.level {
            Level::None => CompressionLevel::None,
            Level::Fast => CompressionLevel::BestSpeed,
            Level::Default => CompressionLevel::Default,
            Level::Best => CompressionLevel::BestCompression,
        };
        ZlibWriter::compress(out, DeflateOptions::default().level(level).nowrap(args.raw))
    };
    io::copy(&mut io::stdin().lock(), &mut writer)?;
    writer.finish()?.flush()
}
