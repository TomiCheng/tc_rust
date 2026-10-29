//! 和 Python 的 `zlib` 模組（參考實作）互相比對；向量由 `tests/data/python/` 提供。

use std::fs;
use std::io::{Read, Write};
use std::path::Path;

use tc_zlib::{CompressionLevel, DeflateOptions, InflateOptions, Strategy, ZlibReader, ZlibWriter};

fn noise(len: usize) -> Vec<u8> {
    let mut x: u32 = 1;
    (0..len)
        .map(|_| {
            x = x.wrapping_mul(1_103_515_245).wrapping_add(12_345);
            (x >> 16) as u8
        })
        .collect()
}

fn data() -> [(&'static str, Vec<u8>); 4] {
    [
        (
            "text",
            b"The quick brown fox jumps over the lazy dog. ".repeat(1000),
        ),
        ("bytes", (0..=255u8).collect::<Vec<_>>().repeat(3)),
        (
            "runs",
            [
                b"a".repeat(4),
                b"b".repeat(5),
                b"c".repeat(259),
                b"d".repeat(1000),
            ]
            .concat(),
        ),
        ("noise", noise(5000)),
    ]
}

fn cases() -> [(u8, &'static str, bool); 9] {
    [
        (0, "default", false),
        (1, "default", false),
        (6, "default", false),
        (9, "default", false),
        (6, "filtered", false),
        (6, "huffman", false),
        (6, "rle", false),
        (6, "fixed", false),
        (6, "default", true),
    ]
}

fn options(level: u8, strategy: &str, raw: bool) -> DeflateOptions {
    let level = match level {
        0 => CompressionLevel::None,
        1 => CompressionLevel::BestSpeed,
        6 => CompressionLevel::Default,
        _ => CompressionLevel::BestCompression,
    };
    let strategy = match strategy {
        "default" => Strategy::Default,
        "filtered" => Strategy::Filtered,
        "huffman" => Strategy::HuffmanOnly,
        "rle" => Strategy::Rle,
        _ => Strategy::Fixed,
    };
    DeflateOptions::default()
        .level(level)
        .strategy(strategy)
        .nowrap(raw)
}

fn vector(name: &str, level: u8, strategy: &str, raw: bool) -> Vec<u8> {
    let suffix = if raw { "deflate" } else { "zlib" };
    let path = Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("tests/data/python")
        .join(format!("{name}_{level}_{strategy}.{suffix}"));
    fs::read(&path).unwrap_or_else(|e| panic!("{}: {e}", path.display()))
}

#[test]
fn streams_from_python_zlib_decompress_to_their_contents() {
    let mut wrong = Vec::new();
    for (name, plain) in data() {
        for (level, strategy, raw) in cases() {
            let mut writer =
                ZlibWriter::decompress(Vec::new(), InflateOptions::default().nowrap(raw));
            let out = writer
                .write_all(&vector(name, level, strategy, raw))
                .and_then(|()| writer.finish());
            if out.as_deref().ok() != Some(&plain[..]) {
                wrong.push(format!("{name} {level} {strategy} raw={raw}"));
            }
        }
    }
    assert!(wrong.is_empty(), "{wrong:#?}");
}

#[test]
fn streams_from_python_zlib_read_back_through_tiny_buffers() {
    let mut wrong = Vec::new();
    for (name, plain) in data() {
        for (level, strategy, raw) in cases() {
            let stream = vector(name, level, strategy, raw);
            for size in [1, 7, 300] {
                let options = InflateOptions::default().nowrap(raw).buf_size(size);
                let mut reader = ZlibReader::decompress(&stream[..], options);
                let mut out = Vec::new();
                let mut chunk = vec![0; size];
                let result = loop {
                    match reader.read(&mut chunk) {
                        Ok(0) => break Ok(()),
                        Ok(n) => out.extend_from_slice(&chunk[..n]),
                        Err(e) => break Err(e),
                    }
                };
                if result.is_err() || out != plain {
                    wrong.push(format!(
                        "{name} {level} {strategy} raw={raw} by {size}: {result:?}"
                    ));
                }
            }
        }
    }
    assert!(wrong.is_empty(), "{wrong:#?}");
}

#[test]
fn compressing_gives_the_same_bytes_as_python_zlib() {
    let mut wrong = Vec::new();
    for (name, plain) in data() {
        for (level, strategy, raw) in cases() {
            let mut writer = ZlibWriter::compress(Vec::new(), options(level, strategy, raw));
            writer.write_all(&plain).unwrap();
            let ours = writer.finish().unwrap();
            let theirs = vector(name, level, strategy, raw);
            if ours != theirs {
                wrong.push(format!(
                    "{name} {level} {strategy} raw={raw}: {} vs {} bytes",
                    ours.len(),
                    theirs.len()
                ));
            }
        }
    }
    assert!(wrong.is_empty(), "{wrong:#?}");
}

const WORDS: &str = "alpha beta gamma delta epsilon zeta eta theta iota kappa lambda mu nu xi \
    omicron pi rho sigma tau upsilon phi chi psi omega zlib deflate inflate window match \
    literal huffman tree block stored fixed dynamic length distance code bits byte stream";

/// 300 KB 的字詞夾雜雜訊：超過視窗兩倍，會滑動視窗並切成多個區塊。
fn large() -> Vec<u8> {
    let words: Vec<&str> = WORDS.split_whitespace().collect();
    let mut x: u32 = 7;
    let mut out = Vec::new();
    while out.len() < 300_000 {
        x = x.wrapping_mul(1_103_515_245).wrapping_add(12_345);
        let r = x >> 16;
        if r % 17 == 0 {
            out.extend((0..8).step_by(3).map(|i| (r >> i) as u8));
        } else {
            out.extend_from_slice(words[r as usize % words.len()].as_bytes());
            out.push(b' ');
        }
    }
    out.truncate(300_000);
    out
}

fn fnv(data: &[u8]) -> u64 {
    data.iter().fold(0xcbf2_9ce4_8422_2325, |h, &b| {
        (h ^ u64::from(b)).wrapping_mul(0x0100_0000_01b3)
    })
}

#[test]
fn a_large_input_compresses_like_python_zlib_whatever_the_buffer_sizes() {
    let plain = large();
    assert_eq!(fnv(&plain), 0x2c6e_63e6_ab80_16ed);
    let mut wrong = Vec::new();
    for (level, strategy, raw, len, hash) in [
        (1, "default", false, 91_961, 0x614f_43e7_b79b_673e),
        (6, "default", false, 72_888, 0x17dc_7319_ef40_0713),
        (9, "default", false, 72_533, 0xb901_4c98_54aa_5591),
        (6, "filtered", false, 73_964, 0xdae1_8941_adcd_9687),
        (6, "huffman", false, 168_095, 0xe552_735e_206a_0423),
        (6, "rle", false, 168_095, 0xe552_735e_206a_0423),
        (6, "fixed", false, 85_298, 0x0a4e_4b81_d95d_8892),
        (9, "default", true, 72_527, 0x4571_8322_f355_d863),
    ] {
        for size in [1, 7, 4096, 100_000] {
            let options = options(level, strategy, raw).buf_size(size);
            let mut writer = ZlibWriter::compress(Vec::new(), options.clone());
            for chunk in plain.chunks(9_999) {
                writer.write_all(chunk).unwrap();
            }
            let written = writer.finish().unwrap();
            let mut read = Vec::new();
            ZlibReader::compress(&plain[..], options)
                .read_to_end(&mut read)
                .unwrap();
            for (how, ours) in [("writer", written), ("reader", read)] {
                if (ours.len(), fnv(&ours)) != (len, hash) {
                    wrong.push(format!("{how} {level} {strategy} raw={raw} by {size}"));
                }
            }
        }
    }
    assert!(wrong.is_empty(), "{wrong:#?}");
}

#[test]
fn a_large_input_stored_without_compression_reads_back_whatever_the_buffer_sizes() {
    // stored 區塊的切法依輸出緩衝區大小而定，所以只驗證能解回原文。
    let plain = large();
    for size in [1, 7, 4096, 100_000] {
        let mut writer =
            ZlibWriter::compress(Vec::new(), options(0, "default", false).buf_size(size));
        writer.write_all(&plain).unwrap();
        let stored = writer.finish().unwrap();
        assert!(stored.len() > plain.len(), "by {size}");
        let mut writer = ZlibWriter::decompress(Vec::new(), InflateOptions::default());
        writer.write_all(&stored).unwrap();
        assert_eq!(writer.finish().unwrap(), plain, "by {size}");
    }
}
