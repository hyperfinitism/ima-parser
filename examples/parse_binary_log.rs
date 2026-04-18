// SPDX-License-Identifier: Apache-2.0

//! Read a binary IMA event log and print a summary of each event.
//!
//! Usage:
//!
//! ```sh
//! cargo run --example parse_binary_log -- <PATH> [--algo sha256] [--endian little|big] [--verify]
//! ```

use std::fs::File;
use std::io::BufReader;
use std::path::PathBuf;
use std::process::ExitCode;

use clap::{Parser, ValueEnum};
use ima_parser::hash::HashAlgorithm;
use ima_parser::log::{Endianness, EventLogParser, ParseOptions, TemplateData};

/// Parse a binary IMA event log and print a one-line summary per event.
#[derive(Debug, Parser)]
#[command(name = "parse_binary_log", about, version)]
struct Args {
    /// Path to the binary log
    /// (e.g. `/sys/kernel/security/ima/binary_runtime_measurements`).
    path: PathBuf,

    /// Hash algorithm used to recompute / verify each event's template hash.
    #[arg(long, value_enum, default_value_t = AlgoArg::Sha1)]
    algo: AlgoArg,

    /// Byte order of the integer fields in the log.
    #[arg(long, value_enum, default_value_t = EndianArg::Little)]
    endian: EndianArg,

    /// Recompute every event's template hash and print whether it matches.
    #[arg(long)]
    verify: bool,
}

#[derive(Debug, Clone, Copy, ValueEnum)]
enum AlgoArg {
    Sha1,
    Sha224,
    Sha256,
    Sha384,
    Sha512,
}

impl From<AlgoArg> for HashAlgorithm {
    fn from(a: AlgoArg) -> Self {
        match a {
            AlgoArg::Sha1 => HashAlgorithm::Sha1,
            AlgoArg::Sha224 => HashAlgorithm::Sha224,
            AlgoArg::Sha256 => HashAlgorithm::Sha256,
            AlgoArg::Sha384 => HashAlgorithm::Sha384,
            AlgoArg::Sha512 => HashAlgorithm::Sha512,
        }
    }
}

#[derive(Debug, Clone, Copy, ValueEnum)]
enum EndianArg {
    Little,
    Big,
}

impl From<EndianArg> for Endianness {
    fn from(e: EndianArg) -> Self {
        match e {
            EndianArg::Little => Endianness::Little,
            EndianArg::Big => Endianness::Big,
        }
    }
}

fn main() -> ExitCode {
    let args = Args::parse();
    let algo: HashAlgorithm = args.algo.into();

    let file = match File::open(&args.path) {
        Ok(f) => f,
        Err(e) => {
            eprintln!("cannot open {}: {e}", args.path.display());
            return ExitCode::from(1);
        }
    };

    let opts = ParseOptions::default()
        .with_endianness(args.endian.into())
        .with_template_hash_algorithm(algo);
    let parser = EventLogParser::new(BufReader::new(file), opts);

    for (i, ev) in parser.enumerate() {
        let ev = match ev {
            Ok(ev) => ev,
            Err(e) => {
                eprintln!("event {i}: parse error: {e}");
                return ExitCode::from(1);
            }
        };
        let hint = match &ev.template_data {
            TemplateData::Ima(e) => format!("{} (legacy ima)", e.filename),
            TemplateData::ImaNg(e) => format!("{} [{}]", e.filename, e.digest),
            TemplateData::ImaSig(e) => {
                format!("{} [{}] sig={}B", e.filename, e.digest, e.signature.len())
            }
            TemplateData::ImaBuf(e) => format!("{} [{}] buf={}B", e.name, e.digest, e.buf.len()),
            TemplateData::Unknown(fields) => format!("{} unknown-field(s)", fields.len()),
        };
        if args.verify {
            #[cfg(feature = "hash")]
            let ok = match ev.verify_template_hash(algo) {
                Some(true) => "true",
                Some(false) => "false",
                None => "unsupported-algo",
            };
            #[cfg(not(feature = "hash"))]
            let ok = "no-hash-feature";
            println!(
                "PCR={:>2}  {:<8}  hash-ok={}  {hint}",
                ev.pcr_index, ev.template_name, ok
            );
        } else {
            println!("PCR={:>2}  {:<8}  {hint}", ev.pcr_index, ev.template_name);
        }
    }
    ExitCode::SUCCESS
}
