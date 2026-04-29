// SPDX-License-Identifier: Apache-2.0

//! Read an ASCII IMA event log and print a summary of each event.
//!
//! Usage:
//!
//! ```sh
//! cargo run --example parse_ascii_log -- <PATH> [--algo sha256] [--verify]
//! ```

use std::fs;
use std::path::PathBuf;
use std::process::ExitCode;

use clap::{Parser, ValueEnum};
use ima_parser::hash::HashAlgorithm;
use ima_parser::log::{TemplateData, parse_ascii_log};

/// Parse an ASCII IMA event log
/// (`/sys/kernel/security/ima/ascii_runtime_measurements[_<algo>]`).
#[derive(Debug, Parser)]
#[command(name = "parse_ascii_log", about, version)]
struct Args {
    /// Path to the ASCII log. Use `-` to read from standard input.
    path: PathBuf,

    /// Algorithm assumed when re-computing the per-event template hash with
    /// `--verify`. Defaults to SHA-1, the algorithm of the legacy
    /// `ascii_runtime_measurements` file.
    #[arg(long, value_enum, default_value_t = AlgoArg::Sha1)]
    algo: AlgoArg,

    /// Recompute every event's template hash and print whether the stored
    /// digest matches the recomputation.
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

fn read_input(path: &PathBuf) -> std::io::Result<String> {
    if path.as_os_str() == "-" {
        let mut s = String::new();
        std::io::Read::read_to_string(&mut std::io::stdin().lock(), &mut s)?;
        Ok(s)
    } else {
        fs::read_to_string(path)
    }
}

fn main() -> ExitCode {
    let args = Args::parse();
    let algo: HashAlgorithm = args.algo.into();

    let text = match read_input(&args.path) {
        Ok(t) => t,
        Err(e) => {
            eprintln!("cannot read {}: {e}", args.path.display());
            return ExitCode::from(1);
        }
    };

    let events = match parse_ascii_log(&text) {
        Ok(e) => e,
        Err(e) => {
            eprintln!("parse error: {e}");
            return ExitCode::from(1);
        }
    };

    for ev in &events {
        let hint = match &ev.template_data {
            TemplateData::Ima(e) => format!("{} (legacy ima)", e.filename),
            TemplateData::ImaNg(e) => format!("{} [{}]", e.filename, e.digest),
            TemplateData::ImaSig(e) => {
                format!("{} [{}] sig={}B", e.filename, e.digest, e.signature.len())
            }
            TemplateData::ImaBuf(e) => format!("{} [{}] buf={}B", e.name, e.digest, e.buf.len()),
            TemplateData::Unknown(fields) => format!("{} unknown-field(s)", fields.len()),
            _ => "other built-in template".to_owned(),
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
                ev.pcr_index,
                ev.template.as_str(),
                ok
            );
        } else {
            println!(
                "PCR={:>2}  {:<8}  {hint}",
                ev.pcr_index,
                ev.template.as_str()
            );
        }
    }
    ExitCode::SUCCESS
}
