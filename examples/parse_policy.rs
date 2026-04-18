// SPDX-License-Identifier: Apache-2.0

//! Read an IMA policy file and pretty-print the parsed structure.
//!
//! Usage:
//!
//! ```sh
//! cargo run --example parse_policy -- <PATH>
//! ```

use std::fs;
use std::path::PathBuf;
use std::process::ExitCode;

use clap::Parser;
use ima_parser::policy::parse_policy;

/// Parse an IMA policy file and dump every rule.
#[derive(Debug, Parser)]
#[command(name = "parse_policy", about, version)]
struct Args {
    /// Path to the IMA policy file (e.g. `/etc/ima/ima-policy`).
    path: PathBuf,
}

fn main() -> ExitCode {
    let args = Args::parse();

    let text = match fs::read_to_string(&args.path) {
        Ok(t) => t,
        Err(e) => {
            eprintln!("cannot read {}: {e}", args.path.display());
            return ExitCode::from(1);
        }
    };
    let policy = match parse_policy(&text) {
        Ok(p) => p,
        Err(e) => {
            eprintln!("parse error: {e}");
            return ExitCode::from(1);
        }
    };
    for (i, rule) in policy.rules.iter().enumerate() {
        println!("rule {i:03}: {rule:#?}");
    }
    ExitCode::SUCCESS
}
