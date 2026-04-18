// SPDX-License-Identifier: Apache-2.0

//! Error type used throughout this crate.

use std::io;

use thiserror::Error;

/// Convenient `Result` alias used across the crate.
pub type Result<T, E = Error> = std::result::Result<T, E>;

/// All errors that can occur while parsing IMA artefacts.
#[derive(Debug, Error)]
#[non_exhaustive]
pub enum Error {
    /// Underlying I/O error from the [`std::io::Read`] adapter.
    #[error("I/O error: {0}")]
    Io(#[from] io::Error),

    /// The byte stream ended in the middle of a record.
    ///
    /// `expected` is the number of bytes that were still required.
    #[error("unexpected end of input (need {expected} more byte(s) for {context})")]
    UnexpectedEof {
        /// Number of bytes that were still required.
        expected: usize,
        /// Free-form description of what was being decoded.
        context: &'static str,
    },

    /// A length field announced more bytes than the spec permits, so the
    /// parser refused to allocate them.
    #[error("invalid length {value} for {context} (limit {limit})")]
    InvalidLength {
        /// Length read from the stream.
        value: u64,
        /// Maximum length tolerated by the parser.
        limit: u64,
        /// Free-form description of which field overflowed.
        context: &'static str,
    },

    /// A field that should be UTF-8 (template name, file name, hash algorithm
    /// name, …) failed to decode.
    #[error("invalid UTF-8 in {context}")]
    InvalidUtf8 {
        /// Free-form description of which field is invalid.
        context: &'static str,
    },

    /// The hash-algorithm prefix in a `d-ng` style digest (e.g. `sha256:…`)
    /// did not match any known algorithm name.
    #[error("unknown hash algorithm `{0}`")]
    UnknownHashAlgorithm(String),

    /// The decoded `Template Data` length disagrees with the sum of the
    /// individual field lengths.
    #[error("template data length mismatch (header says {header}, fields total {fields})")]
    TemplateDataLengthMismatch {
        /// Length declared in the event header.
        header: usize,
        /// Sum of the per-field lengths.
        fields: usize,
    },

    /// Generic syntax error in the textual representation.
    #[error("parse error: {0}")]
    Parse(String),

    /// The text of an ASCII line/policy line had too few tokens.
    #[error("malformed line: {0}")]
    MalformedLine(String),
}

impl Error {
    /// Convenience constructor for [`Error::Parse`].
    pub fn parse<S: Into<String>>(s: S) -> Self {
        Self::Parse(s.into())
    }

    /// Convenience constructor for [`Error::MalformedLine`].
    pub fn malformed<S: Into<String>>(s: S) -> Self {
        Self::MalformedLine(s.into())
    }
}
