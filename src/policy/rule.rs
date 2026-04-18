// SPDX-License-Identifier: Apache-2.0

//! Data types describing a parsed IMA policy.
//!
//! The grammar follows the Linux kernel's
//! `Documentation/ABI/testing/ima_policy` and the parser in
//! `security/integrity/ima/ima_policy.c`. Every keyword and value documented
//! by the kernel maps to a dedicated enum variant; values the kernel would
//! reject (unknown `func=`, unknown `template=`, …) are still preserved
//! through `Other(String)` fallback variants so the parser can round-trip
//! future kernel additions without losing data.

use core::fmt;

use crate::hash::HashAlgorithm;

/// A full IMA policy: a sequence of [`Rule`]s preserved in source order.
#[derive(Debug, Default, Clone, PartialEq, Eq)]
pub struct Policy {
    /// Rules in the order they were written in the policy file.
    pub rules: Vec<Rule>,
}

/// A single rule.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Rule {
    /// Action keyword (`measure`, `dont_measure`, …).
    pub action: Action,
    /// Conditions that must match for the rule to apply.
    pub conditions: Vec<Condition>,
    /// Trailing options (`template=…`, `permit_directio`, `appraise_type=…`, …).
    pub options: Vec<Opt>,
}

impl Rule {
    /// Construct a rule with only an action and no conditions or options.
    #[must_use]
    pub fn new(action: Action) -> Self {
        Self {
            action,
            conditions: Vec::new(),
            options: Vec::new(),
        }
    }
}

// ---------------------------------------------------------------------------
// Action
// ---------------------------------------------------------------------------

/// Top-level action keyword of a rule.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum Action {
    /// `measure` – append a measurement to the event log.
    Measure,
    /// `dont_measure` – suppress measurement.
    DontMeasure,
    /// `appraise` – enforce a stored good value.
    Appraise,
    /// `dont_appraise` – suppress appraisal.
    DontAppraise,
    /// `audit` – write a line to the audit subsystem.
    Audit,
    /// `dont_audit` – suppress audit output.
    DontAudit,
    /// `hash` – compute and store a digest in `security.ima`.
    Hash,
    /// `dont_hash` – suppress storing the digest.
    DontHash,
}

impl Action {
    /// Parse an action keyword, returning `None` for unknown strings.
    #[must_use]
    pub fn parse(s: &str) -> Option<Self> {
        Some(match s {
            "measure" => Self::Measure,
            "dont_measure" => Self::DontMeasure,
            "appraise" => Self::Appraise,
            "dont_appraise" => Self::DontAppraise,
            "audit" => Self::Audit,
            "dont_audit" => Self::DontAudit,
            "hash" => Self::Hash,
            "dont_hash" => Self::DontHash,
            _ => return None,
        })
    }

    /// Canonical keyword for this action.
    #[must_use]
    pub const fn as_str(&self) -> &'static str {
        match self {
            Self::Measure => "measure",
            Self::DontMeasure => "dont_measure",
            Self::Appraise => "appraise",
            Self::DontAppraise => "dont_appraise",
            Self::Audit => "audit",
            Self::DontAudit => "dont_audit",
            Self::Hash => "hash",
            Self::DontHash => "dont_hash",
        }
    }
}

impl core::str::FromStr for Action {
    type Err = crate::error::Error;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        Self::parse(s)
            .ok_or_else(|| crate::error::Error::malformed(format!("unknown action `{s}`")))
    }
}

impl fmt::Display for Action {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

// ---------------------------------------------------------------------------
// Func
// ---------------------------------------------------------------------------

/// IMA `func=` target. Unknown values fall back to [`Func::Other`] so the
/// parser can still round-trip new kernel additions.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub enum Func {
    /// `BPRM_CHECK` – program execution via `execve`.
    BprmCheck,
    /// `MMAP_CHECK` – `mmap` with `PROT_EXEC`. Historical alias `FILE_MMAP`.
    MmapCheck,
    /// `MMAP_CHECK_REQPROT` – same as `MMAP_CHECK` for requested protection.
    MmapCheckReqprot,
    /// `CREDS_CHECK` – credential changes (`commit_creds`).
    CredsCheck,
    /// `FILE_CHECK` – open/read of a regular file. Historical alias `PATH_CHECK`.
    FileCheck,
    /// `MODULE_CHECK` – kernel-module load.
    ModuleCheck,
    /// `FIRMWARE_CHECK` – firmware blob load.
    FirmwareCheck,
    /// `KEXEC_KERNEL_CHECK` – kexec-load of a new kernel image.
    KexecKernelCheck,
    /// `KEXEC_INITRAMFS_CHECK` – kexec-load of the associated initramfs.
    KexecInitramfsCheck,
    /// `KEXEC_CMDLINE` – command-line string used for kexec.
    KexecCmdline,
    /// `POLICY_CHECK` – measure/appraise the IMA policy itself.
    PolicyCheck,
    /// `KEY_CHECK` – addition of a key to a keyring.
    KeyCheck,
    /// `CRITICAL_DATA` – ad-hoc critical-data buffers.
    CriticalData,
    /// `SETXATTR_CHECK` – `security.ima` xattr writes.
    SetxattrCheck,
    /// An unrecognised func name; preserved verbatim.
    Other(String),
}

impl Func {
    /// Parse a `func=` value. Unknown names are returned as
    /// [`Func::Other`] so round-tripping always succeeds.
    #[must_use]
    pub fn parse(s: &str) -> Self {
        match s {
            "BPRM_CHECK" => Self::BprmCheck,
            // FILE_MMAP is the historical name accepted by the kernel.
            "MMAP_CHECK" | "FILE_MMAP" => Self::MmapCheck,
            "MMAP_CHECK_REQPROT" => Self::MmapCheckReqprot,
            "CREDS_CHECK" => Self::CredsCheck,
            // PATH_CHECK is a historical alias.
            "FILE_CHECK" | "PATH_CHECK" => Self::FileCheck,
            "MODULE_CHECK" => Self::ModuleCheck,
            "FIRMWARE_CHECK" => Self::FirmwareCheck,
            "KEXEC_KERNEL_CHECK" => Self::KexecKernelCheck,
            "KEXEC_INITRAMFS_CHECK" => Self::KexecInitramfsCheck,
            "KEXEC_CMDLINE" => Self::KexecCmdline,
            "POLICY_CHECK" => Self::PolicyCheck,
            "KEY_CHECK" => Self::KeyCheck,
            "CRITICAL_DATA" => Self::CriticalData,
            "SETXATTR_CHECK" => Self::SetxattrCheck,
            other => Self::Other(other.to_owned()),
        }
    }

    /// Canonical keyword form. For unknown variants returns the preserved
    /// original string.
    #[must_use]
    pub fn as_str(&self) -> &str {
        match self {
            Self::BprmCheck => "BPRM_CHECK",
            Self::MmapCheck => "MMAP_CHECK",
            Self::MmapCheckReqprot => "MMAP_CHECK_REQPROT",
            Self::CredsCheck => "CREDS_CHECK",
            Self::FileCheck => "FILE_CHECK",
            Self::ModuleCheck => "MODULE_CHECK",
            Self::FirmwareCheck => "FIRMWARE_CHECK",
            Self::KexecKernelCheck => "KEXEC_KERNEL_CHECK",
            Self::KexecInitramfsCheck => "KEXEC_INITRAMFS_CHECK",
            Self::KexecCmdline => "KEXEC_CMDLINE",
            Self::PolicyCheck => "POLICY_CHECK",
            Self::KeyCheck => "KEY_CHECK",
            Self::CriticalData => "CRITICAL_DATA",
            Self::SetxattrCheck => "SETXATTR_CHECK",
            Self::Other(s) => s,
        }
    }
}

impl core::str::FromStr for Func {
    type Err = core::convert::Infallible;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        Ok(Self::parse(s))
    }
}

impl fmt::Display for Func {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

// ---------------------------------------------------------------------------
// Mask
// ---------------------------------------------------------------------------

/// One of the four `mask=` access bits documented in
/// `Documentation/ABI/testing/ima_policy`.
///
/// The kernel parser accepts only one bit per `mask=` clause (it does not
/// split on `|`), so this is a single value rather than a set.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum MaskBit {
    /// `MAY_EXEC`
    MayExec,
    /// `MAY_READ`
    MayRead,
    /// `MAY_WRITE`
    MayWrite,
    /// `MAY_APPEND`
    MayAppend,
}

impl MaskBit {
    /// Parse a bare mask name (without the leading `^`).
    #[must_use]
    pub fn parse(s: &str) -> Option<Self> {
        Some(match s {
            "MAY_EXEC" => Self::MayExec,
            "MAY_READ" => Self::MayRead,
            "MAY_WRITE" => Self::MayWrite,
            "MAY_APPEND" => Self::MayAppend,
            _ => return None,
        })
    }

    /// Canonical kernel keyword.
    #[must_use]
    pub const fn as_str(&self) -> &'static str {
        match self {
            Self::MayExec => "MAY_EXEC",
            Self::MayRead => "MAY_READ",
            Self::MayWrite => "MAY_WRITE",
            Self::MayAppend => "MAY_APPEND",
        }
    }
}

impl fmt::Display for MaskBit {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

/// Decoded `mask=` value: a single bit with optional `^` (NOT) prefix.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct Mask {
    /// Whether the value was prefixed with `^` (meaning "not").
    pub negated: bool,
    /// The selected mask bit.
    pub bit: MaskBit,
}

impl fmt::Display for Mask {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        if self.negated {
            f.write_str("^")?;
        }
        fmt::Display::fmt(&self.bit, f)
    }
}

// ---------------------------------------------------------------------------
// Numeric comparison operator (for uid/euid/gid/egid/fowner/fgroup)
// ---------------------------------------------------------------------------

/// Comparison operator for numeric identity conditions.
///
/// The kernel accepts `key=value`, `key<value`, and `key>value` for the six
/// identity conditions (`uid`, `euid`, `gid`, `egid`, `fowner`, `fgroup`).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum IdOp {
    /// `=` – exact match.
    Eq,
    /// `<` – less than.
    Lt,
    /// `>` – greater than.
    Gt,
}

impl IdOp {
    /// Single-character form used in the policy syntax.
    #[must_use]
    pub const fn as_str(&self) -> &'static str {
        match self {
            Self::Eq => "=",
            Self::Lt => "<",
            Self::Gt => ">",
        }
    }
}

impl fmt::Display for IdOp {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

// ---------------------------------------------------------------------------
// Condition
// ---------------------------------------------------------------------------

/// A single condition inside a rule.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Condition {
    /// `func=<FUNC>`
    Func(Func),
    /// `mask[=^]<BIT>`
    Mask(Mask),
    /// `fsmagic=<HEX>` – filesystem magic number.
    Fsmagic(u64),
    /// `fsuuid=<UUID>`
    Fsuuid(String),
    /// `fsname=<STR>`
    Fsname(String),
    /// `fs_subtype=<STR>`
    FsSubtype(String),
    /// `uid<op><DEC>`
    Uid {
        /// Comparison operator.
        op: IdOp,
        /// Numeric UID.
        value: u32,
    },
    /// `euid<op><DEC>`
    Euid {
        /// Comparison operator.
        op: IdOp,
        /// Numeric EUID.
        value: u32,
    },
    /// `gid<op><DEC>`
    Gid {
        /// Comparison operator.
        op: IdOp,
        /// Numeric GID.
        value: u32,
    },
    /// `egid<op><DEC>`
    Egid {
        /// Comparison operator.
        op: IdOp,
        /// Numeric EGID.
        value: u32,
    },
    /// `fowner<op><DEC>`
    Fowner {
        /// Comparison operator.
        op: IdOp,
        /// File-owner UID.
        value: u32,
    },
    /// `fgroup<op><DEC>`
    Fgroup {
        /// Comparison operator.
        op: IdOp,
        /// File-group GID.
        value: u32,
    },
    /// `subj_user=<STR>` – LSM subject user.
    SubjUser(String),
    /// `subj_role=<STR>`
    SubjRole(String),
    /// `subj_type=<STR>`
    SubjType(String),
    /// `obj_user=<STR>` – LSM object user.
    ObjUser(String),
    /// `obj_role=<STR>`
    ObjRole(String),
    /// `obj_type=<STR>`
    ObjType(String),
}

// ---------------------------------------------------------------------------
// Option values
// ---------------------------------------------------------------------------

/// `digest_type=` value.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub enum DigestType {
    /// `verity` – use fs-verity's file digest instead of the regular IMA hash.
    Verity,
    /// An unrecognised value; preserved verbatim.
    Other(String),
}

impl DigestType {
    /// Parse a `digest_type=` value.
    #[must_use]
    pub fn parse(s: &str) -> Self {
        match s {
            "verity" => Self::Verity,
            other => Self::Other(other.to_owned()),
        }
    }

    /// Canonical string form.
    #[must_use]
    pub fn as_str(&self) -> &str {
        match self {
            Self::Verity => "verity",
            Self::Other(s) => s,
        }
    }
}

impl fmt::Display for DigestType {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

/// `appraise_type=` value.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub enum AppraiseType {
    /// `imasig` – original / v2 IMA signature in `security.ima`.
    Imasig,
    /// `imasig|modsig` – `imasig` with appended kernel-module style signature
    /// allowed.
    ImasigModsig,
    /// `sigv3` – signature format version 3.
    Sigv3,
    /// An unrecognised value; preserved verbatim.
    Other(String),
}

impl AppraiseType {
    /// Parse an `appraise_type=` value.
    #[must_use]
    pub fn parse(s: &str) -> Self {
        match s {
            "imasig" => Self::Imasig,
            "imasig|modsig" => Self::ImasigModsig,
            "sigv3" => Self::Sigv3,
            other => Self::Other(other.to_owned()),
        }
    }

    /// Canonical string form.
    #[must_use]
    pub fn as_str(&self) -> &str {
        match self {
            Self::Imasig => "imasig",
            Self::ImasigModsig => "imasig|modsig",
            Self::Sigv3 => "sigv3",
            Self::Other(s) => s,
        }
    }
}

impl fmt::Display for AppraiseType {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

/// `appraise_flag=` value. The kernel currently logs but ignores this option;
/// the only documented value is `check_blacklist`, kept here for round-trip.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub enum AppraiseFlag {
    /// `check_blacklist` – deprecated; appraisal already checks the
    /// blacklist by default.
    CheckBlacklist,
    /// An unrecognised value; preserved verbatim.
    Other(String),
}

impl AppraiseFlag {
    /// Parse an `appraise_flag=` value.
    #[must_use]
    pub fn parse(s: &str) -> Self {
        match s {
            "check_blacklist" => Self::CheckBlacklist,
            other => Self::Other(other.to_owned()),
        }
    }

    /// Canonical string form.
    #[must_use]
    pub fn as_str(&self) -> &str {
        match self {
            Self::CheckBlacklist => "check_blacklist",
            Self::Other(s) => s,
        }
    }
}

impl fmt::Display for AppraiseFlag {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

/// One entry of an `appraise_algos=` comma-separated list. Known algorithm
/// names map to [`HashAlgorithm`]; unknown ones are preserved verbatim.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub enum AppraiseAlgo {
    /// A recognised hash algorithm.
    Algorithm(HashAlgorithm),
    /// An unrecognised algorithm name; preserved verbatim.
    Other(String),
}

impl AppraiseAlgo {
    /// Parse a single algorithm name.
    #[must_use]
    pub fn parse(s: &str) -> Self {
        match HashAlgorithm::from_name(s) {
            Ok(a) => Self::Algorithm(a),
            Err(_) => Self::Other(s.to_owned()),
        }
    }

    /// Canonical string form.
    #[must_use]
    pub fn as_str(&self) -> &str {
        match self {
            Self::Algorithm(a) => a.name(),
            Self::Other(s) => s,
        }
    }
}

impl fmt::Display for AppraiseAlgo {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

/// `template=` value. Lists every template documented by
/// `Documentation/security/IMA-templates.rst`; unknown names fall back to
/// [`Template::Other`].
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub enum Template {
    /// `ima` – legacy 20-byte digest + 256-byte zero-padded name.
    Ima,
    /// `ima-ng` – `d-ng | n-ng`.
    ImaNg,
    /// `ima-ngv2` – `d-ngv2 | n-ng`. Adds digest type prefix.
    ImaNgv2,
    /// `ima-sig` – `d-ng | n-ng | sig`.
    ImaSig,
    /// `ima-sigv2` – `d-ngv2 | n-ng | sig`.
    ImaSigv2,
    /// `ima-sigv3` – signature format v3 variant referenced in
    /// `Documentation/ABI/testing/ima_policy`.
    ImaSigv3,
    /// `ima-buf` – `d-ng | n-ng | buf`.
    ImaBuf,
    /// `ima-modsig` – `d-ng | n-ng | sig | d-modsig | modsig`.
    ImaModsig,
    /// `evm-sig` – the EVM portable signature template.
    EvmSig,
    /// An unrecognised template name; preserved verbatim.
    Other(String),
}

impl Template {
    /// Parse a `template=` value.
    #[must_use]
    pub fn parse(s: &str) -> Self {
        match s {
            "ima" => Self::Ima,
            "ima-ng" => Self::ImaNg,
            "ima-ngv2" => Self::ImaNgv2,
            "ima-sig" => Self::ImaSig,
            "ima-sigv2" => Self::ImaSigv2,
            "ima-sigv3" => Self::ImaSigv3,
            "ima-buf" => Self::ImaBuf,
            "ima-modsig" => Self::ImaModsig,
            "evm-sig" => Self::EvmSig,
            other => Self::Other(other.to_owned()),
        }
    }

    /// Canonical string form.
    #[must_use]
    pub fn as_str(&self) -> &str {
        match self {
            Self::Ima => "ima",
            Self::ImaNg => "ima-ng",
            Self::ImaNgv2 => "ima-ngv2",
            Self::ImaSig => "ima-sig",
            Self::ImaSigv2 => "ima-sigv2",
            Self::ImaSigv3 => "ima-sigv3",
            Self::ImaBuf => "ima-buf",
            Self::ImaModsig => "ima-modsig",
            Self::EvmSig => "evm-sig",
            Self::Other(s) => s,
        }
    }
}

impl fmt::Display for Template {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

/// One entry of a `label=` pipe-separated list (used with
/// `func=CRITICAL_DATA`).
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub enum LabelEntry {
    /// `selinux` – critical data emitted by SELinux.
    Selinux,
    /// `kernel_info` – critical data describing the kernel itself.
    KernelInfo,
    /// Any other unique grouping/limiting label.
    Custom(String),
}

impl LabelEntry {
    /// Parse a single label entry.
    #[must_use]
    pub fn parse(s: &str) -> Self {
        match s {
            "selinux" => Self::Selinux,
            "kernel_info" => Self::KernelInfo,
            other => Self::Custom(other.to_owned()),
        }
    }

    /// Canonical string form.
    #[must_use]
    pub fn as_str(&self) -> &str {
        match self {
            Self::Selinux => "selinux",
            Self::KernelInfo => "kernel_info",
            Self::Custom(s) => s,
        }
    }
}

impl fmt::Display for LabelEntry {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

// ---------------------------------------------------------------------------
// Option (renamed to `Opt` to avoid clashing with `core::option::Option`)
// ---------------------------------------------------------------------------

/// A single option inside a rule.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Opt {
    /// `digest_type=<VAL>`
    DigestType(DigestType),
    /// `template=<NAME>` – e.g. `ima-ng`, `ima-sig`, `ima-buf`. Only valid
    /// when `action == measure`, but the parser does not enforce that here.
    Template(Template),
    /// `permit_directio` – flag, no value.
    PermitDirectio,
    /// `appraise_type=<VAL>`
    AppraiseType(AppraiseType),
    /// `appraise_flag=<VAL>`
    AppraiseFlag(AppraiseFlag),
    /// `appraise_algos=<COMMA,LIST>` – allowed algorithms for
    /// `security.ima`.
    AppraiseAlgos(Vec<AppraiseAlgo>),
    /// `keyrings=<PIPE|LIST>` – e.g. `.builtin_trusted_keys|.ima`.
    Keyrings(Vec<String>),
    /// `label=<PIPE|LIST>` – grouping for `CRITICAL_DATA` rules.
    Label(Vec<LabelEntry>),
    /// `pcr=<DEC>` – override destination PCR for measurements.
    Pcr(u32),
    /// Any other `key=value` pair we don't model as a dedicated variant.
    Other {
        /// Left-hand side of the `=`.
        key: String,
        /// Right-hand side of the `=`.
        value: String,
    },
    /// A bare flag (no `=`) that the parser didn't recognise.
    Flag(String),
}
