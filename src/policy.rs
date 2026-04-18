// SPDX-License-Identifier: Apache-2.0

//! IMA policy definitions and parser.
//!
//! An IMA policy is an ordered list of rules that the kernel evaluates
//! (first-match wins per file access). Each rule has an *action*, zero or
//! more *conditions*, and zero or more *options*. The grammar is described
//! by `Documentation/ABI/testing/ima_policy` in the kernel:
//!
//! ```bnf
//! rule      ::= action [condition ...] [option ...]
//! action    ::= measure | dont_measure | appraise | dont_appraise |
//!              audit   | dont_audit   | hash     | dont_hash
//! condition ::= func=<FUNC> | mask=[^]<BIT> | fsmagic=<HEX>
//!            | fsuuid=<UUID> | fsname=<STR> | fs_subtype=<STR>
//!            | uid<OP><DEC> | euid<OP><DEC> | gid<OP><DEC> | egid<OP><DEC>
//!            | fowner<OP><DEC> | fgroup<OP><DEC>     ; OP is one of `= < >`
//!            | subj_user=<STR>|subj_role=<STR>|subj_type=<STR>
//!            | obj_user=<STR> |obj_role=<STR> |obj_type=<STR>
//! option    ::= digest_type=<VAL> | template=<NAME>
//!            | permit_directio | appraise_type=<VAL>
//!            | appraise_flag=<VAL> | appraise_algos=<COMMA,LIST>
//!            | keyrings=<PIPE|LIST> | label=<PIPE|LIST>
//!            | pcr=<DEC>
//! ```
//!
//! Lines that are blank or begin with `#` are ignored.
//!
//! Every documented keyword and value maps to a strongly-typed enum variant;
//! values not currently recognised by the parser are preserved through
//! `Other(String)` fallback variants for round-tripping new kernel additions.

mod parser;
mod rule;

pub use self::parser::{parse_policy, parse_policy_line};
pub use self::rule::{
    Action, AppraiseAlgo, AppraiseFlag, AppraiseType, Condition, DigestType, Func, IdOp,
    LabelEntry, Mask, MaskBit, Opt, Policy, Rule, Template,
};
