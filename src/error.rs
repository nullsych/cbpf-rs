//! Error types shared by every compilation stage.

use alloc::string::String;
use core::fmt;
use core::ops::Range;

/// A byte-offset range into the source string passed to [`crate::compile`].
pub type Offset = Range<usize>;

/// The specific reason a compilation failed.
///
/// `non_exhaustive` because new pcap-filter constructs (later grammar phases) will need new
/// variants, and that must not be a breaking change for downstream `match`es.
#[non_exhaustive]
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ErrorTag {
    /// The lexer found a character it doesn't know how to start a token with.
    UnexpectedChar(char),
    /// The parser expected one of a specific set of tokens but found something else.
    UnexpectedToken {
        expected: &'static str,
        found: String,
    },
    /// The parser ran out of tokens while still expecting more input.
    UnexpectedEof { expected: &'static str },
    /// A word token isn't a keyword the MVP grammar recognizes in this position.
    UnknownKeyword(String),
    /// Text that was expected to be an IPv4 address/CIDR literal didn't parse as one.
    InvalidIPv4Literal(String),
    /// Text that was expected to be a port number didn't parse as one (or is out of range).
    InvalidPortNumber(String),
    /// A `portrange` primitive had `lo > hi`.
    InvalidPortRange { lo: u32, hi: u32 },
    /// A `(` was never closed, or a `)` had no matching `(`.
    UnbalancedParens,
    /// The source was empty (or contained only whitespace).
    EmptyExpression,
    /// A `jt`/`jf` displacement didn't fit in the 8-bit field cBPF allows.
    ///
    /// This is a real compile-time limit, not a bug: cBPF jump targets for conditional branches are
    /// one byte, so an expression that ORs together roughly 85+ primitives can legitimately overflow
    /// it. See the project's implementation plan for why this is reported as an error rather than
    /// resolved via long-jump splitting.
    JumpDisplacementOverflow {
        inst_index: usize,
        displacement: u32,
    },
    /// `compile()` was asked for a [`crate::LinkType`] that has no support yet.
    UnsupportedLinkType,
    /// The construct parsed but program generation for it isn't implemented yet (e.g. IPv6 address literals).
    Unimplemented(&'static str),
    /// A syntactically valid `proto`/`type` pairing that doesn't mean anything (e.g. `arp port 80` -
    /// ARP has no notion of a port).
    InvalidPrimitiveCombination(&'static str),
}

impl fmt::Display for ErrorTag {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            ErrorTag::UnexpectedChar(c) => write!(f, "unexpected character '{c}'"),

            ErrorTag::UnexpectedToken { expected, found } => {
                write!(f, "expected {expected}, found '{found}'")
            }

            ErrorTag::UnexpectedEof { expected } => {
                write!(f, "expected {expected}, found end of input")
            }

            ErrorTag::UnknownKeyword(word) => write!(f, "unknown keyword '{word}'"),

            ErrorTag::InvalidIPv4Literal(text) => {
                write!(f, "'{text}' is not a valid IPv4 address or network")
            }

            ErrorTag::InvalidPortNumber(text) => write!(f, "'{text}' is not a valid port number"),

            ErrorTag::InvalidPortRange { lo, hi } => {
                write!(
                    f,
                    "invalid port range {lo}-{hi}: lower bound exceeds upper bound"
                )
            }

            ErrorTag::UnbalancedParens => write!(f, "unbalanced parentheses"),

            ErrorTag::EmptyExpression => write!(f, "empty filter expression"),

            ErrorTag::JumpDisplacementOverflow {
                inst_index,
                displacement,
            } => write!(
                f,
                "jump at instruction {inst_index} has displacement {displacement}, which exceeds the 8-bit cBPF jt/jf limit of 255; split the expression into a smaller one"
            ),

            ErrorTag::UnsupportedLinkType => {
                write!(f, "this link type has no support yet")
            }

            ErrorTag::Unimplemented(what) => write!(f, "{what} is not implemented yet"),

            ErrorTag::InvalidPrimitiveCombination(msg) => write!(f, "{msg}"),
        }
    }
}

/// A compilation failure, with the source offset it applies to.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CompileError {
    pub offset: Offset,
    pub tag: ErrorTag,
}

impl CompileError {
    pub(crate) fn new(offset: Offset, tag: ErrorTag) -> Self {
        CompileError { offset, tag }
    }
}

impl fmt::Display for CompileError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "{} (at {}..{})",
            self.tag, self.offset.start, self.offset.end
        )
    }
}

// `core::error::Error` has been stable since Rust 1.81, and this crate's `edition = "2024"` already
// requires rustc >= 1.85, so there's no MSRV reason to gate this behind `feature = "std"` - it's
// available unconditionally, no_std included.
impl core::error::Error for CompileError {}
