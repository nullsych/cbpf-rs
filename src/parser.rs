//! Recursive-descent parser: [`Token`]s -> [`Expr`].
//!
//! Precedence from tightest to loosest: `not`, `and`, `or`. Parentheses override it.
//!
//! A primitive is `[proto] [dir] type value`. The type keyword (`host`, `net`, `port`,
//! `portrange`) is required, so a bare `tcp` does not parse - every primitive has to say
//! what it matches on.

use crate::ast::{AddrLit, DirTag, Expr, PrimType, Primitive, ProtoTag};
use crate::error::{CompileError, ErrorTag, Offset};
use crate::lexer::{Token, TokenTag};
use alloc::boxed::Box;
use alloc::string::{String, ToString};

pub(crate) fn parse(tokens: &[Token]) -> Result<Expr, CompileError> {
    // check if tokens are not empty (""), just first TokenTag
    let first_tag: Option<&TokenTag> = tokens.first().map(|t| &t.tag);

    if matches!(first_tag, Some(TokenTag::Eof)) {
        // extract offset and tag it as an `EmptyExpression` (see `empty_expression_is_an_error` tests)
        let offset = tokens.first().map(|t| t.offset.clone()).unwrap_or(0..0);

        // for ""  -> offset == 0..0
        // for " " -> offset == 3..3
        return Err(CompileError::new(offset, ErrorTag::EmptyExpression));
    }

    // else - create a parser from the valid tokens
    let mut parser = Parser { tokens, pos: 0 };

    // and then we  perform nested parsing: parse_or -> parse_and -> parse_unary -> parse_primary
    // for example: "a and b and c"
    //      step 1: lhs = and(a, b)
    //      step 2: lhs = and(and(a, b), c)
    let expr = parser.parse_or()?;

    // check for unparsed tokens and parser finished in EOF
    parser.expect_eof()?;
    Ok(expr)
}

struct Parser<'tok> {
    tokens: &'tok [Token], // we set lifetime guarantee: parser's lifetime <= borrowed token's lifetime
    pos: usize,
}

/// Extracts `offset` from known `expression`.
fn offset_from_expr(e: &Expr) -> Offset {
    match e {
        // get simple primitive offset
        Expr::Primitive(p) => p.offset.clone(),
        // get other
        Expr::Not(_, s) | Expr::And(_, _, s) | Expr::Or(_, _, s) => s.clone(),
    }
}

/// Render a token as the text to quote in a "found `...`" error message.
fn token_text(t: &Token) -> String {
    match &t.tag {
        TokenTag::Word(w) => w.clone(),
        TokenTag::Dash => "-".to_string(),
        TokenTag::LParen => "(".to_string(),
        TokenTag::RParen => ")".to_string(),
        TokenTag::Eof => "end of input".to_string(),
    }
}

impl<'a> Parser<'a> {
    /// Get token at the current position
    fn peek(&self) -> &Token {
        return &self.tokens[self.pos];
    }

    /// Return the current token and step forward one position, stopping on the final `Eof`
    fn advance(&mut self) -> &Token {
        let t = &self.tokens[self.pos];
        if self.pos + 1 < self.tokens.len() {
            self.pos += 1;
        }
        return t;
    }

    /// Get the current token's text if it is a [`TokenTag::Word`], else `None`.
    fn word(&self) -> Option<&str> {
        match &self.peek().tag {
            TokenTag::Word(w) => Some(w.as_str()),
            _ => None,
        }
    }

    /// Require that parsing consumed the whole input: the current token must be [`TokenTag::Eof`].
    fn expect_eof(&self) -> Result<(), CompileError> {
        match &self.peek().tag {
            TokenTag::Eof => Ok(()),
            _ => Err(CompileError::new(
                self.peek().offset.clone(),
                ErrorTag::UnexpectedToken {
                    expected: "'and', 'or', or end of input",
                    found: token_text(self.peek()),
                },
            )),
        }
    }

    /// Consume the current token, requiring it to be a [`TokenTag::Word`]; returns its text and offset.
    fn expect_word(&mut self, expected: &'static str) -> Result<(String, Offset), CompileError> {
        match self.peek().tag.clone() {
            TokenTag::Word(w) => {
                let offset = self.peek().offset.clone();
                self.advance();
                Ok((w, offset))
            }
            TokenTag::Eof => Err(CompileError::new(
                self.peek().offset.clone(),
                ErrorTag::UnexpectedEof { expected },
            )),
            _ => Err(CompileError::new(
                self.peek().offset.clone(),
                ErrorTag::UnexpectedToken {
                    expected,
                    found: token_text(self.peek()),
                },
            )),
        }
    }

    /// Consume the current token, requiring it to be [`TokenTag::Dash`] (the `-` in a `portrange`).
    fn expect_dash(&mut self) -> Result<(), CompileError> {
        match self.peek().tag {
            TokenTag::Dash => {
                self.advance();
                Ok(())
            }
            TokenTag::Eof => Err(CompileError::new(
                self.peek().offset.clone(),
                ErrorTag::UnexpectedEof {
                    expected: "'-' in a port range",
                },
            )),
            _ => Err(CompileError::new(
                self.peek().offset.clone(),
                ErrorTag::UnexpectedToken {
                    expected: "'-' in a port range",
                    found: token_text(self.peek()),
                },
            )),
        }
    }

    /// Parse A or B or C or ...
    fn parse_or(&mut self) -> Result<Expr, CompileError> {
        // first obtain smt in left-hand side from "and"
        let mut lhs = self.parse_and()?;
        // then check for "or"
        while self.word() == Some("or") {
            self.advance();
            // obtain smt in right-hand side from "and"
            let rhs = self.parse_and()?;
            let offset = offset_from_expr(&lhs).start..offset_from_expr(&rhs).end;
            lhs = Expr::Or(Box::new(lhs), Box::new(rhs), offset);
        }
        Ok(lhs)
    }

    /// Parse `A and B and C ...`, left-associative, one precedence level tighter than `or`.
    fn parse_and(&mut self) -> Result<Expr, CompileError> {
        let mut lhs = self.parse_unary()?;
        while self.word() == Some("and") {
            self.advance();
            let rhs = self.parse_unary()?;
            let offset = offset_from_expr(&lhs).start..offset_from_expr(&rhs).end;
            lhs = Expr::And(Box::new(lhs), Box::new(rhs), offset);
        }
        Ok(lhs)
    }

    /// Parse zero or more `not` prefixes (right-associative, so `not not x` nests) then a primary.
    fn parse_unary(&mut self) -> Result<Expr, CompileError> {
        if self.word() == Some("not") {
            let start = self.peek().offset.start;
            self.advance();
            let inner = self.parse_unary()?;
            let end = offset_from_expr(&inner).end;
            Ok(Expr::Not(Box::new(inner), start..end))
        } else {
            self.parse_primary()
        }
    }

    /// Parse the tightest-binding form: a `( ... )` group (recursing into [`Self::parse_or`]) or a
    /// single primitive. Reports [`ErrorTag::UnbalancedParens`] on a stray `)` or a missing one.
    fn parse_primary(&mut self) -> Result<Expr, CompileError> {
        match &self.peek().tag {
            TokenTag::LParen => {
                self.advance();
                let inner = self.parse_or()?;
                match self.peek().tag {
                    TokenTag::RParen => {
                        self.advance();
                        Ok(inner)
                    }
                    _ => Err(CompileError::new(
                        self.peek().offset.clone(),
                        ErrorTag::UnbalancedParens,
                    )),
                }
            }
            TokenTag::RParen => Err(CompileError::new(
                self.peek().offset.clone(),
                ErrorTag::UnbalancedParens,
            )),
            TokenTag::Word(_) => self.parse_primitive().map(Expr::Primitive),
            TokenTag::Eof => Err(CompileError::new(
                self.peek().offset.clone(),
                ErrorTag::UnexpectedEof {
                    expected: "an expression",
                },
            )),
            _ => Err(CompileError::new(
                self.peek().offset.clone(),
                ErrorTag::UnexpectedToken {
                    expected: "an expression",
                    found: token_text(self.peek()),
                },
            )),
        }
    }

    /// Consume a leading protocol keyword (`ip`/`ip6`/`arp`/`tcp`/`udp`/`icmp`) if the current token
    /// is one; otherwise return `None` and leave the position unchanged.
    fn try_parse_proto(&mut self) -> Option<ProtoTag> {
        let tag = match self.word()? {
            "ip" => ProtoTag::Ip,
            "ip6" => ProtoTag::Ip6,
            "arp" => ProtoTag::Arp,
            "tcp" => ProtoTag::Tcp,
            "udp" => ProtoTag::Udp,
            "icmp" => ProtoTag::Icmp,
            _ => return None,
        };
        self.advance();
        Some(tag)
    }

    /// Consume a leading direction keyword (`src`/`dst`) if the current token is one; otherwise
    /// return `None` and leave the position unchanged.
    fn try_parse_dir(&mut self) -> Option<DirTag> {
        let tag = match self.word()? {
            "src" => DirTag::Src,
            "dst" => DirTag::Dst,
            _ => return None,
        };
        self.advance();
        Some(tag)
    }

    /// Parse one `[proto] [dir] type value` primitive, where `type` is `host`, `net`, `port`, or
    /// `portrange` and `value` is the matching literal (address, CIDR, port, or `lo-hi` range).
    fn parse_primitive(&mut self) -> Result<Primitive, CompileError> {
        let start = self.peek().offset.start;
        let proto = self.try_parse_proto();
        let dir = self.try_parse_dir();

        let (ty_word, ty_offset) = self.expect_word("'host', 'net', 'port', or 'portrange'")?;
        let ty = match ty_word.as_str() {
            "host" => {
                let (text, offset) = self.expect_word("an address")?;
                let (addr, _) = parse_addr_literal(&text, offset, false)?;
                PrimType::Host(addr)
            }
            "net" => {
                let (text, offset) = self.expect_word("a network address")?;
                let (addr, prefix) = parse_addr_literal(&text, offset, true)?;
                PrimType::Net(addr, prefix)
            }
            "port" => {
                let (text, offset) = self.expect_word("a port number")?;
                PrimType::Port(parse_port(&text, offset)?)
            }
            "portrange" => {
                let (lo_text, lo_offset) = self.expect_word("a port number")?;
                let lo = parse_port(&lo_text, lo_offset)?;
                self.expect_dash()?;
                let (hi_text, hi_offset) = self.expect_word("a port number")?;
                let hi_end = hi_offset.end;
                let hi = parse_port(&hi_text, hi_offset)?;
                if lo > hi {
                    return Err(CompileError::new(
                        start..hi_end,
                        ErrorTag::InvalidPortRange {
                            lo: lo as u32,
                            hi: hi as u32,
                        },
                    ));
                }
                PrimType::PortRange(lo, hi)
            }
            // "rarp"/"sctp" are real protocols in this crate's model, but only ever reachable via
            // default expansion - a user can't type them directly, so calling them out by name here
            // (rather than the generic UnexpectedToken below) is a clearer error.
            "rarp" | "sctp" => {
                return Err(CompileError::new(
                    ty_offset,
                    ErrorTag::UnknownKeyword(ty_word),
                ));
            }
            _ => {
                return Err(CompileError::new(
                    ty_offset,
                    ErrorTag::UnexpectedToken {
                        expected: "'host', 'net', 'port', or 'portrange'",
                        found: ty_word,
                    },
                ));
            }
        };

        let end = self.tokens[self.pos.saturating_sub(1)].offset.end;
        Ok(Primitive {
            proto,
            dir,
            ty,
            offset: start..end,
        })
    }
}

/// Parse a decimal port number into a `u16`, erroring at `offset` if it isn't numeric or is out of range.
fn parse_port(text: &str, offset: Offset) -> Result<u16, CompileError> {
    text.parse::<u16>()
        .map_err(|_| CompileError::new(offset, ErrorTag::InvalidPortNumber(String::from(text))))
}

/// Parse exactly four dot-separated decimal octets (each 0-255) into a big-endian `u32`, or `None` ifthe shape or any octet is wrong.
fn parse_ipv4_octets(text: &str) -> Option<u32> {
    let mut octets = [0u8; 4];
    let mut count = 0;
    for part in text.split('.') {
        if count >= 4 {
            return None;
        }
        let v: u16 = part.parse().ok()?;
        if v > 255 {
            return None;
        }
        octets[count] = v as u8;
        count += 1;
    }
    if count != 4 {
        return None;
    }
    Some(u32::from_be_bytes(octets))
}

/// Parses an address literal, optionally followed by `/<prefix>` when `allow_prefix` is true (used for `net`, not `host`).
///
/// IPv6-looking text (anything containing `:`) is accepted syntactically - `ip6 host ::1` parses - but its value is discarded:
/// currently the crate doesn't implement IPv6 address matching for now and will reject
/// it with [`crate::ErrorTag::Unimplemented`] rather than emit anything wrong.
fn parse_addr_literal(
    text: &str,
    offset: Offset,
    allow_prefix: bool,
) -> Result<(AddrLit, Option<u8>), CompileError> {
    if text.contains(':') {
        return Ok((AddrLit::V6, None));
    }

    let (addr_part, prefix_part) = match text.split_once('/') {
        Some((a, p)) => (a, Some(p)),
        None => (text, None),
    };

    let invalid = || {
        CompileError::new(
            offset.clone(),
            ErrorTag::InvalidIPv4Literal(String::from(text)),
        )
    };

    let addr = parse_ipv4_octets(addr_part).ok_or_else(invalid)?;

    let prefix = match prefix_part {
        Some(p) if allow_prefix => {
            let n: u8 = p.parse().map_err(|_| invalid())?;
            if n > 32 {
                return Err(invalid());
            }
            Some(n)
        }
        Some(_) => return Err(invalid()), // e.g. "host 1.2.3.4/24" - a prefix on a host literal
        None => None,
    };

    Ok((AddrLit::V4(addr), prefix))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::lexer::lex;

    fn render(src: &str) -> String {
        fn go(e: &Expr, out: &mut String) {
            match e {
                Expr::Primitive(p) => {
                    out.push_str(match p.proto {
                        Some(ProtoTag::Ip) => "ip",
                        Some(ProtoTag::Ip6) => "ip6",
                        Some(ProtoTag::Arp) => "arp",
                        Some(ProtoTag::Tcp) => "tcp",
                        Some(ProtoTag::Udp) => "udp",
                        Some(ProtoTag::Icmp) => "icmp",
                        None => "*",
                    });
                    out.push('&');
                    out.push_str(match p.dir {
                        Some(DirTag::Src) => "src",
                        Some(DirTag::Dst) => "dst",
                        None => "*",
                    });
                    match &p.ty {
                        PrimType::Host(AddrLit::V4(a)) => out.push_str(&format!(" host={a:#x}")),
                        PrimType::Host(AddrLit::V6) => out.push_str(" host=v6"),
                        PrimType::Net(AddrLit::V4(a), pfx) => {
                            out.push_str(&alloc::format!(" net={a:#x}/{pfx:?}"))
                        }
                        PrimType::Net(AddrLit::V6, _) => out.push_str(" net=v6"),
                        PrimType::Port(p) => out.push_str(&alloc::format!(" port={p}")),
                        PrimType::PortRange(lo, hi) => {
                            out.push_str(&alloc::format!(" portrange={lo}-{hi}"))
                        }
                    }
                }
                Expr::Not(inner, _) => {
                    out.push('!');
                    go(inner, out);
                }
                Expr::And(l, r, _) => {
                    out.push('(');
                    go(l, out);
                    out.push_str(" & ");
                    go(r, out);
                    out.push(')');
                }
                Expr::Or(l, r, _) => {
                    out.push('(');
                    go(l, out);
                    out.push_str(" | ");
                    go(r, out);
                    out.push(')');
                }
            }
        }
        let tokens = lex(src).unwrap();
        let expr = parse(&tokens).unwrap();
        let mut out = String::new();
        go(&expr, &mut out);
        out
    }

    #[test]
    fn proto_and_type_only() {
        assert_eq!(render("tcp port 80"), "tcp&* port=80");
    }

    #[test]
    fn full_primitive() {
        assert_eq!(render("ip src host 1.2.3.4"), "ip&src host=0x1020304");
    }

    #[test]
    fn precedence_not_and_or() {
        // not binds tighter than and, and binds tighter than or.
        assert_eq!(
            render("tcp port 80 or udp port 53 and not icmp port 1"),
            "(tcp&* port=80 | (udp&* port=53 & !icmp&* port=1))"
        );
    }

    #[test]
    fn parens_override_precedence() {
        assert_eq!(
            render("(tcp port 80 or udp port 53) and not icmp port 1"),
            "((tcp&* port=80 | udp&* port=53) & !icmp&* port=1)"
        );
    }

    #[test]
    fn portrange_parses() {
        assert_eq!(render("portrange 8000-8008"), "*&* portrange=8000-8008");
    }

    #[test]
    fn cidr_net() {
        assert_eq!(render("net 10.0.0.0/8"), "*&* net=0xa000000/Some(8)");
    }

    #[test]
    fn portrange_lo_gt_hi_is_an_error() {
        let tokens = lex("portrange 90-80").unwrap();
        let err = parse(&tokens).unwrap_err();
        assert_eq!(err.tag, ErrorTag::InvalidPortRange { lo: 90, hi: 80 });
    }

    #[test]
    fn unbalanced_parens_is_an_error() {
        let tokens = lex("(tcp port 80").unwrap();
        assert_eq!(parse(&tokens).unwrap_err().tag, ErrorTag::UnbalancedParens);

        let tokens = lex("tcp port 80)").unwrap();
        assert!(matches!(
            parse(&tokens).unwrap_err().tag,
            ErrorTag::UnexpectedToken { .. }
        ));
    }

    #[test]
    fn empty_expression_is_an_error() {
        let tokens = lex("").unwrap();
        assert_eq!(parse(&tokens).unwrap_err().tag, ErrorTag::EmptyExpression);
    }

    #[test]
    fn space_empty_expression_is_an_error() {
        let tokens = lex("   ").unwrap();
        assert_eq!(parse(&tokens).unwrap_err().tag, ErrorTag::EmptyExpression);
    }

    #[test]
    fn host_rejects_explicit_prefix() {
        let tokens = lex("host 1.2.3.4/24").unwrap();
        assert!(matches!(
            parse(&tokens).unwrap_err().tag,
            ErrorTag::InvalidIPv4Literal(_)
        ));
    }

    #[test]
    fn rarp_and_sctp_are_not_directly_typable() {
        let tokens = lex("rarp host 1.2.3.4").unwrap();
        assert!(
            matches!(parse(&tokens).unwrap_err().tag, ErrorTag::UnknownKeyword(w) if w == "rarp")
        );

        let tokens = lex("sctp port 80").unwrap();
        assert!(
            matches!(parse(&tokens).unwrap_err().tag, ErrorTag::UnknownKeyword(w) if w == "sctp")
        );
    }

    #[test]
    fn missing_type_qualifier_is_an_error() {
        let tokens = lex("tcp and udp").unwrap();
        let err = parse(&tokens).unwrap_err();
        assert!(
            matches!(err.tag, ErrorTag::UnexpectedToken { expected, .. } if expected.contains("host"))
        );
    }
}
