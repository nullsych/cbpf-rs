//! Tokenizer for pcap-filter expressions.
//!
//! Produces a flat stream of spanned [`Token`]s, e.g.:
//!
//! String "tcp port 80" to tokens: [Word("tcp"), Word("port"), Word("80"), Eof].

use crate::error::{CompileError, ErrorKind, Span};

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct Token {
    pub kind: TokenKind,
    pub span: Span,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum TokenKind {
    /// A run of word characters: keywords, decimal numbers, and address literals (`1.2.3.4`,
    /// `1.2.3.0/24`, `::1`) all come through as this - undifferentiated text for the parser to
    /// classify.
    Word(String),
    /// `-`, the `portrange` low/high separator (`8000-8008`).
    Dash,
    LParen,
    RParen,
    Eof,
}

fn is_word_char(c: char) -> bool {
    c.is_ascii_alphanumeric() || c == '.' || c == ':' || c == '/'
}

pub(crate) fn lex(src: &str) -> Result<Vec<Token>, CompileError> {
    let mut tokens = Vec::new();
    let bytes = src.as_bytes();
    let mut chars = src.char_indices().peekable();

    while let Some(&(start, c)) = chars.peek() {
        if c.is_whitespace() {
            chars.next();
            continue;
        }

        match c {
            '(' => {
                chars.next();
                tokens.push(Token {
                    kind: TokenKind::LParen,
                    span: start..start + 1,
                });
            }
            ')' => {
                chars.next();
                tokens.push(Token {
                    kind: TokenKind::RParen,
                    span: start..start + 1,
                });
            }
            // dash appears
            '-' => {
                chars.next();
                tokens.push(Token {
                    kind: TokenKind::Dash,
                    span: start..start + 1,
                });
            }
            // `not` case appears
            '!' => {
                chars.next();
                tokens.push(Token {
                    kind: TokenKind::Word(String::from("not")),
                    span: start..start + 1,
                });
            }
            // and / or appears
            '&' | '|' => {
                chars.next();
                let expected = c;
                match chars.peek() {
                    Some(&(_, next)) if next == expected => {
                        let end = start + 2;
                        chars.next();
                        let word = if expected == '&' { "and" } else { "or" };
                        tokens.push(Token {
                            kind: TokenKind::Word(String::from(word)),
                            span: start..end,
                        });
                    }
                    _ => {
                        return Err(CompileError::new(
                            start..start + 1,
                            ErrorKind::UnexpectedChar(c),
                        ));
                    }
                }
            }
            // a word starts here: consume the whole maximal run of word chars as one `Word`
            // (so `1.2.3.0/24` and `::1` stay a single token for the parser to classify)
            c if is_word_char(c) => {
                let mut end = start + c.len_utf8(); // byte just past the first char
                chars.next();
                // keep extending while the next char is still part of the word
                while let Some(&(i, c)) = chars.peek() {
                    if !is_word_char(c) {
                        break;
                    }
                    end = i + c.len_utf8();
                    chars.next();
                }
                // `start..end` always lands on char boundaries by construction, so this can't fail
                let text = core::str::from_utf8(&bytes[start..end])
                    .expect("span boundaries land on char boundaries by construction");
                tokens.push(Token {
                    kind: TokenKind::Word(String::from(text)),
                    span: start..end,
                });
            }
            // nothing else can start a token: bail out at the first offending byte
            other => {
                return Err(CompileError::new(
                    start..start + 1,
                    ErrorKind::UnexpectedChar(other),
                ));
            }
        }
    }

    let eof_at = src.len();
    tokens.push(Token {
        kind: TokenKind::Eof,
        span: eof_at..eof_at,
    });
    Ok(tokens)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn words(src: &str) -> Vec<TokenKind> {
        lex(src).unwrap().into_iter().map(|t| t.kind).collect()
    }

    #[test]
    fn keywords_separated() {
        assert_eq!(
            words("tcp port 80"),
            vec![
                TokenKind::Word(String::from("tcp")),
                TokenKind::Word(String::from("port")),
                TokenKind::Word(String::from("80")),
                TokenKind::Eof,
            ]
        );
    }

    #[test]
    fn lex_tokenkind_separated() {
        let expr: &str = "tcp port 80";

        let tokens = lex(expr).unwrap();

        assert_eq!(TokenKind::Word(String::from("tcp")), tokens[0].kind);
        assert_eq!(TokenKind::Word(String::from("port")), tokens[1].kind);
        assert_eq!(TokenKind::Word(String::from("80")), tokens[2].kind);
    }

    #[test]
    fn portrange_splits_on_dash() {
        assert_eq!(
            words("portrange 8000-8008"),
            vec![
                TokenKind::Word(String::from("portrange")),
                TokenKind::Word(String::from("8000")),
                TokenKind::Dash,
                TokenKind::Word(String::from("8008")),
                TokenKind::Eof,
            ]
        );
    }

    /// Make sure that CIDR block parsed as one word.
    #[test]
    fn cidr() {
        assert_eq!(
            words("1.2.3.0/24"),
            vec![TokenKind::Word(String::from("1.2.3.0/24")), TokenKind::Eof]
        );
    }

    /// Test that symbolic connectives are canonicalized to their word forms.
    #[test]
    fn symbolic_connectives() {
        assert_eq!(
            words("tcp && !udp || arp"),
            vec![
                TokenKind::Word(String::from("tcp")),
                TokenKind::Word(String::from("and")),
                TokenKind::Word(String::from("not")),
                TokenKind::Word(String::from("udp")),
                TokenKind::Word(String::from("or")),
                TokenKind::Word(String::from("arp")),
                TokenKind::Eof,
            ]
        );
    }

    /// Test that token spans point to the correct ranges in the source text.
    #[test]
    fn spans_cover_the_source_text() {
        let tokens = lex("  tcp  port").unwrap();
        assert_eq!(tokens[0].span, 2..5); // "tcp"
        assert_eq!(tokens[1].span, 7..11); // "port"
    }

    /// Test that a single `&` is rejected as an unexpected character.
    #[test]
    fn single_ampersand_is_an_error() {
        let err = lex("tcp & udp").unwrap_err();
        assert_eq!(err.kind, ErrorKind::UnexpectedChar('&'));
        assert_eq!(err.span, 4..5);
    }

    /// Test that parentheses are tokenized as separate tokens.
    #[test]
    fn parens_are_tokenized() {
        assert_eq!(
            words("(tcp)"),
            vec![
                TokenKind::LParen,
                TokenKind::Word(String::from("tcp")),
                TokenKind::RParen,
                TokenKind::Eof,
            ]
        );
    }
}
