//! Tokenizer for pcap-filter expressions.
//!
//! Produces a flat stream of tagged [`Token`]s, e.g.:
//!
//! String "tcp port 80" to tokens: [Word("tcp"), Word("port"), Word("80"), Eof].

use crate::error::{CompileError, ErrorTag, Offset};
use alloc::string::String;
use alloc::vec::Vec;

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct Token {
    pub tag: TokenTag,
    pub offset: Offset,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum TokenTag {
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
                    tag: TokenTag::LParen,
                    offset: start..start + 1,
                });
            }
            ')' => {
                chars.next();
                tokens.push(Token {
                    tag: TokenTag::RParen,
                    offset: start..start + 1,
                });
            }
            // dash appears
            '-' => {
                chars.next();
                tokens.push(Token {
                    tag: TokenTag::Dash,
                    offset: start..start + 1,
                });
            }
            // `not` case appears
            '!' => {
                chars.next();
                tokens.push(Token {
                    tag: TokenTag::Word(String::from("not")),
                    offset: start..start + 1,
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
                            tag: TokenTag::Word(String::from(word)),
                            offset: start..end,
                        });
                    }
                    _ => {
                        return Err(CompileError::new(
                            start..start + 1,
                            ErrorTag::UnexpectedChar(c),
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
                    .expect("offset boundaries land on char boundaries by construction");
                tokens.push(Token {
                    tag: TokenTag::Word(String::from(text)),
                    offset: start..end,
                });
            }
            // nothing else can start a token: bail out at the first offending byte
            other => {
                return Err(CompileError::new(
                    start..start + 1,
                    ErrorTag::UnexpectedChar(other),
                ));
            }
        }
    }

    let eof_at = src.len();
    tokens.push(Token {
        tag: TokenTag::Eof,
        offset: eof_at..eof_at,
    });
    Ok(tokens)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn words(src: &str) -> Vec<TokenTag> {
        lex(src).unwrap().into_iter().map(|t| t.tag).collect()
    }

    #[test]
    fn keywords_separated() {
        assert_eq!(
            words("tcp port 80"),
            alloc::vec![
                TokenTag::Word(String::from("tcp")),
                TokenTag::Word(String::from("port")),
                TokenTag::Word(String::from("80")),
                TokenTag::Eof,
            ]
        );
    }

    #[test]
    fn lex_token_separated() {
        let expr: &str = "tcp port 80";

        let tokens = lex(expr).unwrap();

        assert_eq!(TokenTag::Word(String::from("tcp")), tokens[0].tag);
        assert_eq!(TokenTag::Word(String::from("port")), tokens[1].tag);
        assert_eq!(TokenTag::Word(String::from("80")), tokens[2].tag);
    }

    #[test]
    fn portrange_splits_on_dash() {
        assert_eq!(
            words("portrange 8000-8008"),
            alloc::vec![
                TokenTag::Word(String::from("portrange")),
                TokenTag::Word(String::from("8000")),
                TokenTag::Dash,
                TokenTag::Word(String::from("8008")),
                TokenTag::Eof,
            ]
        );
    }

    /// Make sure that CIDR block parsed as one word.
    #[test]
    fn cidr() {
        assert_eq!(
            words("1.2.3.0/24"),
            alloc::vec![TokenTag::Word(String::from("1.2.3.0/24")), TokenTag::Eof]
        );
    }

    /// Test that symbolic connectives are canonicalized to their word forms.
    #[test]
    fn symbolic_connectives() {
        assert_eq!(
            words("tcp && !udp || arp"),
            alloc::vec![
                TokenTag::Word(String::from("tcp")),
                TokenTag::Word(String::from("and")),
                TokenTag::Word(String::from("not")),
                TokenTag::Word(String::from("udp")),
                TokenTag::Word(String::from("or")),
                TokenTag::Word(String::from("arp")),
                TokenTag::Eof,
            ]
        );
    }

    /// Test that token offsets point to the correct ranges in the source text.
    #[test]
    fn offsets_cover_the_source_text() {
        let tokens = lex("  tcp  port").unwrap();
        assert_eq!(tokens[0].offset, 2..5); // "tcp"
        assert_eq!(tokens[1].offset, 7..11); // "port"
    }

    /// Test that a single `&` is rejected as an unexpected character.
    #[test]
    fn single_ampersand_is_an_error() {
        let err = lex("tcp & udp").unwrap_err();
        assert_eq!(err.tag, ErrorTag::UnexpectedChar('&'));
        assert_eq!(err.offset, 4..5);
    }

    /// Test that parentheses are tokenized as separate tokens.
    #[test]
    fn parens_are_tokenized() {
        assert_eq!(
            words("(tcp)"),
            alloc::vec![
                TokenTag::LParen,
                TokenTag::Word(String::from("tcp")),
                TokenTag::RParen,
                TokenTag::Eof,
            ]
        );
    }
}
