//! Section 4 ApprovalRule predicate compiler and matcher.
//!
//! Wire form of an approval rule is `{predicate: String, on_match:
//! "escalate" | "deny"}` (see [`crate::passport::ApprovalRule`]). The
//! string predicate is parsed and compiled here into a fast match form
//! used by `aps_check` (spec §9, step 12).
//!
//! Prototype 1 DSL grammar:
//!
//! ```text
//! Rule          := Conjunction
//! Conjunction   := Term ('AND' Term)*
//! Term          := Comparison | SetMembership
//! Comparison    := Field CompareOp Value
//! SetMembership := Field 'NOT'? 'IN' '[' Value (',' Value)* ']'
//! Field         := 'operation' | 'risk_class' | 'cost_units'
//! CompareOp     := '==' | '!=' | '<' | '<=' | '>' | '>='
//! Value         := Identifier | Number
//! ```
//!
//! Restrictions for Prototype 1:
//!
//! - Whitespace is freely ignored between tokens.
//! - `AND`, `NOT`, `IN` are case-sensitive uppercase keywords.
//! - Set membership is supported only on the `operation` field
//!   (operation names are unordered tags; `IN` is the natural form).
//! - Comparison on the `operation` field accepts only `==` and `!=`
//!   (operation IDs are not ordered).
//! - Mid-path resource matching, OR composition, and additional fields
//!   (recipient, etc.) are Phase 2.
//!
//! Fixed operation enum: `read=0`, `write=1`, `delete=2`,
//! `external_send=3`, `money_move=4`, `data_export=5`,
//! `approval_request=6`. Same mapping shared by
//! [`crate::compiled::CompiledAuthority::from_passport`] for the
//! `allowed_op_mask`.

use thiserror::Error;

use crate::action::ActionDescriptor;
use crate::passport::ApprovalAction;

// -----------------------------------------------------------------------
// Name resolution helpers (canonical home; compiled.rs imports these)
// -----------------------------------------------------------------------

/// Resolve an operation name to its numeric id. The id is also the
/// bit position in the compiled `allowed_op_mask`.
pub fn operation_id_from_name(name: &str) -> Option<u16> {
    match name {
        "read" => Some(0),
        "write" => Some(1),
        "delete" => Some(2),
        "external_send" => Some(3),
        "money_move" => Some(4),
        "data_export" => Some(5),
        "approval_request" => Some(6),
        _ => None,
    }
}

/// Resolve a risk class name (`"R0"`..`"R4"`) to its u8 value.
pub fn risk_class_value_from_name(name: &str) -> Option<u8> {
    match name {
        "R0" => Some(0),
        "R1" => Some(1),
        "R2" => Some(2),
        "R3" => Some(3),
        "R4" => Some(4),
        _ => None,
    }
}

// -----------------------------------------------------------------------
// Public types
// -----------------------------------------------------------------------

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PredicateField {
    Operation,
    RiskClass,
    CostUnits,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CompareOp {
    Eq,
    Ne,
    Lt,
    Le,
    Gt,
    Ge,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SetOp {
    In,
    NotIn,
}

#[derive(Debug, Clone)]
pub enum CompiledPredicate {
    Compare {
        field: PredicateField,
        op: CompareOp,
        value: u64,
    },
    SetMember {
        field: PredicateField,
        op: SetOp,
        set: Vec<u64>,
    },
}

#[derive(Debug, Clone)]
pub struct CompiledApprovalRule {
    /// Source predicate string (retained for audit / receipt purposes).
    pub source: String,
    /// AND-conjunction of compiled predicate terms. Non-empty.
    pub terms: Vec<CompiledPredicate>,
    pub on_match: ApprovalAction,
}

#[derive(Debug, Error)]
pub enum ApprovalCompileError {
    #[error("empty predicate")]
    EmptyPredicate,
    #[error("syntax error at position {pos}: {msg}")]
    SyntaxError { pos: usize, msg: String },
    #[error("unknown field: {0} (supported: operation, risk_class, cost_units)")]
    UnknownField(String),
    #[error("unknown operation name: {0}")]
    UnknownOperation(String),
    #[error("unknown risk class: {0} (supported: R0..R4)")]
    UnknownRiskClass(String),
    #[error("invalid value for {field:?}: {value}")]
    InvalidValue { field: PredicateField, value: String },
    #[error("operator '{op}' not supported for field {field:?}")]
    UnsupportedOperator { field: PredicateField, op: String },
}

// -----------------------------------------------------------------------
// Lexer
// -----------------------------------------------------------------------

#[derive(Debug, Clone, PartialEq)]
enum Token<'a> {
    Identifier(&'a str),
    Number(u64),
    Op(&'static str), // ==, !=, <, <=, >, >=
    LBracket,
    RBracket,
    Comma,
    And,
    Not,
    In,
    Eof,
}

struct Lexer<'a> {
    src: &'a str,
    pos: usize,
}

impl<'a> Lexer<'a> {
    fn new(src: &'a str) -> Self {
        Lexer { src, pos: 0 }
    }

    fn skip_ws(&mut self) {
        while let Some(b) = self.src.as_bytes().get(self.pos) {
            if b.is_ascii_whitespace() {
                self.pos += 1;
            } else {
                break;
            }
        }
    }

    fn next(&mut self) -> Result<(usize, Token<'a>), ApprovalCompileError> {
        self.skip_ws();
        let start = self.pos;
        let bytes = self.src.as_bytes();
        let Some(&b) = bytes.get(self.pos) else {
            return Ok((start, Token::Eof));
        };
        match b {
            b'[' => {
                self.pos += 1;
                Ok((start, Token::LBracket))
            }
            b']' => {
                self.pos += 1;
                Ok((start, Token::RBracket))
            }
            b',' => {
                self.pos += 1;
                Ok((start, Token::Comma))
            }
            b'=' => {
                if bytes.get(self.pos + 1) == Some(&b'=') {
                    self.pos += 2;
                    Ok((start, Token::Op("==")))
                } else {
                    Err(ApprovalCompileError::SyntaxError {
                        pos: start,
                        msg: "expected '==' (single '=' is not an operator)".into(),
                    })
                }
            }
            b'!' => {
                if bytes.get(self.pos + 1) == Some(&b'=') {
                    self.pos += 2;
                    Ok((start, Token::Op("!=")))
                } else {
                    Err(ApprovalCompileError::SyntaxError {
                        pos: start,
                        msg: "expected '!=' (bare '!' is not an operator)".into(),
                    })
                }
            }
            b'<' => {
                if bytes.get(self.pos + 1) == Some(&b'=') {
                    self.pos += 2;
                    Ok((start, Token::Op("<=")))
                } else {
                    self.pos += 1;
                    Ok((start, Token::Op("<")))
                }
            }
            b'>' => {
                if bytes.get(self.pos + 1) == Some(&b'=') {
                    self.pos += 2;
                    Ok((start, Token::Op(">=")))
                } else {
                    self.pos += 1;
                    Ok((start, Token::Op(">")))
                }
            }
            d if d.is_ascii_digit() => {
                let end = bytes[self.pos..]
                    .iter()
                    .position(|c| !c.is_ascii_digit())
                    .map(|n| self.pos + n)
                    .unwrap_or(bytes.len());
                let n: u64 = self.src[self.pos..end].parse().map_err(|_| {
                    ApprovalCompileError::SyntaxError {
                        pos: start,
                        msg: "number overflow".into(),
                    }
                })?;
                self.pos = end;
                Ok((start, Token::Number(n)))
            }
            c if c.is_ascii_alphabetic() || c == b'_' => {
                let end = bytes[self.pos..]
                    .iter()
                    .position(|c| !(c.is_ascii_alphanumeric() || *c == b'_'))
                    .map(|n| self.pos + n)
                    .unwrap_or(bytes.len());
                let ident = &self.src[self.pos..end];
                self.pos = end;
                let tok = match ident {
                    "AND" => Token::And,
                    "NOT" => Token::Not,
                    "IN" => Token::In,
                    other => Token::Identifier(other),
                };
                Ok((start, tok))
            }
            _ => Err(ApprovalCompileError::SyntaxError {
                pos: start,
                msg: format!("unexpected character {:?}", b as char),
            }),
        }
    }
}

// -----------------------------------------------------------------------
// Parser
// -----------------------------------------------------------------------

fn field_from_ident(name: &str) -> Option<PredicateField> {
    match name {
        "operation" => Some(PredicateField::Operation),
        "risk_class" => Some(PredicateField::RiskClass),
        "cost_units" => Some(PredicateField::CostUnits),
        _ => None,
    }
}

fn compare_op_from_str(op: &str) -> Option<CompareOp> {
    match op {
        "==" => Some(CompareOp::Eq),
        "!=" => Some(CompareOp::Ne),
        "<" => Some(CompareOp::Lt),
        "<=" => Some(CompareOp::Le),
        ">" => Some(CompareOp::Gt),
        ">=" => Some(CompareOp::Ge),
        _ => None,
    }
}

fn resolve_value_for_field(
    field: PredicateField,
    tok: Token<'_>,
    pos: usize,
) -> Result<u64, ApprovalCompileError> {
    match (field, tok) {
        (PredicateField::Operation, Token::Identifier(name)) => operation_id_from_name(name)
            .map(u64::from)
            .ok_or_else(|| ApprovalCompileError::UnknownOperation(name.to_string())),
        (PredicateField::Operation, Token::Number(n)) => Ok(n),
        (PredicateField::RiskClass, Token::Identifier(name)) => risk_class_value_from_name(name)
            .map(u64::from)
            .ok_or_else(|| ApprovalCompileError::UnknownRiskClass(name.to_string())),
        (PredicateField::RiskClass, Token::Number(n)) => Ok(n),
        (PredicateField::CostUnits, Token::Number(n)) => Ok(n),
        (PredicateField::CostUnits, Token::Identifier(name)) => {
            Err(ApprovalCompileError::InvalidValue {
                field: PredicateField::CostUnits,
                value: name.to_string(),
            })
        }
        _ => Err(ApprovalCompileError::SyntaxError {
            pos,
            msg: "expected a value (identifier or number)".into(),
        }),
    }
}

fn parse_term<'a>(
    lex: &mut Lexer<'a>,
    first: (usize, Token<'a>),
) -> Result<CompiledPredicate, ApprovalCompileError> {
    let (field_pos, field_tok) = first;
    let field_name = match field_tok {
        Token::Identifier(s) => s,
        _ => {
            return Err(ApprovalCompileError::SyntaxError {
                pos: field_pos,
                msg: "expected field identifier".into(),
            })
        }
    };
    let field = field_from_ident(field_name)
        .ok_or_else(|| ApprovalCompileError::UnknownField(field_name.to_string()))?;

    let (op_pos, op_tok) = lex.next()?;
    match op_tok {
        Token::Op(op_str) => {
            // Comparison: only Operation and RiskClass and CostUnits.
            let op = compare_op_from_str(op_str).ok_or(ApprovalCompileError::SyntaxError {
                pos: op_pos,
                msg: "unrecognized operator".into(),
            })?;
            // Operation only accepts Eq/Ne.
            if field == PredicateField::Operation
                && !matches!(op, CompareOp::Eq | CompareOp::Ne)
            {
                return Err(ApprovalCompileError::UnsupportedOperator {
                    field,
                    op: op_str.to_string(),
                });
            }
            let (val_pos, val_tok) = lex.next()?;
            let value = resolve_value_for_field(field, val_tok, val_pos)?;
            Ok(CompiledPredicate::Compare { field, op, value })
        }
        Token::Not => {
            // Expect IN next; set membership.
            let (_, t) = lex.next()?;
            if t != Token::In {
                return Err(ApprovalCompileError::SyntaxError {
                    pos: op_pos,
                    msg: "expected 'IN' after 'NOT'".into(),
                });
            }
            parse_set_membership(lex, field, SetOp::NotIn, op_pos)
        }
        Token::In => parse_set_membership(lex, field, SetOp::In, op_pos),
        other => Err(ApprovalCompileError::SyntaxError {
            pos: op_pos,
            msg: format!("expected comparison or set-membership, got {other:?}"),
        }),
    }
}

fn parse_set_membership(
    lex: &mut Lexer<'_>,
    field: PredicateField,
    op: SetOp,
    op_pos: usize,
) -> Result<CompiledPredicate, ApprovalCompileError> {
    if field != PredicateField::Operation {
        return Err(ApprovalCompileError::UnsupportedOperator {
            field,
            op: match op {
                SetOp::In => "IN".into(),
                SetOp::NotIn => "NOT IN".into(),
            },
        });
    }
    let (lb_pos, lb) = lex.next()?;
    if lb != Token::LBracket {
        return Err(ApprovalCompileError::SyntaxError {
            pos: lb_pos,
            msg: "expected '[' after IN".into(),
        });
    }
    let mut set: Vec<u64> = Vec::new();
    loop {
        let (vpos, vtok) = lex.next()?;
        let val = resolve_value_for_field(field, vtok, vpos)?;
        set.push(val);
        let (sep_pos, sep) = lex.next()?;
        match sep {
            Token::Comma => continue,
            Token::RBracket => break,
            _ => {
                return Err(ApprovalCompileError::SyntaxError {
                    pos: sep_pos,
                    msg: "expected ',' or ']' in set literal".into(),
                })
            }
        }
    }
    if set.is_empty() {
        return Err(ApprovalCompileError::SyntaxError {
            pos: op_pos,
            msg: "set literal must contain at least one value".into(),
        });
    }
    Ok(CompiledPredicate::SetMember { field, op, set })
}

fn parse_conjunction(lex: &mut Lexer<'_>) -> Result<Vec<CompiledPredicate>, ApprovalCompileError> {
    let mut terms = Vec::new();
    let first = lex.next()?;
    if first.1 == Token::Eof {
        return Err(ApprovalCompileError::EmptyPredicate);
    }
    terms.push(parse_term(lex, first)?);
    loop {
        let (and_pos, t) = lex.next()?;
        match t {
            Token::Eof => break,
            Token::And => {
                let next_first = lex.next()?;
                terms.push(parse_term(lex, next_first)?);
            }
            _ => {
                return Err(ApprovalCompileError::SyntaxError {
                    pos: and_pos,
                    msg: "expected 'AND' or end of predicate".into(),
                })
            }
        }
    }
    Ok(terms)
}

// -----------------------------------------------------------------------
// Public compile + match
// -----------------------------------------------------------------------

impl CompiledApprovalRule {
    /// Compile a predicate string into match form.
    pub fn compile(
        predicate: &str,
        on_match: ApprovalAction,
    ) -> Result<Self, ApprovalCompileError> {
        if predicate.trim().is_empty() {
            return Err(ApprovalCompileError::EmptyPredicate);
        }
        let mut lex = Lexer::new(predicate);
        let terms = parse_conjunction(&mut lex)?;
        Ok(CompiledApprovalRule {
            source: predicate.to_string(),
            terms,
            on_match,
        })
    }

    /// Match the rule against an action. Returns `true` iff every term
    /// matches (AND-conjunction).
    pub fn matches(&self, action: &ActionDescriptor) -> bool {
        self.terms.iter().all(|t| eval_term(t, action))
    }
}

fn field_value(action: &ActionDescriptor, field: PredicateField) -> u64 {
    match field {
        PredicateField::Operation => u64::from(action.operation_id),
        PredicateField::RiskClass => u64::from(action.risk_class),
        PredicateField::CostUnits => u64::from(action.cost_units),
    }
}

fn eval_term(term: &CompiledPredicate, action: &ActionDescriptor) -> bool {
    match term {
        CompiledPredicate::Compare { field, op, value } => {
            let lhs = field_value(action, *field);
            match op {
                CompareOp::Eq => lhs == *value,
                CompareOp::Ne => lhs != *value,
                CompareOp::Lt => lhs < *value,
                CompareOp::Le => lhs <= *value,
                CompareOp::Gt => lhs > *value,
                CompareOp::Ge => lhs >= *value,
            }
        }
        CompiledPredicate::SetMember { field, op, set } => {
            let lhs = field_value(action, *field);
            let present = set.contains(&lhs);
            match op {
                SetOp::In => present,
                SetOp::NotIn => !present,
            }
        }
    }
}
