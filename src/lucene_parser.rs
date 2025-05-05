use pest::{Parser, error::Error as PestError, iterators::Pair};
use pest_derive::Parser;
use std::{error::Error, fmt};

/// Possible errors during query parsing or rendering
#[derive(Debug)]
pub enum QueryParseError {
  SyntaxError(Box<PestError<Rule>>),
  InternalError(String),
}

impl fmt::Display for QueryParseError {
  fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
    match self {
      QueryParseError::SyntaxError(err) => {
        write!(f, "Invalid query syntax: {}", err)
      }
      QueryParseError::InternalError(msg) => {
        write!(f, "Internal parser error: {}", msg)
      }
    }
  }
}

impl Error for QueryParseError {
  fn source(&self) -> Option<&(dyn Error + 'static)> {
    match self {
      QueryParseError::SyntaxError(err) => Some(err.as_ref()),
      QueryParseError::InternalError(_) => None,
    }
  }
}

/// The Pest parser generated from `grammar.pest`
#[derive(Parser)]
#[grammar = "grammar.pest"]
pub struct QueryParser;
/// ---------- little helpers ----------
#[inline]
fn is_ws(pair: &pest::iterators::Pair<Rule>) -> bool {
  pair.as_rule() == Rule::WHITESPACE
}

/// True for any “divider” token we should ignore when collecting operands.
fn is_sep(pair: &pest::iterators::Pair<Rule>) -> bool {
  is_ws(pair) || matches!(pair.as_rule(), Rule::and_op | Rule::or_op)
}

fn next_non_ws<'a, I>(pairs: &mut I) -> Option<pest::iterators::Pair<'a, Rule>>
where
  I: Iterator<Item = pest::iterators::Pair<'a, Rule>>,
{
  pairs.find(|p| !is_ws(p))
}

/// Escape `%`, `_`, and backslash for SQL LIKE patterns.
fn escape_sql_like(s: &str) -> String {
  s.replace('\\', "\\\\")
    .replace('%', "\\%")
    .replace('_', "\\_")
}

/// Convert a raw Lucene-style query into a SQL WHERE clause.
pub fn query_to_sql(raw: &str) -> Result<String, QueryParseError> {
  let q = raw.trim();
  if q.is_empty() {
    return Ok("TRUE".to_string());
  }
  match QueryParser::parse(Rule::expression, q) {
    Ok(mut pairs) => {
      let expr_pair = pairs.next().ok_or_else(|| {
        QueryParseError::InternalError("Empty parse tree".into())
      })?;
      // Pass the top-level expression directly
      parse_expression(expr_pair)
    }
    Err(e) => Err(QueryParseError::SyntaxError(Box::new(e))),
  }
}

/// Recursively walk the parse tree and generate SQL.
fn parse_expression(pair: Pair<Rule>) -> Result<String, QueryParseError> {
  match pair.as_rule() {
    Rule::expression => {
      let mut inner = pair.into_inner();
      let expr = next_non_ws(&mut inner).ok_or_else(|| {
        QueryParseError::InternalError("Empty expression".into())
      })?;
      parse_expression(expr)
    }

    // ---------- OR ----------
    Rule::or_expr => {
      let mut inner = pair.into_inner();
      let first = next_non_ws(&mut inner).unwrap();
      let mut parts = vec![parse_expression(first)?];
      for p in inner {
        if is_sep(&p) {
          continue;
        }
        parts.push(parse_expression(p)?);
      }
      if parts.len() == 1 {
        Ok(parts.pop().unwrap())
      } else {
        Ok(parts.join(" OR "))
      }
    }

    // ---------- AND ----------
    Rule::and_expr => {
      let mut inner = pair.into_inner();
      let first = next_non_ws(&mut inner).unwrap();
      let mut parts = vec![parse_expression(first)?];
      for p in inner {
        if is_sep(&p) {
          continue;
        }
        parts.push(parse_expression(p)?);
      }
      if parts.len() == 1 {
        Ok(parts.pop().unwrap())
      } else {
        Ok(parts.join(" AND "))
      }
    }

    // ---------- NOT ----------
    Rule::not_expr => {
      let inner = pair.into_inner();
      let mut has_not = false;
      let mut target: Option<Pair<Rule>> = None;
      for p in inner {
        if is_ws(&p) {
          continue;
        }
        if p.as_rule() == Rule::NOT_OP {
          has_not = true;
        } else {
          target = Some(p);
          break;
        }
      }
      let expr_sql = parse_expression(target.ok_or_else(|| {
        QueryParseError::InternalError("Missing NOT target".into())
      })?)?;
      if has_not {
        Ok(format!("NOT {}", expr_sql))
      } else {
        Ok(expr_sql)
      }
    }

    Rule::primary => {
      let inner = pair.into_inner().next().unwrap();
      // Recursive call without is_top
      parse_expression(inner)
    }

    Rule::grouped => {
      let mut inner = pair.into_inner();
      let inner_pair = next_non_ws(&mut inner).unwrap();
      let inner_sql = parse_expression(inner_pair)?;
      Ok(format!("({})", inner_sql))
    }

    // Call render_key_value without is_top
    Rule::key_value => render_key_value(pair),

    Rule::phrase => {
      // Inline unquoting logic for phrases
      let s = pair.as_str();
      let t = if s.starts_with('"') && s.ends_with('"') && s.len() >= 2 {
        let inner = &s[1..s.len() - 1];
        inner.replace("\\\\", "\\").replace("\\\"", "\"")
      } else {
        s.to_string() // Fallback, though grammar should ensure quotes
      };
      Ok(format!(
        "(secret_key ILIKE '%{0}%' OR secret_value::text ILIKE '%{0}%')", // Keep parens for term search grouping
        escape_sql_like(&t)
      ))
    }
    Rule::term => {
      let t = pair.as_str();
      Ok(format!(
        "(secret_key ILIKE '%{0}%' OR secret_value::text ILIKE '%{0}%')", // Keep parens for term search grouping
        escape_sql_like(t)
      ))
    }
    Rule::EOI => Ok(String::new()), // Should not be reached if called from query_to_sql correctly
    other => Err(QueryParseError::InternalError(format!(
      "Unexpected rule encountered: {:?}",
      other
    ))),
  }
}

/// Render a key:value pair, handling schema vs. generic fields.
fn render_key_value(pair: Pair<Rule>) -> Result<String, QueryParseError> {
  let mut iter = pair.into_inner().filter(|p| !is_ws(p)); // pair is the key_value rule match
  let key_rule_pair = iter.next().ok_or_else(|| {
    // This pair corresponds to the 'key' rule
    QueryParseError::InternalError("Missing key in key_value rule".into())
  })?;
  let value_rule_pair = iter.next().ok_or_else(|| {
    // This pair corresponds to the 'value' rule
    QueryParseError::InternalError("Missing value in key_value rule".into())
  })?;

  // --- Determine raw key string ---
  // Look inside the 'key' rule's pair to find the actual token (quoted_string or ident)
  let key_inner_pair = key_rule_pair.into_inner().next().ok_or_else(|| {
    QueryParseError::InternalError("Missing inner pair for key rule".into())
  })?;

  let key_raw = match key_inner_pair.as_rule() {
    Rule::quoted_string => {
      let s = key_inner_pair.as_str();
      // Slice off the outer quotes guaranteed by the rule match
      let inner = &s[1..s.len() - 1];
      // Now unescape standard sequences like \\ and \" from the inner content
      inner.replace("\\\\", "\\").replace("\\\"", "\"")
    }
    Rule::ident => key_inner_pair.as_str().to_string(),
    _ => {
      return Err(QueryParseError::InternalError(format!(
        "Unexpected rule inside key: {:?}",
        key_inner_pair.as_rule()
      )));
    }
  };


  // --- Determine raw value string ---
  // Look inside the 'value' rule's pair to find the actual token
  let value_inner_pair =
    value_rule_pair.into_inner().next().ok_or_else(|| {
      QueryParseError::InternalError("Missing inner pair for value rule".into())
    })?;

  let val_raw = match value_inner_pair.as_rule() {
    Rule::quoted_string => {
      let s = value_inner_pair.as_str();
      // Slice off the outer quotes guaranteed by the rule match
      let inner = &s[1..s.len() - 1];
      // Now unescape standard sequences like \\ and \" from the inner content
      inner.replace("\\\\", "\\").replace("\\\"", "\"")
    }
    // Handle both single and multi-word identifiers correctly
    Rule::ident => value_inner_pair.as_str().to_string(),
    _ => {
      return Err(QueryParseError::InternalError(format!(
        "Unexpected rule inside value: {:?}",
        value_inner_pair.as_rule()
      )));
    }
  };

  // --- The rest of the function remains exactly as you had it ---
  let like_key = escape_sql_like(&key_raw);
  let like_val = escape_sql_like(&val_raw);
  let json_key = key_raw.replace('\\', "\\\\").replace('"', "\\\"");
  let json_val = val_raw.replace('\\', "\\\\").replace('"', "\\\"");

  let sql = match key_raw.as_str() {
    "secret_key" => format!("secret_key ILIKE '%{}%'", like_val),
    "secret_value" => format!("secret_value::text ILIKE '%{}%'", like_val),
    _ => {
      format!(
        "(secret_key ILIKE '%{lk}%' AND secret_value::text ILIKE '%{lv}%' OR \
         secret_value @> '{{\"{jk}\": \"{jv}\"}}')",
        lk = like_key,
        lv = like_val,
        jk = json_key,
        jv = json_val
      )
    }
  };

  Ok(sql)
}
