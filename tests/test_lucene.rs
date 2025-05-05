use keyvault::lucene_parser::query_to_sql;

macro_rules! assert_sql_eq {
  ($raw:expr, $expected:expr) => {{
    match query_to_sql($raw) {
      Ok(sql) => {
        use keyvault::lucene_parser::{QueryParser, Rule};
        use pest::Parser;
        use pest_ascii_tree::print_ascii_tree;

        // On success, print the parse tree
        match QueryParser::parse(Rule::expression, $raw) {
          Ok(pairs) => print_ascii_tree(Ok(pairs)),
          Err(e) => eprintln!("⚠️ Could not parse for tree: {e}"),
        }
        assert_eq!(sql, $expected, "Query: '{}'", $raw);
      }
      Err(e) => {
        eprintln!("❌ query_to_sql failed for query '{}': {}", $raw, e);

        // -------- headless trace via pest_debugger ----------
        use pest_debugger::DebuggerContext;

        let mut ctx = DebuggerContext::default();

        let grammar = include_str!("../src/grammar.pest"); // point to your .pest
        let _ = ctx.load_grammar_direct("lucene", grammar);
        let _ = ctx.load_input_direct($raw.to_string());

        // ⚠️  DO NOT set breakpoints; just stream the events
        let (tx, rx) = std::sync::mpsc::sync_channel(1_000);
        if ctx.run("expression", tx).is_ok() {
            for event in rx {      // iter ends when parse finishes
                eprintln!("{event:?}");
            }
        }
        // -----------------------------------------------------

        panic!("query_to_sql failed for query '{}'", $raw);
      }
    }
  }};
  ($raw:expr, $expected:expr,) => {
    assert_sql_eq!($raw, $expected)
  };
}


#[test]
fn test_empty_query() {
  assert_sql_eq!("", "TRUE");
  assert_sql_eq!("   ", "TRUE");
}

#[test]
fn test_simple_key_value_includes() {
  let raw = "something:wild";
  // Top-level generic k:v uses combo query, wrapped in parens
  assert_sql_eq!(
    raw,
    "(secret_key ILIKE '%something%' AND secret_value::text ILIKE '%wild%' OR \
     secret_value @> '{\"something\": \"wild\"}')"
  );
}

#[test]
fn test_simple_key_value_excludes() {
  let raw = "-something:wild";
  // NOT wraps the operand in parens
  assert_sql_eq!(
    raw,
    "NOT (secret_key ILIKE '%something%' AND secret_value::text ILIKE \
     '%wild%' OR secret_value @> '{\"something\": \"wild\"}')"
  );
}

#[test]
fn test_schema_field_key_includes() {
  let raw = "secret_key:test_value";
  // Top-level schema field (no combo query needed)
  assert_sql_eq!(
    raw,
    "secret_key ILIKE '%test\\_value%'" // Value escaped for LIKE
  );
}

#[test]
fn test_schema_field_value_includes() {
  // Test multi-word value after special field: first word applies to the field,
  // subsequent words become ANDed keyword searches.
  let raw = "secret_value:some data";
  assert_sql_eq!(
    raw,
    // Expected SQL based on desired logic:
    "secret_value::text ILIKE '%some%' AND (secret_key ILIKE '%data%' OR \
     secret_value::text ILIKE '%data%')"
  );
}

#[test]
fn test_schema_field_key_excludes() {
  let raw = "-secret_key:test_initial_value";
  // NOT wraps the operand in parens
  assert_sql_eq!(
    raw,
    "NOT secret_key ILIKE '%test\\_initial\\_value%'" // Escaped value
  );
}

#[test]
fn test_implicit_and() {
  let raw = "foo:bar baz:qux"; // Implicit AND
  // Nested generic k:v use simple @>
  assert_sql_eq!(
    raw,
    "(secret_key ILIKE '%foo%' AND secret_value::text ILIKE '%bar%' OR \
     secret_value @> '{\"foo\": \"bar\"}') AND (secret_key ILIKE '%baz%' AND \
     secret_value::text ILIKE '%qux%' OR secret_value @> '{\"baz\": \"qux\"}')"
  );
}

#[test]
fn test_explicit_and() {
  let raw = "foo:bar AND baz:qux";
  assert_sql_eq!(
    raw,
    "(secret_key ILIKE '%foo%' AND secret_value::text ILIKE '%bar%' OR \
     secret_value @> '{\"foo\": \"bar\"}') AND (secret_key ILIKE '%baz%' AND \
     secret_value::text ILIKE '%qux%' OR secret_value @> '{\"baz\": \"qux\"}')"
  );
}

#[test]
fn test_multiple_and() {
  let raw = "foo AND bar baz:qux";
  // Nested generic k:v use simple @>
  assert_sql_eq!(
    raw,
    "(secret_key ILIKE '%foo%' OR secret_value::text ILIKE '%foo%') AND \
     (secret_key ILIKE '%bar%' OR secret_value::text ILIKE '%bar%') AND \
     (secret_key ILIKE '%baz%' AND secret_value::text ILIKE '%qux%' OR \
     secret_value @> '{\"baz\": \"qux\"}')"
  );
}

#[test]
fn test_multiple_or() {
  let raw = "foo:bar OR baz:qux";
  // OR group is top-level here
  // Nested generic k:v use simple @>
  assert_sql_eq!(
    raw,
    "(secret_key ILIKE '%foo%' AND secret_value::text ILIKE '%bar%' OR \
     secret_value @> '{\"foo\": \"bar\"}') OR (secret_key ILIKE '%baz%' AND \
     secret_value::text ILIKE '%qux%' OR secret_value @> '{\"baz\": \"qux\"}')"
  );
}

#[test]
fn test_single_term_includes() {
  let raw = "term";
  // Term search is wrapped in parens
  assert_sql_eq!(
    raw,
    "(secret_key ILIKE '%term%' OR secret_value::text ILIKE '%term%')"
  );
}

#[test]
fn test_single_term_excludes() {
  let raw = "-term";
  // NOT wraps the term search parens
  assert_sql_eq!(
    raw,
    "NOT (secret_key ILIKE '%term%' OR secret_value::text ILIKE '%term%')"
  );
}

#[test]
fn test_grouped_and_or() {
  let raw = "(foo:bar OR baz:qux) AND something:wild";
  // The OR group gets wrapped. `something:wild` is nested within AND, so simple @> is used.
  assert_sql_eq!(
    raw,
    "((secret_key ILIKE '%foo%' AND secret_value::text ILIKE '%bar%' OR \
     secret_value @> '{\"foo\": \"bar\"}') OR (secret_key ILIKE '%baz%' AND \
     secret_value::text ILIKE '%qux%' OR secret_value @> '{\"baz\": \
     \"qux\"}')) AND (secret_key ILIKE '%something%' AND secret_value::text \
     ILIKE '%wild%' OR secret_value @> '{\"something\": \"wild\"}')"
  );
}

#[test]
fn test_quoted_phrase() {
  let raw = "\"hello world\"";
  // Phrase search wrapped in parens
  assert_sql_eq!(
    raw,
    "(secret_key ILIKE '%hello world%' OR secret_value::text ILIKE '%hello \
     world%')"
  );
}

#[test]
fn test_key_value_with_quoted_spaces() {
  let raw = "\"first name\":\"last name\"";
  // Top-level generic k:v with quotes -> combo query, correctly parsed key/value
  assert_sql_eq!(
    raw,
    // Key/Value escaped for ILIKE, Key/Value escaped for JSON
    "(secret_key ILIKE '%first name%' AND secret_value::text ILIKE '%last \
     name%' OR secret_value @> '{\"first name\": \"last name\"}')"
  );
}

#[test]
fn test_key_value_with_escaped_quotes_in_value() {
  let raw = r#"message:"{\"ok\": true}""#;
  // Top-level generic k:v -> combo query, value needs correct escaping for JSON and LIKE
  assert_sql_eq!(
    raw,
    // LIKE needs single-escaped \, JSON needs double-escaped \"
    r#"(secret_key ILIKE '%message%' AND secret_value::text ILIKE '%{"ok": true}%' OR secret_value @> '{"message": "{\"ok\": true}"}')"#
  );
}

#[test]
fn test_nested_grouping() {
  let raw = "(a:b OR (c:d AND e:f))";
  // Nested k:v use simple @>
  // Inner OR group gets wrapped. Inner AND group doesn't need wrapping by default.
  assert_sql_eq!(
    raw,
    "((secret_key ILIKE '%a%' AND secret_value::text ILIKE '%b%' OR \
     secret_value @> '{\"a\": \"b\"}') OR ((secret_key ILIKE '%c%' AND \
     secret_value::text ILIKE '%d%' OR secret_value @> '{\"c\": \"d\"}') AND \
     (secret_key ILIKE '%e%' AND secret_value::text ILIKE '%f%' OR \
     secret_value @> '{\"e\": \"f\"}')))"
  );
}

#[test]
fn test_double_nested_grouping_with_or() {
  let raw =
    "(foo:bar OR baz:qux) AND (alpha:beta OR gamma:delta) OR (i:j AND k:l)";
  let expected_sql = concat!(
    "((secret_key ILIKE '%foo%' AND secret_value::text ILIKE '%bar%' OR \
     secret_value @> '{\"foo\": \"bar\"}')",
    " OR ",
    "(secret_key ILIKE '%baz%' AND secret_value::text ILIKE '%qux%' OR \
     secret_value @> '{\"baz\": \"qux\"}'))",
    " AND ",
    "((secret_key ILIKE '%alpha%' AND secret_value::text ILIKE '%beta%' OR \
     secret_value @> '{\"alpha\": \"beta\"}')",
    " OR ",
    "(secret_key ILIKE '%gamma%' AND secret_value::text ILIKE '%delta%' OR \
     secret_value @> '{\"gamma\": \"delta\"}'))",
    " OR ",
    "((secret_key ILIKE '%i%' AND secret_value::text ILIKE '%j%' OR \
     secret_value @> '{\"i\": \"j\"}')",
    " AND ",
    "(secret_key ILIKE '%k%' AND secret_value::text ILIKE '%l%' OR \
     secret_value @> '{\"k\": \"l\"}'))"
  );

  assert_sql_eq!(raw, expected_sql);
}

#[test]
fn test_not_with_or() {
  let raw = "-(a:b OR c:d)";
  // NOT wraps the generated OR group's parentheses
  assert_sql_eq!(
    raw,
    "NOT ((secret_key ILIKE '%a%' AND secret_value::text ILIKE '%b%' OR \
     secret_value @> '{\"a\": \"b\"}') OR (secret_key ILIKE '%c%' AND \
     secret_value::text ILIKE '%d%' OR secret_value @> '{\"c\": \"d\"}'))"
  );
}

#[test]
fn test_not_with_and() {
  let raw = "-(a:b AND c:d)";
  // NOT wraps the AND group
  assert_sql_eq!(
    raw,
    "NOT ((secret_key ILIKE '%a%' AND secret_value::text ILIKE '%b%' OR \
     secret_value @> '{\"a\": \"b\"}') AND (secret_key ILIKE '%c%' AND \
     secret_value::text ILIKE '%d%' OR secret_value @> '{\"c\": \"d\"}'))"
  );
}

#[test]
fn test_mixed_not_and_or() {
  let raw = "-a:b AND (c:d OR -e:f)";
  // NOT applied to a:b, nested NOT applied to e:f, OR group wrapped
  assert_sql_eq!(
    raw,
    "NOT (secret_key ILIKE '%a%' AND secret_value::text ILIKE '%b%' OR \
     secret_value @> '{\"a\": \"b\"}') AND ((secret_key ILIKE '%c%' AND \
     secret_value::text ILIKE '%d%' OR secret_value @> '{\"c\": \"d\"}') OR \
     NOT (secret_key ILIKE '%e%' AND secret_value::text ILIKE '%f%' OR \
     secret_value @> '{\"e\": \"f\"}'))"
  );
}

#[test]
fn test_invalid_syntax() {
  // Test cases that should fail parsing
  assert!(query_to_sql("a:").is_err());
  assert!(query_to_sql(":b").is_err());
  assert!(query_to_sql("(").is_err());
  assert!(query_to_sql("a AND").is_err());
  assert!(query_to_sql("\"unterminated").is_err());
  assert!(query_to_sql("a:b OR AND c:d").is_err()); // adjacent operators
}
