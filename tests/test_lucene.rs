use keyvault::lucene_parser::{make_tantivy_index, query_to_sql};
use tantivy::query::AllQuery;

#[test]
fn test_simple_key_value_includes() {
  let (_idx, sk, sv) = make_tantivy_index().unwrap();
  let raw = "something:wild";
  let sql = query_to_sql(&AllQuery, sk, sv, raw);
  assert_eq!(
    sql,
    "((secret_key ILIKE '%something%' AND secret_value::text ILIKE '%wild%')) \
     OR (secret_value @> '{\"something\": \"wild\"}')"
  );
}

#[test]
fn test_simple_key_value_excludes() {
  let (_idx, sk, sv) = make_tantivy_index().unwrap();
  let raw = "-something:wild";
  let sql = query_to_sql(&AllQuery, sk, sv, raw);
  assert_eq!(
    sql,
    "NOT (((secret_key ILIKE '%something%' AND secret_value::text ILIKE \
     '%wild%')) OR (secret_value @> '{\"something\": \"wild\"}'))"
  );
}

#[test]
fn test_schema_field_key_includes() {
  let (_idx, sk, sv) = make_tantivy_index().unwrap();
  let raw = "secret_key:test_initial_value";
  let sql = query_to_sql(&AllQuery, sk, sv, raw);
  assert_eq!(
    sql,
    "(secret_key ILIKE '%test_initial_value%') OR (secret_value @> \
     '{\"secret_key\": \"test_initial_value\"}')"
  );
}

#[test]
fn test_schema_field_key_excludes() {
  let (_idx, sk, sv) = make_tantivy_index().unwrap();
  let raw = "-secret_key:test_initial_value";
  let sql = query_to_sql(&AllQuery, sk, sv, raw);
  assert_eq!(
    sql,
    "NOT ((secret_key ILIKE '%test_initial_value%') OR (secret_value @> \
     '{\"secret_key\": \"test_initial_value\"}'))"
  );
}

#[test]
fn test_multiple_and() {
  let (_idx, sk, sv) = make_tantivy_index().unwrap();
  let raw = "foo:bar baz:qux";
  let sql = query_to_sql(&AllQuery, sk, sv, raw);
  assert_eq!(
    sql,
    "secret_value @> '{\"foo\": \"bar\"}' AND secret_value @> '{\"baz\": \
     \"qux\"}'"
  );
}

#[test]
fn test_multiple_or() {
  let (_idx, sk, sv) = make_tantivy_index().unwrap();
  let raw = "foo:bar OR baz:qux";
  let sql = query_to_sql(&AllQuery, sk, sv, raw);
  assert_eq!(
    sql,
    "secret_value @> '{\"foo\": \"bar\"}' OR secret_value @> '{\"baz\": \
     \"qux\"}'"
  );
}

#[test]
fn test_single_term_includes() {
  let (_idx, sk, sv) = make_tantivy_index().unwrap();
  let raw = "term";
  let sql = query_to_sql(&AllQuery, sk, sv, raw);
  assert_eq!(
    sql,
    "(secret_key ILIKE '%term%' OR secret_value::text ILIKE '%term%')"
  );
}

#[test]
fn test_single_term_excludes() {
  let (_idx, sk, sv) = make_tantivy_index().unwrap();
  let raw = "-term";
  let sql = query_to_sql(&AllQuery, sk, sv, raw);
  assert_eq!(
    sql,
    "NOT ((secret_key ILIKE '%term%' OR secret_value::text ILIKE '%term%'))"
  );
}
