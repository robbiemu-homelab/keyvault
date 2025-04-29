use std::str;
use tantivy::{
  Index,
  query::{BooleanQuery, Occur, PhraseQuery, Query, TermQuery},
  schema::{Field, Schema, TEXT},
};

pub fn make_tantivy_index()
-> tantivy::Result<(Index, tantivy::schema::Field, tantivy::schema::Field)> {
  let mut sb = Schema::builder();
  let sk_field = sb.add_text_field("secret_key", TEXT);
  let sv_field = sb.add_text_field("secret_value", TEXT);
  let schema = sb.build();
  let index = Index::create_in_ram(schema);
  Ok((index, sk_field, sv_field))
}

/// Recursively walk the AST `Query` and emit SQL, aware of which field was queried.
pub fn query_to_sql(
  q: &(dyn Query),
  sk_field: Field,
  sv_field: Field,
  raw: &str,
) -> String {
  // 0a) JSON key:value single‐term search (no spaces, no wildcard)
  if !raw.contains(' ') && !raw.ends_with('*') && raw.contains(':') {
    let mut parts = raw.splitn(2, ':');
    let key = parts.next().unwrap().replace('\'', "''");
    let val = parts.next().unwrap().replace('\'', "''");
    // Clause A: key in secret_key AND value anywhere in blob
    let a = format!(
      "(secret_key ILIKE '%{k}%') AND (secret_value::text ILIKE '%{v}%')",
      k = key,
      v = val
    );
    // Clause B: JSON‐pair match anywhere
    let b = format!(
      "secret_value::text ILIKE '%\"{k}\":\"{v}\"%'",
      k = key,
      v = val
    );
    return format!("({}) OR ({})", a, b);
  }

  // 0b) Single‐term fallback (no spaces, no wildcard)
  if !raw.contains(' ') && !raw.ends_with('*') {
    let term = raw.replace('\'', "''");
    let a = format!("secret_key ILIKE '%{}%'", term);
    let b = format!("secret_value::text ILIKE '%{}%'", term);
    return format!("({}) OR ({})", a, b);
  }

  // 1) TermQuery → respect field-aware search
  if let Some(tq) = q.as_any().downcast_ref::<TermQuery>() {
    let value = tq.term().value();
    let bytes = value.as_bytes().unwrap_or(&[]);
    let term = str::from_utf8(bytes).unwrap_or("").replace('\'', "''");
    if tq.term().field() == sk_field {
      return format!("secret_key ILIKE '%{}%'", term);
    } else {
      return format!("secret_value::text ILIKE '%{}%'", term);
    }
  }

  // 2) PhraseQuery → phrase‐level search
  if let Some(pq) = q.as_any().downcast_ref::<PhraseQuery>() {
    let mut terms = Vec::new();
    pq.query_terms(&mut |t, _| terms.push(t.clone()));
    let phrase = terms
      .iter()
      .map(|t| {
        let binding = t.value();
        let bytes = binding.as_bytes().unwrap_or(&[]);
        str::from_utf8(bytes).unwrap_or("").replace('\'', "''")
      })
      .collect::<Vec<_>>()
      .join(" ");
    return format!("secret_value::text ILIKE '%{}%'", phrase);
  }

  // 3) BooleanQuery → AND/OR/NOT combinations
  if let Some(bq) = q.as_any().downcast_ref::<BooleanQuery>() {
    let mut musts = Vec::new();
    let mut shoulds = Vec::new();
    let mut must_nots = Vec::new();
    for (occur, sub) in bq.clauses() {
      let sql = query_to_sql(sub.as_ref(), sk_field, sv_field, raw);
      match occur {
        Occur::Must => musts.push(sql),
        Occur::Should => shoulds.push(sql),
        Occur::MustNot => must_nots.push(sql),
      }
    }
    let mut clauses = Vec::new();
    if !musts.is_empty() {
      clauses.push(
        musts
          .into_iter()
          .map(|s| format!("({})", s))
          .collect::<Vec<_>>()
          .join(" AND "),
      );
    }
    if !shoulds.is_empty() {
      clauses.push(format!(
        "({})",
        shoulds
          .into_iter()
          .map(|s| format!("({})", s))
          .collect::<Vec<_>>()
          .join(" OR ")
      ));
    }
    if !must_nots.is_empty() {
      clauses.push(format!(
        "NOT ({})",
        must_nots
          .into_iter()
          .map(|s| format!("({})", s))
          .collect::<Vec<_>>()
          .join(" AND ")
      ));
    }
    return clauses.join(" AND ");
  }

  // 4) Fallback: match all
  "TRUE".into()
}
