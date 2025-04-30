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

pub fn extract_key_values(raw: &str) -> Vec<(String, String)> {
  raw
    // split on whitespace or “ OR ” later
    .split_whitespace()
    .filter_map(|tok| {
      let mut parts = tok.splitn(2, ':');
      let k = parts.next()?.trim_matches('"').to_string();
      let v = parts.next()?.trim_matches('"').to_string();
      if k.is_empty() || v.is_empty() {
        None
      } else {
        Some((k, v))
      }
    })
    .collect()
}

/// Recursively walk the AST `Query` and emit SQL, aware of which field was queried.
pub fn query_to_sql(
  q: &(dyn Query),
  sk_field: Field,
  sv_field: Field,
  raw: &str,
) -> String {
  // 0) Multi key:value pairs (AND by default, OR if “ OR ” present)
  // 0) Multi key:value pairs (AND by default, OR if “ OR ” present; support -key:value as NOT)
  let pairs = extract_key_values(raw);
  if pairs.len() > 1 {
    let op = if raw.to_uppercase().contains(" OR ") {
      " OR "
    } else {
      " AND "
    };

    let clauses: Vec<String> = pairs
      .into_iter()
      .map(|(raw_key, raw_val)| {
        // detect negation prefix
        let negated = raw_key.starts_with('-');
        let key = raw_key.trim_start_matches('-').replace('\'', "''");
        let val = raw_val.replace('\'', "''");

        // build base clause
        let clause = match key.as_str() {
          "secret_key" => format!("secret_key ILIKE '%{}%'", val),
          "secret_value" => format!("secret_value::text ILIKE '%{}%'", val),
          other => format!("secret_value @> '{{\"{}\": \"{}\"}}'", other, val),
        };

        // wrap in NOT(...) if needed
        if negated {
          format!("NOT ({})", clause)
        } else {
          clause
        }
      })
      .collect();

    return clauses.join(op);
  }

  // 1a) Single key:value JSON search (no spaces, no wildcard)
  // 1a) Single key:value fallback (no spaces, no wildcard)
  if !raw.contains(' ') && !raw.ends_with('*') && raw.contains(':') {
    // 1) detect negation
    let negated = raw.starts_with('-');
    let cleaned = raw.trim_start_matches('-');

    // 2) split into key and val
    let mut parts = cleaned.splitn(2, ':');
    let key = parts.next().unwrap().replace('\'', "''");
    let val = parts.next().unwrap().replace('\'', "''");

    // 3) build Clause A differently if it's a real field
    let clause_a = match key.as_str() {
      "secret_key" => {
        // search secret_key for the *value*
        format!("secret_key ILIKE '%{}%'", val)
      }
      "secret_value" => {
        // search the JSON blob text for the *value*
        format!("secret_value::text ILIKE '%{}%'", val)
      }
      _ => {
        // your old fallback: key in secret_key & val in the blob
        format!(
          "(secret_key ILIKE '%{k}%' AND secret_value::text ILIKE '%{v}%')",
          k = key,
          v = val
        )
      }
    };

    // 4) Clause B: JSON‐aware match on the pair
    let clause_b = format!("secret_value @> '{{\"{}\": \"{}\"}}'", key, val);

    // 5) combine with OR, then negate if needed
    let combined = format!("({}) OR ({})", clause_a, clause_b);
    return if negated {
      format!("NOT ({})", combined)
    } else {
      combined
    };
  }
  // 1b) Single‐term fallback (no spaces, no wildcard)
  if !raw.contains(' ') && !raw.ends_with('*') {
    // detect negation
    let negated = raw.starts_with('-');
    let term_str = if negated {
      raw.trim_start_matches('-')
    } else {
      raw
    };
    let term = term_str.replace('\'', "''");

    let clause = format!(
      "(secret_key ILIKE '%{}%' OR secret_value::text ILIKE '%{}%')",
      term, term
    );

    return if negated {
      format!("NOT ({})", clause)
    } else {
      clause
    };
  }

  // 2) TermQuery → respect field-aware search
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

  // 3) PhraseQuery → phrase‐level search
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

  // 4) BooleanQuery → AND/OR/NOT combinations
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
          .map(|inner| format!("({})", inner))
          .collect::<Vec<_>>()
          .join(" AND "),
      );
    }
    if !shoulds.is_empty() {
      clauses.push(format!(
        "({})",
        shoulds
          .into_iter()
          .map(|inner| format!("({})", inner))
          .collect::<Vec<_>>()
          .join(" OR ")
      ));
    }
    if !must_nots.is_empty() {
      clauses.push(format!(
        "NOT ({})",
        must_nots
          .into_iter()
          .map(|inner| format!("({})", inner))
          .collect::<Vec<_>>()
          .join(" AND ")
      ));
    }
    return clauses.join(" AND ");
  }

  // 5) Fallback: match all
  "TRUE".into()
}
