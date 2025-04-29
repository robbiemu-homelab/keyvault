use axum::{
  extract::{Extension, FromRequestParts, Json, Path},
  http::{StatusCode, request::Parts},
  response::IntoResponse,
};
use lucene_parser::make_tantivy_index;
use serde::Deserialize;
use sqlx::PgPool;
use std::collections::HashMap;
use tantivy::query::QueryParser;

mod lucene_parser;
use crate::lucene_parser::query_to_sql;


// Load SQL queries from queries.yaml
#[derive(Debug, Deserialize, Clone)]
pub struct Queries(pub HashMap<String, String>);

impl Queries {
  pub fn get(&self, key: &str) -> Result<&str, String> {
    self
      .0
      .get(key)
      .map(|s| s.as_str())
      .ok_or_else(|| format!("Missing query '{}'", key))
  }
}

// Shared application state
#[derive(Clone)]
pub struct AppState {
  pub read_pool: PgPool,
  pub write_pool: PgPool,
  pub queries: Queries,
}

// Request payloads
#[derive(Deserialize)]
pub struct SecretInput {
  pub key: String,
  pub value: serde_json::Value,
}

#[derive(Deserialize)]
pub struct SecretValueOnly {
  pub value: serde_json::Value,
}

#[derive(Deserialize)]
pub struct SearchInput {
  pub query: Option<String>,
}

// Extracted headers and auth types
pub struct ProjectKey(pub String);
pub struct ReadAuth;
pub struct WriteAuth;

// Implement Axum extractors for authentication and project scoping
impl<S> FromRequestParts<S> for ReadAuth
where
  S: Send + Sync + 'static,
{
  type Rejection = (StatusCode, &'static str);

  async fn from_request_parts(
    parts: &mut Parts,
    _: &S,
  ) -> Result<Self, Self::Rejection> {
    let header = parts.headers.get("x-api-key").and_then(|v| v.to_str().ok());
    let read = std::env::var("API_MASTER_KEY_READ")
      .expect("API_MASTER_KEY_READ missing");
    let write = std::env::var("API_MASTER_KEY_WRITE")
      .expect("API_MASTER_KEY_WRITE missing");
    match header {
      Some(key) if key == read || key == write => Ok(ReadAuth),
      _ => Err((StatusCode::UNAUTHORIZED, "Read key invalid")),
    }
  }
}

impl<S> FromRequestParts<S> for WriteAuth
where
  S: Send + Sync + 'static,
{
  type Rejection = (StatusCode, &'static str);

  async fn from_request_parts(
    parts: &mut Parts,
    _: &S,
  ) -> Result<Self, Self::Rejection> {
    match parts.headers.get("x-api-key").and_then(|v| v.to_str().ok()) {
      Some(key)
        if key
          == std::env::var("API_MASTER_KEY_WRITE")
            .expect("API_MASTER_KEY_WRITE missing") =>
      {
        Ok(WriteAuth)
      }
      _ => Err((StatusCode::UNAUTHORIZED, "Write key invalid")),
    }
  }
}

impl<S> FromRequestParts<S> for ProjectKey
where
  S: Send + Sync + 'static,
{
  type Rejection = (StatusCode, &'static str);

  async fn from_request_parts(
    parts: &mut Parts,
    _: &S,
  ) -> Result<Self, Self::Rejection> {
    let key = parts
      .headers
      .get("x-project-key")
      .and_then(|v| v.to_str().ok())
      .ok_or((StatusCode::BAD_REQUEST, "Missing X-PROJECT-KEY"))?;
    Ok(ProjectKey(key.to_owned()))
  }
}

// GET /secrets/:key
pub async fn get_secret(
  _auth: ReadAuth,
  ProjectKey(project): ProjectKey,
  Path(key): Path<String>,
  Extension(state): Extension<AppState>,
) -> impl IntoResponse {
  let sql = match state.queries.get("get_secret") {
    Ok(q) => q,
    Err(err) => {
      return (
        StatusCode::INTERNAL_SERVER_ERROR,
        format!("Query error: {}", err),
      )
        .into_response();
    }
  };

  let rec: Result<Option<(serde_json::Value,)>, _> = sqlx::query_as(sql)
    .bind(&key)
    .bind(&project)
    .fetch_optional(&state.read_pool)
    .await;

  match rec {
    Ok(Some((value,))) => (StatusCode::OK, Json(value)).into_response(),
    Ok(None) => (StatusCode::NOT_FOUND, "Not found").into_response(),
    Err(_) => (StatusCode::INTERNAL_SERVER_ERROR, "DB error").into_response(),
  }
}

// POST /secrets
#[axum::debug_handler]
pub async fn upsert_secret(
  _auth: WriteAuth,
  ProjectKey(project): ProjectKey,
  Extension(state): Extension<AppState>,
  Json(payload): Json<SecretInput>,
) -> impl IntoResponse {
  let sql = match state.queries.get("upsert_secret") {
    Ok(q) => q,
    Err(err) => {
      return (
        StatusCode::INTERNAL_SERVER_ERROR,
        format!("Query error: {}", err),
      )
        .into_response();
    }
  };

  let result = sqlx::query(sql)
    .bind(&project)
    .bind(&payload.key)
    .bind(&payload.value)
    .execute(&state.write_pool)
    .await;

  match result {
    Ok(_) => StatusCode::NO_CONTENT.into_response(),
    Err(_) => (StatusCode::INTERNAL_SERVER_ERROR, "DB error").into_response(),
  }
}

// PUT /secrets/:key
pub async fn upsert_secret_by_path(
  _auth: WriteAuth,
  ProjectKey(project): ProjectKey,
  Path(key): Path<String>,
  Extension(state): Extension<AppState>,
  Json(payload): Json<SecretValueOnly>,
) -> impl IntoResponse {
  let sql = match state.queries.get("upsert_secret") {
    Ok(q) => q,
    Err(err) => {
      return (
        StatusCode::INTERNAL_SERVER_ERROR,
        format!("Query error: {}", err),
      )
        .into_response();
    }
  };

  let result = sqlx::query(sql)
    .bind(&project)
    .bind(&key)
    .bind(&payload.value)
    .execute(&state.write_pool)
    .await;

  match result {
    Ok(_) => StatusCode::NO_CONTENT.into_response(),
    Err(_) => (StatusCode::INTERNAL_SERVER_ERROR, "DB error").into_response(),
  }
}

// DELETE /secrets/:key
pub async fn delete_secret(
  _auth: WriteAuth,
  ProjectKey(project): ProjectKey,
  Path(key): Path<String>,
  Extension(state): Extension<AppState>,
) -> impl IntoResponse {
  let sql = match state.queries.get("delete_secret") {
    Ok(q) => q,
    Err(err) => {
      return (
        StatusCode::INTERNAL_SERVER_ERROR,
        format!("Query error: {}", err),
      )
        .into_response();
    }
  };

  let result = sqlx::query(sql)
    .bind(&key)
    .bind(&project)
    .execute(&state.write_pool)
    .await;

  match result {
    Ok(_) => StatusCode::NO_CONTENT.into_response(),
    Err(_) => (StatusCode::INTERNAL_SERVER_ERROR, "DB error").into_response(),
  }
}

// POST /search
pub async fn search_secrets(
  _auth: ReadAuth,
  ProjectKey(project): ProjectKey,
  Extension(state): Extension<AppState>,
  Json(payload): Json<SearchInput>,
) -> impl IntoResponse {
  // 1) Setup index + parser
  let raw = payload.query.clone().unwrap_or_default();
  let (index, sk_field, sv_field) = match make_tantivy_index() {
    Ok(res) => res,
    Err(e) => {
      return (
        StatusCode::INTERNAL_SERVER_ERROR,
        format!("Index error: {}", e),
      )
        .into_response();
    }
  };
  let parser = QueryParser::for_index(&index, vec![sk_field, sv_field]);

  // 2) Parse Lucene‐style syntax
  let tantivy_query = match parser.parse_query(&raw) {
    Ok(q) => q,
    Err(e) => {
      return (StatusCode::BAD_REQUEST, format!("Query parse error: {}", e))
        .into_response();
    }
  };

  tracing::debug!("🔍 AST = {:#?}", tantivy_query);

  // 3) AST → SQL WHERE clause
  let where_clause =
    query_to_sql(tantivy_query.as_ref(), sk_field, sv_field, raw.as_str());

  // 4) Execute dynamic SQL safely
  let sql = format!(
    "SELECT secret_key, project_key, secret_value FROM secrets WHERE \
     project_key = $1 AND ({})",
    where_clause
  );

  tracing::debug!("🔍 raw query = {:?}", raw);
  tracing::debug!("🔍 generated WHERE clause = {}", where_clause);

  let rows =
    match sqlx::query_as::<_, (String, String, serde_json::Value)>(&sql)
      .bind(&project)
      .fetch_all(&state.read_pool)
      .await
    {
      Ok(r) => r,
      Err(e) => {
        return (
          StatusCode::INTERNAL_SERVER_ERROR,
          format!("DB error: {}", e),
        )
          .into_response();
      }
    };

  // 5) Return JSON
  let secrets = rows
    .into_iter()
    .map(|(k, p, v)| {
      serde_json::json!({
          "secret_key": k,
          "project_key": p,
          "secret_value": v,
      })
    })
    .collect::<Vec<_>>();
  (StatusCode::OK, Json(secrets)).into_response()
}
