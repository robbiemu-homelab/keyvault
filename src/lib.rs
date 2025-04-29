use axum::{
  extract::{Extension, FromRequestParts, Json, Path},
  http::{StatusCode, request::Parts},
  response::IntoResponse,
};
use serde::Deserialize;
use sqlx::PgPool;
use std::collections::HashMap;


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

#[derive(Clone)]
pub struct AppState {
  pub read_pool: PgPool,
  pub write_pool: PgPool,
  pub queries: Queries,
}

#[derive(Deserialize)]
pub struct SecretInput {
  pub key: String,
  pub value: serde_json::Value,
}

/// Extract the `X-PROJECT-KEY` header
pub struct ProjectKey(String);


// Simple header-check middleware
pub struct ReadAuth;
pub struct WriteAuth;

impl<S> FromRequestParts<S> for ReadAuth
where
  S: Send + Sync + 'static,
{
  type Rejection = (StatusCode, &'static str);

  // native async-fn-in-trait—no macro
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

  // native async-fn-in-trait—no macro
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
    // read X-PROJECT-KEY header
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
  let query = match state.queries.get("get_secret") {
    Ok(q) => q,
    Err(e) => {
      return (
        StatusCode::INTERNAL_SERVER_ERROR,
        format!("Query error: {}", e),
      )
        .into_response();
    }
  };

  let rec: Result<Option<(serde_json::Value,)>, _> =
    sqlx::query_as::<_, (serde_json::Value,)>(query)
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
  let query = match state.queries.get("upsert_secret") {
    Ok(q) => q,
    Err(e) => {
      return (
        StatusCode::INTERNAL_SERVER_ERROR,
        format!("Query error: {}", e),
      )
        .into_response();
    }
  };

  let result = sqlx::query(query)
    .bind(&project) // $1 → project_key
    .bind(&payload.key) // $2 → secret_key
    .bind(&payload.value) // $3 → secret_value
    .execute(&state.write_pool)
    .await;


  // match result {
  //   Ok(_) => StatusCode::NO_CONTENT.into_response(),
  //   Err(_) => (StatusCode::INTERNAL_SERVER_ERROR, "DB error").into_response(),
  // }
  match result {
    Ok(_) => StatusCode::NO_CONTENT.into_response(),
    Err(err) => {
      // print the full SQLx error to stderr
      eprintln!("[upsert_secret] SQLx error = {:?}", err);
      (StatusCode::INTERNAL_SERVER_ERROR, "DB error").into_response()
    }
  }
}
