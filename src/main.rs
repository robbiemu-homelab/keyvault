use axum::{
  Router,
  extract::{Extension, FromRequestParts, Json, Path},
  http::{HeaderMap, StatusCode, request::Parts},
  response::IntoResponse,
  routing::{get, post},
};
use dotenvy::dotenv;
use serde::Deserialize;
use sqlx::{PgPool, postgres::PgPoolOptions};
use std::collections::HashMap;
use std::{env, net::SocketAddr};


#[derive(Debug, Deserialize, Clone)]
struct Queries(HashMap<String, String>);

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
struct AppState {
  read_pool: PgPool,
  write_pool: PgPool,
  queries: Queries,
}

#[derive(Deserialize)]
struct SecretInput {
  key: String,
  value: serde_json::Value,
}

/// Extract the `X-PROJECT-KEY` header
struct ProjectKey(String);


// Simple header-check middleware
struct ReadAuth;
struct WriteAuth;

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
async fn get_secret(
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
async fn upsert_secret(
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
    .bind(&payload.key)
    .bind(&payload.value)
    .bind(&project)
    .execute(&state.write_pool)
    .await;

  match result {
    Ok(_) => StatusCode::NO_CONTENT.into_response(),
    Err(_) => (StatusCode::INTERNAL_SERVER_ERROR, "DB error").into_response(),
  }
}

#[tokio::main]
async fn main() {
  let queries: Queries = {
    let data = tokio::fs::read_to_string("queries.yaml")
      .await
      .expect("queries.yaml not found");
    serde_yaml::from_str(&data).expect("Failed to parse queries.yaml")
  };

  dotenv().ok();
  let host = env::var("PG_HOST").unwrap_or_else(|_| "postgres".into());
  let db = env::var("POSTGRES_DB").expect("POSTGRES_DB unset");
  let rusr = env::var("SECRETS_READ_USER").expect("...READ_USER");
  let rpwd = env::var("SECRETS_READ_PASSWORD").expect("...READ_PASSWORD");
  let wusr = env::var("SECRETS_WRITE_USER").expect("...WRITE_USER");
  let wpwd = env::var("SECRETS_WRITE_PASSWORD").expect("...WRITE_PASSWORD");

  let read_url = format!("postgres://{}:{}@{}/{}", rusr, rpwd, host, db);
  let write_url = format!("postgres://{}:{}@{}/{}", wusr, wpwd, host, db);

  let read_pool = PgPoolOptions::new()
    .max_connections(5)
    .connect(&read_url)
    .await
    .expect("read pool failed");
  let write_pool = PgPoolOptions::new()
    .max_connections(5)
    .connect(&write_url)
    .await
    .expect("write pool failed");

  let state = AppState { read_pool, write_pool, queries };

  let app = Router::new()
    .route("/secrets/:key", get(get_secret))
    .route("/secrets", post(upsert_secret))
    .layer(Extension(state));

  let addr = SocketAddr::from(([0, 0, 0, 0], 3000));
  let listener = tokio::net::TcpListener::bind(addr).await.unwrap();

  axum::serve(listener, app.into_make_service())
    .await
    .unwrap();
}
