use axum::Extension;
use axum::body::to_bytes;
use axum::http::{Request, StatusCode};
use axum::{Router, body::Body};
use dotenvy::dotenv;
use once_cell::sync::Lazy;
use serde_json::Value;
use sqlx::{Executor, PgPool};
use std::collections::HashMap;
use tokio::runtime::Runtime;
use tokio::sync::OnceCell;
use tower::util::ServiceExt; // for .oneshot
use uuid::Uuid;

use keyvault::{
  AppState, Queries, delete_secret, get_secret, search_secrets, upsert_secret,
  upsert_secret_by_path,
};

// Single-instance ephemeral test database for the suite
static TEST_DB: Lazy<OnceCell<TestDb>> = Lazy::new(OnceCell::const_new);

/// Temporary database holder
struct TestDb {
  name: String,
}

impl TestDb {
  /// Create a unique test database, set up schema, grants, and seed data
  async fn init() -> TestDb {
    // Load both .env and .env.test
    dotenv().ok();
    dotenvy::from_filename(".env.test").ok();

    // Admin credentials (must have CREATEROLE and CREATEDB)
    let admin_user =
      std::env::var("POSTGRES_USER").expect("POSTGRES_USER must be set");
    let admin_pwd = std::env::var("POSTGRES_PASSWORD")
      .expect("POSTGRES_PASSWORD must be set");
    let host = std::env::var("PG_HOST").unwrap_or_else(|_| "localhost".into());

    // Connection URL for admin operations
    let admin_url = if admin_pwd.is_empty() {
      format!("postgres://{}@{}/postgres", admin_user, host)
    } else {
      format!("postgres://{}:{}@{}/postgres", admin_user, admin_pwd, host)
    };
    let admin_pool = PgPool::connect(&admin_url).await.unwrap();

    // ── ensure reader/writer roles exist ────────────────────────────────
    admin_pool
      .execute(
        r#"DO $$
BEGIN
  IF NOT EXISTS (SELECT 1 FROM pg_roles WHERE rolname='secrets_reader') THEN
      CREATE ROLE secrets_reader;
  END IF;
END
$$;"#,
      )
      .await
      .unwrap();
    admin_pool
      .execute(
        r#"DO $$
BEGIN
  IF NOT EXISTS (SELECT 1 FROM pg_roles WHERE rolname='secrets_writer') THEN
      CREATE ROLE secrets_writer;
  END IF;
END
$$;"#,
      )
      .await
      .unwrap();

    // ── create login users and assign roles ─────────────────────────────
    let read_user = std::env::var("SECRETS_READ_USER").unwrap();
    let read_pwd = std::env::var("SECRETS_READ_PASSWORD").unwrap();
    admin_pool
      .execute(
        format!(
          r#"DO $$
BEGIN
  IF NOT EXISTS (SELECT 1 FROM pg_roles WHERE rolname = '{0}') THEN
      CREATE ROLE "{0}" LOGIN PASSWORD '{1}';
  END IF;
END
$$;"#,
          read_user, read_pwd
        )
        .as_str(),
      )
      .await
      .unwrap();
    admin_pool
      .execute(format!("GRANT secrets_reader TO \"{}\";", read_user).as_str())
      .await
      .unwrap();

    let write_user = std::env::var("SECRETS_WRITE_USER").unwrap();
    let write_pwd = std::env::var("SECRETS_WRITE_PASSWORD").unwrap();
    admin_pool
      .execute(
        format!(
          r#"DO $$
BEGIN
  IF NOT EXISTS (SELECT 1 FROM pg_roles WHERE rolname = '{0}') THEN
      CREATE ROLE "{0}" LOGIN PASSWORD '{1}';
  END IF;
END
$$;"#,
          write_user, write_pwd
        )
        .as_str(),
      )
      .await
      .unwrap();
    admin_pool
      .execute(format!("GRANT secrets_writer TO \"{}\";", write_user).as_str())
      .await
      .unwrap();

    // ── create a fresh database ────────────────────────────────────────
    let name = format!("testdb_{}", Uuid::new_v4().simple());
    admin_pool
      .execute(format!("CREATE DATABASE {}", name).as_str())
      .await
      .unwrap();

    // ── allow roles to connect ─────────────────────────────────────────
    admin_pool
      .execute(
        format!("GRANT CONNECT ON DATABASE {} TO secrets_reader;", name)
          .as_str(),
      )
      .await
      .unwrap();
    admin_pool
      .execute(
        format!("GRANT CONNECT ON DATABASE {} TO secrets_writer;", name)
          .as_str(),
      )
      .await
      .unwrap();

    // Build test DB URL and connect as admin
    let test_url = if admin_pwd.is_empty() {
      format!("postgres://{}@{}/{}", admin_user, host, name)
    } else {
      format!("postgres://{}:{}@{}/{}", admin_user, admin_pwd, host, name)
    };
    let test_admin = PgPool::connect(&test_url).await.unwrap();

    // ── create schema and table ─────────────────────────────────────────
    test_admin
      .execute(r#"CREATE SCHEMA IF NOT EXISTS public;"#)
      .await
      .unwrap();
    test_admin
      .execute(
        r#"
          CREATE TABLE IF NOT EXISTS secrets (
              project_key TEXT NOT NULL,
              secret_key TEXT NOT NULL,
              secret_value JSONB NOT NULL,
              PRIMARY KEY (project_key, secret_key)
          );
      "#,
      )
      .await
      .unwrap();

    // ── grant privileges to roles ───────────────────────────────────────
    test_admin
      .execute(r#"GRANT USAGE ON SCHEMA public TO secrets_reader;"#)
      .await
      .unwrap();
    test_admin
      .execute(r#"GRANT USAGE ON SCHEMA public TO secrets_writer;"#)
      .await
      .unwrap();
    test_admin
      .execute(r#"GRANT SELECT ON secrets TO secrets_reader;"#)
      .await
      .unwrap();
    test_admin
      .execute(
        r#"GRANT SELECT, INSERT, UPDATE, DELETE ON secrets TO secrets_writer;"#,
      )
      .await
      .unwrap();

    // ── seed initial data as admin ─────────────────────────────────────
    sqlx::query(
      "INSERT INTO secrets (project_key, secret_key, secret_value) VALUES \
       ($1, $2, $3)",
    )
    .bind("test_project")
    .bind("mykey")
    .bind(serde_json::json!({"some":"value"}))
    .execute(&test_admin)
    .await
    .unwrap();

    TestDb { name }
  }
}

impl Drop for TestDb {
  fn drop(&mut self) {
    // Clean up the test database when program exits
    let name = self.name.clone();
    dotenv().ok();
    dotenvy::from_filename(".env.test").ok();
    let admin_user =
      std::env::var("POSTGRES_USER").expect("POSTGRES_USER must be set");
    let admin_pwd = std::env::var("POSTGRES_PASSWORD")
      .expect("POSTGRES_PASSWORD must be set");
    let host = std::env::var("PG_HOST").unwrap_or_else(|_| "localhost".into());

    let admin_url = if admin_pwd.is_empty() {
      format!("postgres://{}@{}/postgres", admin_user, host)
    } else {
      format!("postgres://{}:{}@{}/postgres", admin_user, admin_pwd, host)
    };
    let rt = Runtime::new().unwrap();
    rt.block_on(async move {
      let admin_pool = PgPool::connect(&admin_url).await.unwrap();
      admin_pool
        .execute(format!("DROP DATABASE IF EXISTS {}", name).as_str())
        .await
        .unwrap();
    });
  }
}

/// Ensure the ephemeral database is created once per test session
async fn test_setup() {
  // ensure the DB exists
  let test_db = TEST_DB.get_or_init(TestDb::init).await;

  // reconnect as admin directly into that new test DB
  let admin_user = std::env::var("POSTGRES_USER").unwrap();
  let admin_pwd = std::env::var("POSTGRES_PASSWORD").unwrap();
  let host = std::env::var("PG_HOST").unwrap_or_else(|_| "localhost".into());

  let test_url = if admin_pwd.is_empty() {
    format!("postgres://{}@{}/{}", admin_user, host, test_db.name)
  } else {
    format!(
      "postgres://{}:{}@{}/{}",
      admin_user, admin_pwd, host, test_db.name
    )
  };
  let test_admin = PgPool::connect(&test_url).await.unwrap();

  // reset table and reseed the original secret
  test_admin.execute("TRUNCATE TABLE secrets;").await.unwrap();
  sqlx::query(
    "INSERT INTO secrets (project_key, secret_key, secret_value) VALUES ($1, \
     $2, $3)",
  )
  .bind("test_project")
  .bind("mykey")
  .bind(serde_json::json!({"some":"value"}))
  .execute(&test_admin)
  .await
  .unwrap();
}

/// Build AppState pointing at the ephemeral DB
async fn create_test_state() -> AppState {
  test_setup().await;
  // Set API key headers
  unsafe {
    std::env::set_var("API_MASTER_KEY_READ", "test-api-key-read");
    std::env::set_var("API_MASTER_KEY_WRITE", "test-api-key-write");
  }

  // Queries map
  let mut queries_map = HashMap::new();
  queries_map.insert(
    "get_secret".into(),
    "SELECT secret_value FROM secrets WHERE secret_key = $1 AND project_key = \
     $2"
      .into(),
  );
  queries_map.insert(
    "upsert_secret".into(),
    // match your handler: project_key first, then key, then value::jsonb
    "INSERT INTO secrets (project_key, secret_key, secret_value) VALUES ($1, \
     $2, $3::jsonb) ON CONFLICT (project_key, secret_key) DO UPDATE SET \
     secret_value = EXCLUDED.secret_value"
      .into(),
  );

  // ─── support DELETE /secrets/:key ───────────
  queries_map.insert(
    "delete_secret".into(),
    "DELETE FROM secrets WHERE secret_key = $1 AND project_key = $2".into(),
  );
  // ─── support POST /search ────────────────────
  // ILIKE '%%' will match everything when term == ""
  queries_map.insert(
    "search_secrets".into(),
    "SELECT secret_key, project_key, secret_value FROM secrets WHERE \
     project_key = $1 AND secret_key ILIKE '%' || $2 || '%'"
      .into(),
  );

  let queries = Queries(queries_map);

  // Build read/write pools with vault roles
  let host = std::env::var("PG_HOST").unwrap_or_else(|_| "localhost".into());
  let db_name = &TEST_DB.get().unwrap().name;
  let read_user =
    std::env::var("SECRETS_READ_USER").expect("SECRETS_READ_USER must be set");
  let read_pwd = std::env::var("SECRETS_READ_PASSWORD")
    .expect("SECRETS_READ_PASSWORD must be set");
  let write_user = std::env::var("SECRETS_WRITE_USER")
    .expect("SECRETS_WRITE_USER must be set");
  let write_pwd = std::env::var("SECRETS_WRITE_PASSWORD")
    .expect("SECRETS_WRITE_PASSWORD must be set");

  let read_url =
    format!("postgres://{}:{}@{}/{}", read_user, read_pwd, host, db_name);
  let write_url = format!(
    "postgres://{}:{}@{}/{}",
    write_user, write_pwd, host, db_name
  );

  let read_pool = PgPool::connect_lazy(&read_url).unwrap();
  let write_pool = PgPool::connect_lazy(&write_url).unwrap();

  AppState { read_pool, write_pool, queries }
}

/// Create test HTTP app and shared state
async fn create_test_app() -> (Router, AppState) {
  let state = create_test_state().await;

  let app = Router::new()
    .route(
      "/secrets/{key}",
      axum::routing::get(get_secret)
        .put(upsert_secret_by_path)
        .delete(delete_secret),
    )
    .route("/secrets", axum::routing::post(upsert_secret))
    .route("/search", axum::routing::post(search_secrets))
    .layer(Extension(state.clone()));

  (app, state)
}

#[tokio::test]
async fn test_get_secret_happy_path() {
  let (app, _) = create_test_app().await;
  let res = app
    .oneshot(
      Request::builder()
        .uri("/secrets/mykey")
        .header("x-api-key", "test-api-key-read")
        .header("x-project-key", "test_project")
        .body(Body::empty())
        .unwrap(),
    )
    .await
    .unwrap();
  assert_eq!(res.status(), StatusCode::OK);
}

#[tokio::test]
async fn test_get_secret_bad_api_key() {
  let (app, _) = create_test_app().await;
  let res = app
    .oneshot(
      Request::builder()
        .uri("/secrets/mykey")
        .header("x-api-key", "wrong-api-key")
        .header("x-project-key", "test_project")
        .body(Body::empty())
        .unwrap(),
    )
    .await
    .unwrap();
  assert_eq!(res.status(), StatusCode::UNAUTHORIZED);
}

#[tokio::test]
async fn test_get_secret_missing_project_key() {
  let (app, _) = create_test_app().await;
  let res = app
    .oneshot(
      Request::builder()
        .uri("/secrets/mykey")
        .header("x-api-key", "test-api-key-read")
        .body(Body::empty())
        .unwrap(),
    )
    .await
    .unwrap();
  assert_eq!(res.status(), StatusCode::BAD_REQUEST);
}

#[tokio::test]
async fn test_get_secret_not_found() {
  let (app, _) = create_test_app().await;
  let res = app
    .oneshot(
      Request::builder()
        .uri("/secrets/nonexistentkey")
        .header("x-api-key", "test-api-key-read")
        .header("x-project-key", "test_project")
        .body(Body::empty())
        .unwrap(),
    )
    .await
    .unwrap();
  assert_eq!(res.status(), StatusCode::NOT_FOUND);
}

#[tokio::test]
async fn test_upsert_secret_happy_path() {
  let (app, _) = create_test_app().await;
  let payload = r#"{"key":"newkey","value":{"foo":"bar"}}"#;

  let res = app
    .oneshot(
      Request::builder()
        .method("POST")
        .uri("/secrets")
        .header("x-api-key", "test-api-key-write")
        .header("x-project-key", "test_project")
        .header("content-type", "application/json")
        .body(Body::from(payload))
        .unwrap(),
    )
    .await
    .unwrap();
  assert_eq!(res.status(), StatusCode::NO_CONTENT);
}

#[tokio::test]
async fn test_upsert_secret_bad_api_key() {
  let (app, _) = create_test_app().await;
  let payload = r#"{"key":"another","value":{"a":1}}"#;

  let res = app
    .oneshot(
      Request::builder()
        .method("POST")
        .uri("/secrets")
        .header("x-api-key", "wrong-api-key")
        .header("x-project-key", "test_project")
        .header("content-type", "application/json")
        .body(Body::from(payload))
        .unwrap(),
    )
    .await
    .unwrap();
  assert_eq!(res.status(), StatusCode::UNAUTHORIZED);
}

#[tokio::test]
async fn test_upsert_secret_missing_project_key() {
  let (app, _) = create_test_app().await;
  let payload = r#"{"key":"noproj","value":{"x":42}}"#;

  let res = app
    .oneshot(
      Request::builder()
        .method("POST")
        .uri("/secrets")
        .header("x-api-key", "test-api-key-write")
        .header("content-type", "application/json")
        .body(Body::from(payload))
        .unwrap(),
    )
    .await
    .unwrap();
  assert_eq!(res.status(), StatusCode::BAD_REQUEST);
}

#[tokio::test]
async fn test_upsert_secret_overwrite_existing() {
  let (app, _) = create_test_app().await;
  let payload = r#"{"key":"mykey","value":{"some":"new_value"}}"#;

  // First request using the cloned router
  let res = app
    .clone()
    .oneshot(
      Request::builder()
        .method("POST")
        .uri("/secrets")
        .header("x-api-key", "test-api-key-write")
        .header("x-project-key", "test_project")
        .header("content-type", "application/json")
        .body(Body::from(payload))
        .unwrap(),
    )
    .await
    .unwrap();
  assert_eq!(res.status(), StatusCode::NO_CONTENT);

  // Second request using the cloned router
  let res = app
    .clone()
    .oneshot(
      Request::builder()
        .uri("/secrets/mykey")
        .header("x-api-key", "test-api-key-read")
        .header("x-project-key", "test_project")
        .body(Body::empty())
        .unwrap(),
    )
    .await
    .unwrap();
  assert_eq!(res.status(), StatusCode::OK);
}

#[tokio::test]
async fn test_upsert_secret_with_read_key_forbidden() {
  let (app, _) = create_test_app().await;
  let payload = r#"{"key":"anotherkey","value":{"foo":"baz"}}"#;

  let res = app
    .oneshot(
      Request::builder()
        .method("POST")
        .uri("/secrets")
        .header("x-api-key", "test-api-key-read")
        .header("x-project-key", "test_project")
        .header("content-type", "application/json")
        .body(Body::from(payload))
        .unwrap(),
    )
    .await
    .unwrap();
  assert_eq!(res.status(), StatusCode::UNAUTHORIZED);
}

#[tokio::test]
async fn test_put_upsert_secret_by_path_happy_path() {
  let (app, _state) = create_test_app().await;
  let payload = r#"{"value":{"new":"data"}}"#;

  let res = app
    .clone()
    .oneshot(
      Request::builder()
        .method("PUT")
        .uri("/secrets/mykey")
        .header("x-api-key", "test-api-key-write")
        .header("x-project-key", "test_project")
        .header("content-type", "application/json")
        .body(Body::from(payload))
        .unwrap(),
    )
    .await
    .unwrap();
  assert_eq!(res.status(), StatusCode::NO_CONTENT);

  // Confirm via GET
  let res = app
    .clone()
    .oneshot(
      Request::builder()
        .uri("/secrets/mykey")
        .header("x-api-key", "test-api-key-read")
        .header("x-project-key", "test_project")
        .body(Body::empty())
        .unwrap(),
    )
    .await
    .unwrap();
  assert_eq!(res.status(), StatusCode::OK);
  let body = to_bytes(res.into_body(), 1024 * 1024).await.unwrap();
  let json: Value = serde_json::from_slice(&body).unwrap();
  assert_eq!(json, serde_json::json!({"new":"data"}));
}

#[tokio::test]
async fn test_delete_secret_happy_path() {
  let (app, _state) = create_test_app().await;
  // Delete existing secret
  let res = app
    .clone()
    .oneshot(
      Request::builder()
        .method("DELETE")
        .uri("/secrets/mykey")
        .header("x-api-key", "test-api-key-write")
        .header("x-project-key", "test_project")
        .body(Body::empty())
        .unwrap(),
    )
    .await
    .unwrap();
  assert_eq!(res.status(), StatusCode::NO_CONTENT);

  // Confirm deletion via GET
  let res = app
    .clone()
    .oneshot(
      Request::builder()
        .uri("/secrets/mykey")
        .header("x-api-key", "test-api-key-read")
        .header("x-project-key", "test_project")
        .body(Body::empty())
        .unwrap(),
    )
    .await
    .unwrap();
  assert_eq!(res.status(), StatusCode::NOT_FOUND);
}

#[tokio::test]
async fn test_search_secrets_without_query_returns_all() {
  let (app, _state) = create_test_app().await;
  // Insert an extra secret via upsert
  let payload = r#"{"key":"another","value":{"a":1}}"#;
  app
    .clone()
    .oneshot(
      Request::builder()
        .method("POST")
        .uri("/secrets")
        .header("x-api-key", "test-api-key-write")
        .header("x-project-key", "test_project")
        .header("content-type", "application/json")
        .body(Body::from(payload))
        .unwrap(),
    )
    .await
    .unwrap();

  let res = app
    .clone()
    .oneshot(
      Request::builder()
        .method("POST")
        .uri("/search")
        .header("x-api-key", "test-api-key-read")
        .header("x-project-key", "test_project")
        .header("content-type", "application/json")
        .body(Body::from("{}"))
        .unwrap(),
    )
    .await
    .unwrap();
  assert_eq!(res.status(), StatusCode::OK);
  let body = to_bytes(res.into_body(), 1024 * 1024).await.unwrap();
  let arr: Vec<Value> = serde_json::from_slice(&body).unwrap();
  // Should contain at least two entries
  assert!(arr.len() >= 2);
}

#[tokio::test]
async fn test_search_secrets_with_query_filters() {
  let (app, _state) = create_test_app().await;
  let res = app
    .oneshot(
      Request::builder()
        .method("POST")
        .uri("/search")
        .header("x-api-key", "test-api-key-read")
        .header("x-project-key", "test_project")
        .header("content-type", "application/json")
        .body(Body::from(r#"{"query":"myk"}"#))
        .unwrap(),
    )
    .await
    .unwrap();
  assert_eq!(res.status(), StatusCode::OK);
  let body = to_bytes(res.into_body(), 1024 * 1024).await.unwrap();
  let arr: Vec<Value> = serde_json::from_slice(&body).unwrap();
  // Should only return keys matching 'myk'
  assert!(
    arr
      .iter()
      .all(|v| v["secret_key"].as_str().unwrap().contains("myk"))
  );
}

#[tokio::test]
async fn test_search_excludes_nonmatching() {
  let (app, _) = create_test_app().await;

  // Insert a non-matching secret
  let payload = r#"{"key":"otherkey","value":{"foo":"bar"}}"#;
  let res = app
    .clone()
    .oneshot(
      Request::builder()
        .method("POST")
        .uri("/secrets")
        .header("x-api-key", "test-api-key-write")
        .header("x-project-key", "test_project")
        .header("content-type", "application/json")
        .body(Body::from(payload))
        .unwrap(),
    )
    .await
    .unwrap();
  assert_eq!(res.status(), StatusCode::NO_CONTENT);

  // Now search for "mykey" only
  let res = app
    .clone()
    .oneshot(
      Request::builder()
        .method("POST")
        .uri("/search")
        .header("x-api-key", "test-api-key-read")
        .header("x-project-key", "test_project")
        .header("content-type", "application/json")
        .body(Body::from(r#"{"query":"mykey"}"#))
        .unwrap(),
    )
    .await
    .unwrap();
  assert_eq!(res.status(), StatusCode::OK);

  // Parse and verify results
  let body = to_bytes(res.into_body(), 1024 * 1024).await.unwrap();
  let arr: Vec<Value> = serde_json::from_slice(&body).unwrap();
  assert_eq!(arr.len(), 1, "Expected exactly one match");
  assert_eq!(arr[0]["secret_key"].as_str().unwrap(), "mykey");
}

#[tokio::test]
async fn test_search_ignores_body_project_key_override() {
  let (app, _state) = create_test_app().await;

  // 1) Seed a secret under a *different* project via the API
  let payload = r#"{"key":"othersecret","value":{"x":1}}"#;
  let res = app
    .clone()
    .oneshot(
      Request::builder()
        .method("POST")
        .uri("/secrets")
        .header("x-api-key", "test-api-key-write")
        .header("x-project-key", "other_project")
        .header("content-type", "application/json")
        .body(Body::from(payload))
        .unwrap(),
    )
    .await
    .unwrap();
  assert_eq!(res.status(), StatusCode::NO_CONTENT);

  // 2) Now search for "othersecret" but with header project = “test_project”
  //    and an overridden project_key in the JSON body.
  let body = r#"{
    "query":"othersecret",
    "project_key":"other_project"
  }"#;
  let res = app
    .clone()
    .oneshot(
      Request::builder()
        .method("POST")
        .uri("/search")
        .header("x-api-key", "test-api-key-read")
        .header("x-project-key", "test_project")
        .header("content-type", "application/json")
        .body(Body::from(body))
        .unwrap(),
    )
    .await
    .unwrap();
  assert_eq!(res.status(), StatusCode::OK);

  // 3) We should get back an empty array, because "othersecret" lives under
  //    other_project, not test_project—our header binding wins.
  let bytes = to_bytes(res.into_body(), 1024 * 1024).await.unwrap();
  let arr: Vec<Value> = serde_json::from_slice(&bytes).unwrap();
  assert!(arr.is_empty(), "Expected no results, got {:?}", arr);
}
