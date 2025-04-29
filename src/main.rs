use axum::{
  Router,
  extract::Extension,
  http::Method,
  response::IntoResponse,
  routing::{get, post},
};
use dotenvy::dotenv;
use hyper::{HeaderMap, StatusCode};
use sqlx::postgres::PgPoolOptions;
use std::{env, net::SocketAddr};
use tower_http::cors::{Any, CorsLayer};
use tracing_subscriber::FmtSubscriber;
use tracing_subscriber::filter::EnvFilter;

use keyvault::{
  AppState, Queries, delete_secret, get_secret, search_secrets, upsert_secret,
  upsert_secret_by_path,
};


#[tokio::main]
async fn main() {
  // initialize subscriber to read RUST_LOG
  let filter = EnvFilter::try_from_default_env()
    .unwrap_or_else(|_| EnvFilter::new("warn"));
  let subscriber = FmtSubscriber::builder().with_env_filter(filter).finish();

  tracing::subscriber::set_global_default(subscriber)
    .expect("setting default subscriber failed");

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

  let cors = CorsLayer::new()
    .allow_origin(Any) // Permite qualquer origem. Para maior segurança, especifique a origem do seu frontend.
    .allow_methods([Method::GET, Method::POST, Method::PUT, Method::DELETE])
    .allow_headers(Any);

  async fn cors_preflight() -> impl IntoResponse {
    (StatusCode::NO_CONTENT, HeaderMap::new())
  }

  let app = Router::new()
    .route(
      "/secrets/{key}",
      get(get_secret)
        .put(upsert_secret_by_path)
        .delete(delete_secret)
        .options(cors_preflight),
    )
    .route("/secrets", post(upsert_secret).options(cors_preflight))
    .route("/search", post(search_secrets).options(cors_preflight))
    .layer(cors)
    .layer(Extension(state));

  let addr = SocketAddr::from(([0, 0, 0, 0], 3000));
  let listener = tokio::net::TcpListener::bind(addr).await.unwrap();

  axum::serve(listener, app.into_make_service())
    .await
    .unwrap();
}
