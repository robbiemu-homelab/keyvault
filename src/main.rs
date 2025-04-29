use axum::{
  Router,
  extract::Extension,
  routing::{get, post},
};
use dotenvy::dotenv;
use sqlx::postgres::PgPoolOptions;
use std::{env, net::SocketAddr};

use keyvault::{AppState, Queries, get_secret, upsert_secret};


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
    .route("/secrets/{key}", get(get_secret))
    .route("/secrets", post(upsert_secret))
    .layer(Extension(state));

  let addr = SocketAddr::from(([0, 0, 0, 0], 3000));
  let listener = tokio::net::TcpListener::bind(addr).await.unwrap();

  axum::serve(listener, app.into_make_service())
    .await
    .unwrap();
}
