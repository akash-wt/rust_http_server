use axum::{Json, Router, http::StatusCode, response::IntoResponse, routing::get};
use reqwest::{self};
use serde::{Deserialize, Serialize};
use tracing_subscriber;

#[tokio::main]
async fn main() {
    tracing_subscriber::fmt::init();

    let app = Router::new()
        .route("/", get(root))
        .route("/get_jokes", get(get_jokes));

    let listener = tokio::net::TcpListener::bind("0.0.0.0:3000").await.unwrap();
    axum::serve(listener, app).await.unwrap();
}

async fn root() -> &'static str {
    return "hallo world!";
}

#[derive(Serialize, Deserialize)]
struct Joke {
    joke: String,
}

async fn get_jokes() -> impl IntoResponse {
    let client = reqwest::Client::new();

    let res = client
        .get("https://icanhazdadjoke.com/")
        .header("Accept", "application/json")
        .send()
        .await;

    match res {
        Ok(response) => {
            let joke: Joke = response.json().await.unwrap();
            (StatusCode::OK, Json(joke))
        }

        Err(_) => (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(Joke {
                joke: "Failed to fetch joke".to_string(),
            }),
        ),
    }
}
