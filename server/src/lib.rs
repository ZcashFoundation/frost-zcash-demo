pub mod args;
mod functions;
mod state;
mod types;
pub use types::*;

use args::Args;
use axum::{
    http::StatusCode,
    response::{IntoResponse, Response},
    routing::post,
    Router,
};

pub fn router() -> Router {
    let shared_state = state::SharedState::default();
    Router::new()
        .route("/create_new_session", post(functions::create_new_session))
        .route("/send_commitments", post(functions::send_commitments))
        .route("/get_commitments", post(functions::get_commitments))
        .route(
            "/send_signing_package",
            post(functions::send_signing_package),
        )
        .route("/get_signing_package", post(functions::get_signing_package))
        .route(
            "/send_signature_share",
            post(functions::send_signature_share),
        )
        .route(
            "/get_signature_shares",
            post(functions::get_signature_shares),
        )
        .with_state(shared_state)
}

pub async fn cli(args: &Args) -> Result<(), Box<dyn std::error::Error>> {
    let app = router();

    let addr = format!("{}:{}", args.ip, args.port);
    let listener = tokio::net::TcpListener::bind(addr).await?;
    Ok(axum::serve(listener, app).await?)
}

pub struct AppError(StatusCode, eyre::Report);

impl IntoResponse for AppError {
    fn into_response(self) -> Response {
        (self.0, format!("{}", self.1)).into_response()
    }
}
