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

/// Create the axum Router for the server.
/// Maps specific endpoints to handler functions.
// TODO: use methods of a single object instead of separate functions?
pub fn router() -> Router {
    // Shared state that is passed to each handler by axum
    let shared_state = state::SharedState::default();
    Router::new()
        .route("/create_new_session", post(functions::create_new_session))
        .route("/get_session_info", post(functions::get_session_info))
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
        .route("/close_session", post(functions::close_session))
        .with_state(shared_state)
}

/// Run the server with the specified arguments.
pub async fn run(args: &Args) -> Result<(), Box<dyn std::error::Error>> {
    let app = router();

    let addr = format!("{}:{}", args.ip, args.port);
    let listener = tokio::net::TcpListener::bind(addr).await?;
    Ok(axum::serve(listener, app).await?)
}

/// An error. Wraps a StatusCode which is returned by the server when the
/// error happens during a API call, and a generic eyre::Report.
// TODO: create an enum with specific errors
pub struct AppError(StatusCode, eyre::Report);

impl IntoResponse for AppError {
    fn into_response(self) -> Response {
        (self.0, format!("{}", self.1)).into_response()
    }
}
