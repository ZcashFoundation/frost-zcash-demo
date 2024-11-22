pub mod args;
mod functions;
mod state;
mod types;
mod user;

pub use state::{AppState, SharedState};
use tower_http::trace::TraceLayer;
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
pub fn router(shared_state: SharedState) -> Router {
    // Shared state that is passed to each handler by axum
    Router::new()
        .route("/challenge", post(functions::challenge))
        .route("/login", post(functions::login))
        .route("/logout", post(functions::logout))
        .route("/create_new_session", post(functions::create_new_session))
        .route("/list_sessions", post(functions::list_sessions))
        .route("/get_session_info", post(functions::get_session_info))
        .route("/send", post(functions::send))
        .route("/receive", post(functions::receive))
        .route("/close_session", post(functions::close_session))
        .layer(TraceLayer::new_for_http())
        .with_state(shared_state)
}

/// Run the server with the specified arguments.
pub async fn run(args: &Args) -> Result<(), Box<dyn std::error::Error>> {
    let shared_state = AppState::new().await?;
    let app = router(shared_state.clone());

    let addr = format!("{}:{}", args.ip, args.port);
    let listener = tokio::net::TcpListener::bind(addr).await?;
    Ok(axum::serve(listener, app).await?)
}

/// An error. Wraps a StatusCode which is returned by the server when the
/// error happens during a API call, and a generic eyre::Report.
// TODO: create an enum with specific errors
#[derive(Debug)]
pub struct AppError(StatusCode, Box<dyn std::error::Error>);

impl IntoResponse for AppError {
    fn into_response(self) -> Response {
        (self.0, format!("{}", self.1)).into_response()
    }
}
