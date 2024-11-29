pub mod args;
mod functions;
mod state;
mod types;
mod user;

pub use state::{AppState, SharedState};
use thiserror::Error;
use tower_http::trace::TraceLayer;
pub use types::*;

use args::Args;
use axum::{
    http::StatusCode,
    response::{IntoResponse, Response},
    routing::post,
    Json, Router,
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
#[derive(Debug, Error)]
pub(crate) enum AppError {
    #[error("invalid or missing argument: {0}")]
    InvalidArgument(String),
    #[error("client did not provide proper authorization credentials")]
    Unauthorized,
    #[error("session was not found")]
    SessionNotFound,
    #[error("user is not the coordinator")]
    NotCoordinator,
}

// These make it easier to clients to tell which error happened.
pub const INVALID_ARGUMENT: usize = 1;
pub const UNAUTHORIZED: usize = 2;
pub const SESSION_NOT_FOUND: usize = 3;
pub const NOT_COORDINATOR: usize = 4;

impl AppError {
    pub fn error_code(&self) -> usize {
        match &self {
            AppError::InvalidArgument(_) => INVALID_ARGUMENT,
            AppError::Unauthorized => UNAUTHORIZED,
            AppError::SessionNotFound => SESSION_NOT_FOUND,
            AppError::NotCoordinator => NOT_COORDINATOR,
        }
    }
}

impl From<AppError> for types::Error {
    fn from(err: AppError) -> Self {
        types::Error {
            code: err.error_code(),
            msg: err.to_string(),
        }
    }
}

impl IntoResponse for AppError {
    fn into_response(self) -> Response {
        (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(Into::<types::Error>::into(self)),
        )
            .into_response()
    }
}
