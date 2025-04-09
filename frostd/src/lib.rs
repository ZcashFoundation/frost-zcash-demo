pub mod args;
pub mod cipher;
pub mod client;
mod functions;
mod state;
mod types;
mod user;

use std::net::SocketAddr;

use axum::{
    http::StatusCode,
    response::{IntoResponse, Response},
    routing::post,
    Json, Router,
};
use axum_server::tls_rustls::RustlsConfig;
use eyre::OptionExt;
use serde::{Deserialize, Serialize};
use thiserror::Error;
use tower_http::trace::TraceLayer;

use args::Args;
pub use state::{AppState, SharedState};
pub use types::*;

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

    let addr: SocketAddr = format!("{}:{}", args.ip(), args.port).parse()?;

    if args.no_tls_very_insecure {
        tracing::warn!(
            "starting an INSECURE HTTP server at {}. This should be done only \
            for testing or if you are providing TLS/HTTPS with a separate \
            mechanism (e.g. reverse proxy such as nginx)",
            addr,
        );
        let listener = tokio::net::TcpListener::bind(addr).await?;
        Ok(axum::serve(listener, app).await?)
    } else {
        rustls::crypto::ring::default_provider()
            .install_default()
            .expect("Failed to install rustls crypto provider");
        let config = RustlsConfig::from_pem_file(
            args.tls_cert
                .clone()
                .ok_or_eyre("tls-cert argument is required")?,
            args.tls_key
                .clone()
                .ok_or_eyre("tls-key argument is required")?,
        )
        .await?;

        tracing::info!("starting HTTPS server at {}", addr);
        Ok(axum_server::bind_rustls(addr, config)
            .serve(app.into_make_service())
            .await?)
    }
}

/// An error. Wraps a StatusCode which is returned by the server when the
/// error happens during a API call, and a generic eyre::Report.
#[derive(Debug, Error, Serialize, Deserialize, PartialEq, Eq)]
#[serde(tag = "code", content = "err")]
pub enum Error {
    #[error("invalid or missing argument: {0}")]
    InvalidArgument(String),
    #[error("client did not provide proper authorization credentials")]
    Unauthorized,
    #[error("session was not found")]
    SessionNotFound,
    #[error("user is not the coordinator")]
    NotCoordinator,
    #[error("user is not part of the given session")]
    NotInSession,
    #[serde(other)]
    #[error("unknown error")]
    Unknown,
}

// These make it easier to clients to tell which error happened.
pub const INVALID_ARGUMENT: usize = 1;
pub const UNAUTHORIZED: usize = 2;
pub const SESSION_NOT_FOUND: usize = 3;
pub const NOT_COORDINATOR: usize = 4;
pub const NOT_IN_SESSION: usize = 5;
pub const UNKNOWN: usize = 255;

impl Error {
    pub fn error_code(&self) -> usize {
        match &self {
            Error::InvalidArgument(_) => INVALID_ARGUMENT,
            Error::Unauthorized => UNAUTHORIZED,
            Error::SessionNotFound => SESSION_NOT_FOUND,
            Error::NotCoordinator => NOT_COORDINATOR,
            Error::NotInSession => NOT_IN_SESSION,
            Error::Unknown => UNKNOWN,
        }
    }
}

#[derive(Debug, Serialize, Deserialize)]
pub struct LowError {
    pub code: usize,
    pub msg: String,
    pub error: Error,
}

impl From<Error> for LowError {
    fn from(err: Error) -> Self {
        LowError {
            code: err.error_code(),
            msg: err.to_string(),
            error: err,
        }
    }
}

impl From<LowError> for Error {
    fn from(err: LowError) -> Self {
        err.error
    }
}

impl IntoResponse for Error {
    fn into_response(self) -> Response {
        (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(Into::<LowError>::into(self)),
        )
            .into_response()
    }
}
