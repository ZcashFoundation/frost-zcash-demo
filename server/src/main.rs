use reddsa::frost::{
    redjubjub::{round1::SigningCommitments, Identifier},
    redpallas as frost,
};

use axum::{
    extract::State,
    http::StatusCode,
    response::{IntoResponse, Response},
    routing::post,
    Json, Router,
};
use std::{
    collections::{BTreeMap, BTreeSet, HashMap},
    sync::{Arc, RwLock},
};

use eyre::eyre;
use serde::{Deserialize, Serialize};
use uuid::Uuid;

enum SessionState {
    WaitingForCommitments {
        commitments: BTreeMap<frost::Identifier, frost::round1::SigningCommitments>,
    },
    CommitmentsReady {
        commitments: BTreeMap<frost::Identifier, frost::round1::SigningCommitments>,
    },
    WaitingForSignatureShares {
        signing_package: frost::SigningPackage,
        signature_shares: BTreeMap<frost::Identifier, frost::round2::SignatureShare>,
    },
    SignatureSharesReady {
        signature_shares: BTreeMap<frost::Identifier, frost::round2::SignatureShare>,
    },
}

impl Default for SessionState {
    fn default() -> Self {
        SessionState::WaitingForCommitments {
            commitments: Default::default(),
        }
    }
}

struct Session {
    id: Uuid,
    identifiers: BTreeSet<frost::Identifier>,
    state: SessionState,
}

#[derive(Default)]
struct AppState {
    sessions: HashMap<Uuid, Session>,
}

type SharedState = Arc<RwLock<AppState>>;

#[tokio::main]
async fn main() {
    // initialize tracing
    tracing_subscriber::fmt::init();

    let shared_state = SharedState::default();

    // build our application with a route
    let app = Router::new()
        .route("/create_new_session", post(create_new_session))
        .route("/send_commitments", post(send_commitments))
        .route("/get_commitments", post(get_commitments))
        .route("/send_signing_package", post(send_signing_package))
        .route("/get_signing_package", post(get_signing_package))
        .route("/send_signature_share", post(send_signature_share))
        .route("/get_signature_shares", post(get_signature_shares))
        .with_state(shared_state);

    // run our app with hyper, listening globally on port 3000
    let listener = tokio::net::TcpListener::bind("0.0.0.0:3000").await.unwrap();
    axum::serve(listener, app).await.unwrap();
}

async fn create_new_session(
    State(state): State<SharedState>,
    Json(args): Json<CreateNewSessionArgs>,
) -> Result<Json<CreateNewSessionOutput>, AppError> {
    let id = Uuid::new_v4();
    let session = Session {
        id,
        identifiers: args.identifiers.iter().cloned().collect(),
        state: SessionState::WaitingForCommitments {
            commitments: Default::default(),
        },
    };
    state.write().unwrap().sessions.insert(id, session);
    let user = CreateNewSessionOutput { session_id: id };
    Ok(Json(user))
}

/// Implement the send_commitments API
// TODO: get identifier from channel rather from arguments
async fn send_commitments(
    State(state): State<SharedState>,
    Json(args): Json<SendCommitmentsArgs>,
) -> Result<(), AppError> {
    let mut state_lock = state.write().unwrap();

    let session = state_lock
        .sessions
        .get_mut(&args.session_id)
        .ok_or(AppError(
            StatusCode::NOT_FOUND,
            eyre!("session ID not found"),
        ))?;

    match &mut session.state {
        SessionState::WaitingForCommitments { commitments } => {
            if !session.identifiers.contains(&args.identifier) {
                return Err(AppError(StatusCode::NOT_FOUND, eyre!("invalid identifier")));
            }
            // Currently ignoring the possibility of overwriting previous values
            // (it seems better to ignore overwrites, which could be caused by
            // poor networking connectivity leading to retries)
            commitments.insert(args.identifier, args.commitments);
            // If complete, advance to next state
            if commitments.keys().cloned().collect::<BTreeSet<_>>() == session.identifiers {
                session.state = SessionState::CommitmentsReady {
                    commitments: commitments.clone(),
                }
            }
        }
        _ => {
            return Err(AppError(
                StatusCode::INTERNAL_SERVER_ERROR,
                eyre!("incompatible session state"),
            ));
        }
    }
    Ok(())
}

/// Implement the get_commitments API
async fn get_commitments(
    State(state): State<SharedState>,
    Json(args): Json<GetCommitmentsArgs>,
) -> Result<Json<GetCommitmentsOutput>, AppError> {
    let state_lock = state.read().unwrap();

    let session = state_lock.sessions.get(&args.session_id).ok_or(AppError(
        StatusCode::NOT_FOUND,
        eyre!("session ID not found"),
    ))?;

    match &session.state {
        SessionState::CommitmentsReady { commitments } => Ok(Json(GetCommitmentsOutput {
            commitments: commitments.clone(),
        })),
        _ => Err(AppError(
            StatusCode::INTERNAL_SERVER_ERROR,
            eyre!("incompatible session state"),
        )),
    }
}

/// Implement the send_signing_package API
async fn send_signing_package(
    State(state): State<SharedState>,
    Json(args): Json<SendSigningPackageArgs>,
) -> Result<(), AppError> {
    let mut state_lock = state.write().unwrap();

    let session = state_lock
        .sessions
        .get_mut(&args.session_id)
        .ok_or(AppError(
            StatusCode::NOT_FOUND,
            eyre!("session ID not found"),
        ))?;

    match &mut session.state {
        SessionState::CommitmentsReady { .. } => {
            session.state = SessionState::WaitingForSignatureShares {
                signing_package: args.signing_package,
                signature_shares: Default::default(),
            };
        }
        _ => {
            return Err(AppError(
                StatusCode::INTERNAL_SERVER_ERROR,
                eyre!("incompatible session state"),
            ));
        }
    }
    Ok(())
}

/// Implement the get_signing_package API
async fn get_signing_package(
    State(state): State<SharedState>,
    Json(args): Json<GetSigningPackageArgs>,
) -> Result<Json<GetSigningPackageOutput>, AppError> {
    let state_lock = state.read().unwrap();

    let session = state_lock.sessions.get(&args.session_id).ok_or(AppError(
        StatusCode::NOT_FOUND,
        eyre!("session ID not found"),
    ))?;

    match &session.state {
        SessionState::WaitingForSignatureShares {
            signing_package,
            signature_shares: _,
        } => Ok(Json(GetSigningPackageOutput {
            signing_package: signing_package.clone(),
        })),
        _ => Err(AppError(
            StatusCode::INTERNAL_SERVER_ERROR,
            eyre!("incompatible session state"),
        )),
    }
}

/// Implement the send_signature_share API
// TODO: get identifier from channel rather from arguments
async fn send_signature_share(
    State(state): State<SharedState>,
    Json(args): Json<SendSignatureShareArgs>,
) -> Result<(), AppError> {
    let mut state_lock = state.write().unwrap();

    let session = state_lock
        .sessions
        .get_mut(&args.session_id)
        .ok_or(AppError(
            StatusCode::NOT_FOUND,
            eyre!("session ID not found"),
        ))?;

    match &mut session.state {
        SessionState::WaitingForSignatureShares {
            signing_package: _,
            signature_shares,
        } => {
            if !session.identifiers.contains(&args.identifier) {
                return Err(AppError(StatusCode::NOT_FOUND, eyre!("invalid identifier")));
            }
            // Currently ignoring the possibility of overwriting previous values
            // (it seems better to ignore overwrites, which could be caused by
            // poor networking connectivity leading to retries)
            signature_shares.insert(args.identifier, args.signature_share);
            // If complete, advance to next state
            if signature_shares.keys().cloned().collect::<BTreeSet<_>>() == session.identifiers {
                session.state = SessionState::SignatureSharesReady {
                    signature_shares: signature_shares.clone(),
                };
            }
        }
        _ => {
            return Err(AppError(
                StatusCode::INTERNAL_SERVER_ERROR,
                eyre!("incompatible session state"),
            ));
        }
    }
    Ok(())
}

/// Implement the get_signature_shares API
async fn get_signature_shares(
    State(state): State<SharedState>,
    Json(args): Json<GetSignatureSharesArgs>,
) -> Result<Json<GetSignatureSharesOutput>, AppError> {
    let state_lock = state.read().unwrap();

    let session = state_lock.sessions.get(&args.session_id).ok_or(AppError(
        StatusCode::NOT_FOUND,
        eyre!("session ID not found"),
    ))?;

    match &session.state {
        SessionState::SignatureSharesReady { signature_shares } => {
            Ok(Json(GetSignatureSharesOutput {
                signature_shares: signature_shares.clone(),
            }))
        }
        _ => Err(AppError(
            StatusCode::INTERNAL_SERVER_ERROR,
            eyre!("incompatible session state"),
        )),
    }
}

struct AppError(StatusCode, eyre::Report);

impl IntoResponse for AppError {
    fn into_response(self) -> Response {
        (self.0, format!("{}", self.1)).into_response()
    }
}

#[derive(Deserialize)]
struct CreateNewSessionArgs {
    identifiers: Vec<frost::Identifier>,
}

#[derive(Serialize)]
struct CreateNewSessionOutput {
    session_id: Uuid,
}

#[derive(Deserialize)]
struct SendCommitmentsArgs {
    session_id: Uuid,
    identifier: frost::Identifier,
    commitments: frost::round1::SigningCommitments,
}

#[derive(Deserialize)]
struct GetCommitmentsArgs {
    session_id: Uuid,
}

#[derive(Serialize)]
struct GetCommitmentsOutput {
    commitments: BTreeMap<frost::Identifier, frost::round1::SigningCommitments>,
}

#[derive(Deserialize)]
struct SendSigningPackageArgs {
    session_id: Uuid,
    signing_package: frost::SigningPackage,
}

#[derive(Deserialize)]
struct GetSigningPackageArgs {
    session_id: Uuid,
}

#[derive(Serialize)]
struct GetSigningPackageOutput {
    signing_package: frost::SigningPackage,
}

#[derive(Deserialize)]
struct SendSignatureShareArgs {
    session_id: Uuid,
    identifier: frost::Identifier,
    signature_share: frost::round2::SignatureShare,
}

#[derive(Deserialize)]
struct GetSignatureSharesArgs {
    session_id: Uuid,
}

#[derive(Serialize)]
struct GetSignatureSharesOutput {
    signature_shares: BTreeMap<frost::Identifier, frost::round2::SignatureShare>,
}
