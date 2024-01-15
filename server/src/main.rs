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
                StatusCode::NOT_FOUND,
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
            StatusCode::NOT_FOUND,
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
