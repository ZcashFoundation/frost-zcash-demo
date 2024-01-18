use std::collections::BTreeSet;

use axum::{extract::State, http::StatusCode, Json};

use eyre::eyre;
use uuid::Uuid;

use crate::{
    state::{Session, SessionState, SharedState},
    types::*,
    AppError,
};

pub(crate) async fn create_new_session(
    State(state): State<SharedState>,
    Json(args): Json<CreateNewSessionArgs>,
) -> Result<Json<CreateNewSessionOutput>, AppError> {
    let id = Uuid::new_v4();
    let session = Session {
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
pub(crate) async fn send_commitments(
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
pub(crate) async fn get_commitments(
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
pub(crate) async fn send_signing_package(
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
                randomizer: args.randomizer,
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
pub(crate) async fn get_signing_package(
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
            randomizer,
        } => Ok(Json(GetSigningPackageOutput {
            signing_package: signing_package.clone(),
            randomizer: randomizer.clone(),
        })),
        _ => Err(AppError(
            StatusCode::INTERNAL_SERVER_ERROR,
            eyre!("incompatible session state"),
        )),
    }
}

/// Implement the send_signature_share API
// TODO: get identifier from channel rather from arguments
pub(crate) async fn send_signature_share(
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
            randomizer: _,
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
pub(crate) async fn get_signature_shares(
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
