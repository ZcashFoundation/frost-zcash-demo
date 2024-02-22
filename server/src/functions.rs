use std::collections::BTreeSet;

use axum::{extract::State, http::StatusCode, Json};

use eyre::eyre;
use uuid::Uuid;

use crate::{
    state::{Session, SessionState, SharedState},
    types::*,
    AppError,
};

/// Implement the create_new_session API.
pub(crate) async fn create_new_session(
    State(state): State<SharedState>,
    Json(args): Json<CreateNewSessionArgs>,
) -> Result<Json<CreateNewSessionOutput>, AppError> {
    if args.message_count == 0 {
        return Err(AppError(
            StatusCode::INTERNAL_SERVER_ERROR,
            eyre!("invalid message_count"),
        ));
    }
    // Create new session object.
    let id = Uuid::new_v4();
    let session = Session {
        identifiers: args.identifiers.iter().cloned().collect(),
        message_count: args.message_count,
        state: SessionState::WaitingForCommitments {
            commitments: Default::default(),
        },
    };
    // Save session into global state.
    state.write().unwrap().sessions.insert(id, session);
    let user = CreateNewSessionOutput { session_id: id };
    Ok(Json(user))
}

/// Implement the get_session_info API
pub(crate) async fn get_session_info(
    State(state): State<SharedState>,
    Json(args): Json<GetSessionInfoArgs>,
) -> Result<Json<GetSessionInfoOutput>, AppError> {
    let state_lock = state.read().unwrap();

    let session = state_lock.sessions.get(&args.session_id).ok_or(AppError(
        StatusCode::NOT_FOUND,
        eyre!("session ID not found"),
    ))?;

    Ok(Json(GetSessionInfoOutput {
        identifiers: session.identifiers.iter().copied().collect(),
        message_count: session.message_count,
    }))
}

/// Implement the send_commitments API
// TODO: get identifier from channel rather from arguments
pub(crate) async fn send_commitments(
    State(state): State<SharedState>,
    Json(args): Json<SendCommitmentsArgs>,
) -> Result<(), AppError> {
    // Get the mutex lock to read and write from the state
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
            if args.commitments.len() != session.message_count as usize {
                return Err(AppError(
                    StatusCode::INTERNAL_SERVER_ERROR,
                    eyre!("wrong number of commitments"),
                ));
            }
            // Add commitment to map.
            // Currently ignores the possibility of overwriting previous values
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
            // Convert the BTreeMap<Identifier, Vec<SigningCommitments>> map
            // into a Vec<BTreeMap<Identifier, SigningCommitments>> map to make
            // it easier for the coordinator to build the SigningPackages.
            commitments: (0..session.message_count)
                .map(|i| {
                    commitments
                        .iter()
                        .map(|(id, c)| (*id, c[i as usize]))
                        .collect()
                })
                .collect(),
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
            if args.signing_package.len() != session.message_count as usize
                || args.randomizer.len() != session.message_count as usize
            {
                return Err(AppError(
                    StatusCode::INTERNAL_SERVER_ERROR,
                    eyre!("wrong number of inputs"),
                ));
            }
            session.state = SessionState::WaitingForSignatureShares {
                signing_package: args.signing_package,
                signature_shares: Default::default(),
                randomizer: args.randomizer,
                aux_msg: args.aux_msg,
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
            aux_msg,
        } => Ok(Json(GetSigningPackageOutput {
            signing_package: signing_package.clone(),
            randomizer: randomizer.clone(),
            aux_msg: aux_msg.clone(),
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
            aux_msg: _,
        } => {
            if !session.identifiers.contains(&args.identifier) {
                return Err(AppError(StatusCode::NOT_FOUND, eyre!("invalid identifier")));
            }
            if args.signature_share.len() != session.message_count as usize {
                return Err(AppError(
                    StatusCode::INTERNAL_SERVER_ERROR,
                    eyre!("wrong number of signature shares"),
                ));
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
                // Convert the BTreeMap<Identifier, Vec<SigningCommitments>> map
                // into a Vec<BTreeMap<Identifier, SigningCommitments>> map to make
                // it easier for the coordinator to build the SigningPackages.
                signature_shares: (0..session.message_count)
                    .map(|i| {
                        signature_shares
                            .iter()
                            .map(|(id, s)| (*id, s[i as usize]))
                            .collect()
                    })
                    .collect(),
            }))
        }
        _ => Err(AppError(
            StatusCode::INTERNAL_SERVER_ERROR,
            eyre!("incompatible session state"),
        )),
    }
}

/// Implement the close_session API.
pub(crate) async fn close_session(
    State(state): State<SharedState>,
    Json(args): Json<CloseSessionArgs>,
) -> Result<Json<()>, AppError> {
    state.write().unwrap().sessions.remove(&args.session_id);
    Ok(Json(()))
}
