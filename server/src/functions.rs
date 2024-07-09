use std::collections::HashSet;

use axum::{extract::State, http::StatusCode, Json};
use eyre::eyre;
use uuid::Uuid;

use crate::{
    state::{Session, SessionState, SharedState},
    types::*,
    user::{
        add_access_token, authenticate_user, create_user, delete_user, get_user,
        remove_access_token, User,
    },
    AppError,
};

/// Implement the register API.
#[tracing::instrument(ret, err(Debug), skip(state,args), fields(args.username = %args.username))]
pub(crate) async fn register(
    State(state): State<SharedState>,
    Json(args): Json<RegisterArgs>,
) -> Result<Json<()>, AppError> {
    let username = args.username.trim();
    let password = args.password.trim();

    if username.is_empty() || password.is_empty() {
        return Err(AppError(
            StatusCode::INTERNAL_SERVER_ERROR,
            eyre!("empty args").into(),
        ));
    }

    let db = {
        let state_lock = state.read().unwrap();
        state_lock.db.clone()
    };

    create_user(db, username, password, args.pubkey)
        .await
        .map_err(|e| AppError(StatusCode::INTERNAL_SERVER_ERROR, e))?;

    Ok(Json(()))
}

/// Implement the login API.
#[tracing::instrument(ret, err(Debug), skip(state,args), fields(args.username = %args.username))]
pub(crate) async fn login(
    State(state): State<SharedState>,
    Json(args): Json<LoginArgs>,
) -> Result<Json<LoginOutput>, AppError> {
    // Check if the user sent the credentials
    if args.username.is_empty() || args.password.is_empty() {
        return Err(AppError(
            StatusCode::INTERNAL_SERVER_ERROR,
            eyre!("empty args").into(),
        ));
    }

    let db = {
        let state_lock = state.read().unwrap();
        state_lock.db.clone()
    };

    let user = authenticate_user(db.clone(), &args.username, &args.password)
        .await
        .map_err(|e| AppError(StatusCode::INTERNAL_SERVER_ERROR, e))?;

    let user = match user {
        Some(user) => user,
        None => {
            return Err(AppError(
                StatusCode::UNAUTHORIZED,
                eyre!("invalid user or password").into(),
            ))
        }
    };

    let access_token = add_access_token(db.clone(), user.id)
        .await
        .map_err(|e| AppError(StatusCode::INTERNAL_SERVER_ERROR, e))?;

    let token = LoginOutput { access_token };

    Ok(Json(token))
}

/// Implement the logout API.
#[tracing::instrument(ret, err(Debug), skip(state,user), fields(user.username = %user.username))]
pub(crate) async fn logout(
    State(state): State<SharedState>,
    user: User,
) -> Result<Json<()>, AppError> {
    let db = {
        let state_lock = state.read().unwrap();
        state_lock.db.clone()
    };

    remove_access_token(
        db.clone(),
        user.current_token
            .expect("user is logged in so they must have a token"),
    )
    .await
    .map_err(|e| AppError(StatusCode::INTERNAL_SERVER_ERROR, e))?;

    Ok(Json(()))
}

/// Implement the unregister API.
#[tracing::instrument(ret, err(Debug), skip(state,user), fields(user.username = %user.username))]
pub(crate) async fn unregister(
    State(state): State<SharedState>,
    user: User,
) -> Result<Json<()>, AppError> {
    let db = {
        let state_lock = state.read().unwrap();
        state_lock.db.clone()
    };

    delete_user(db, user.id)
        .await
        .map_err(|e| AppError(StatusCode::INTERNAL_SERVER_ERROR, e))?;

    Ok(Json(()))
}

/// Implement the create_new_session API.
#[tracing::instrument(ret, err(Debug), skip(state,user), fields(user.username = %user.username))]
pub(crate) async fn create_new_session(
    State(state): State<SharedState>,
    user: User,
    Json(args): Json<CreateNewSessionArgs>,
) -> Result<Json<CreateNewSessionOutput>, AppError> {
    if args.message_count == 0 {
        return Err(AppError(
            StatusCode::INTERNAL_SERVER_ERROR,
            eyre!("invalid message_count").into(),
        ));
    }
    let db = {
        let state_lock = state.read().unwrap();
        state_lock.db.clone()
    };
    for username in &args.usernames {
        if get_user(db.clone(), username)
            .await
            .map_err(|e| AppError(StatusCode::INTERNAL_SERVER_ERROR, e))?
            .is_none()
        {
            return Err(AppError(
                StatusCode::INTERNAL_SERVER_ERROR,
                eyre!("invalid user").into(),
            ));
        }
    }
    // Create new session object.
    let id = Uuid::new_v4();

    let mut state = state.write().unwrap();

    // Save session ID in global state
    for username in &args.usernames {
        state
            .sessions_by_username
            .entry(username.to_string())
            .or_default()
            .insert(id);
    }
    // Create Session object
    let session = Session {
        usernames: args.usernames,
        coordinator: user.username,
        num_signers: args.num_signers,
        message_count: args.message_count,
        state: SessionState::WaitingForCommitments {
            commitments: Default::default(),
        },
        queue: Default::default(),
    };
    // Save session into global state.
    state.sessions.insert(id, session);

    let user = CreateNewSessionOutput { session_id: id };
    Ok(Json(user))
}

/// Implement the create_new_session API.
#[tracing::instrument(ret, err(Debug), skip(state,user), fields(user.username = %user.username))]
pub(crate) async fn list_sessions(
    State(state): State<SharedState>,
    user: User,
) -> Result<Json<ListSessionsOutput>, AppError> {
    let state = state.read().unwrap();

    let session_ids = state
        .sessions_by_username
        .get(&user.username)
        .map(|s| s.iter().cloned().collect())
        .unwrap_or_default();

    Ok(Json(ListSessionsOutput { session_ids }))
}

/// Implement the get_session_info API
#[tracing::instrument(ret, err(Debug), skip(state,user), fields(user.username = %user.username))]
pub(crate) async fn get_session_info(
    State(state): State<SharedState>,
    user: User,
    Json(args): Json<GetSessionInfoArgs>,
) -> Result<Json<GetSessionInfoOutput>, AppError> {
    let state_lock = state.read().unwrap();

    let session = state_lock.sessions.get(&args.session_id).ok_or(AppError(
        StatusCode::NOT_FOUND,
        eyre!("session ID not found").into(),
    ))?;

    Ok(Json(GetSessionInfoOutput {
        num_signers: session.num_signers,
        message_count: session.message_count,
        usernames: session.usernames.clone(),
        coordinator: session.coordinator.clone(),
    }))
}

/// Implement the send API
// TODO: get identifier from channel rather from arguments
#[tracing::instrument(ret, err(Debug), skip(state,user), fields(user.username = %user.username))]
pub(crate) async fn send(
    State(state): State<SharedState>,
    user: User,
    Json(args): Json<SendArgs>,
) -> Result<(), AppError> {
    // Get the mutex lock to read and write from the state
    let mut state_lock = state.write().unwrap();

    let session = state_lock
        .sessions
        .get_mut(&args.session_id)
        .ok_or(AppError(
            StatusCode::NOT_FOUND,
            eyre!("session ID not found").into(),
        ))?;

    let recipients = if args.recipients.is_empty() {
        vec![String::new()]
    } else {
        args.recipients
    };
    for username in &recipients {
        session
            .queue
            .entry(username.clone())
            .or_default()
            .push_back(Msg {
                sender: user.username.clone(),
                msg: args.msg.clone(),
            });
    }

    Ok(())
}

/// Implement the recv API
// TODO: get identifier from channel rather from arguments
#[tracing::instrument(ret, err(Debug), skip(state,user), fields(user.username = %user.username))]
pub(crate) async fn receive(
    State(state): State<SharedState>,
    user: User,
    Json(args): Json<ReceiveArgs>,
) -> Result<Json<ReceiveOutput>, AppError> {
    // Get the mutex lock to read and write from the state
    let mut state_lock = state.write().unwrap();

    let session = state_lock
        .sessions
        .get_mut(&args.session_id)
        .ok_or(AppError(
            StatusCode::NOT_FOUND,
            eyre!("session ID not found").into(),
        ))?;

    let username = if user.username == session.coordinator && args.as_coordinator {
        String::new()
    } else {
        user.username
    };

    let msgs = session
        .queue
        .entry(username.to_string())
        .or_default()
        .drain(..)
        .collect();

    Ok(Json(ReceiveOutput { msgs }))
}

/// Implement the send_commitments API
// TODO: get identifier from channel rather from arguments
#[tracing::instrument(ret, err(Debug), skip(state,user), fields(user.username = %user.username))]
pub(crate) async fn send_commitments(
    State(state): State<SharedState>,
    user: User,
    Json(args): Json<SendCommitmentsArgs>,
) -> Result<(), AppError> {
    // Get the mutex lock to read and write from the state
    let mut state_lock = state.write().unwrap();

    let session = state_lock
        .sessions
        .get_mut(&args.session_id)
        .ok_or(AppError(
            StatusCode::NOT_FOUND,
            eyre!("session ID not found").into(),
        ))?;

    match &mut session.state {
        SessionState::WaitingForCommitments { commitments } => {
            if args.commitments.len() != session.message_count as usize {
                return Err(AppError(
                    StatusCode::INTERNAL_SERVER_ERROR,
                    eyre!("wrong number of commitments").into(),
                ));
            }
            // Add commitment to map.
            // Currently ignores the possibility of overwriting previous values
            // (it seems better to ignore overwrites, which could be caused by
            // poor networking connectivity leading to retries)
            commitments.insert(args.identifier, args.commitments);
            tracing::debug!(
                "added commitments, currently {}/{}",
                commitments.len(),
                session.num_signers
            );
            // If complete, advance to next state
            if commitments.len() == session.num_signers as usize {
                session.state = SessionState::CommitmentsReady {
                    commitments: commitments.clone(),
                }
            }
        }
        _ => {
            return Err(AppError(
                StatusCode::INTERNAL_SERVER_ERROR,
                eyre!("incompatible session state").into(),
            ));
        }
    }
    Ok(())
}

/// Implement the get_commitments API
#[tracing::instrument(ret, err(Debug), skip(state,user), fields(user.username = %user.username))]
pub(crate) async fn get_commitments(
    State(state): State<SharedState>,
    user: User,
    Json(args): Json<GetCommitmentsArgs>,
) -> Result<Json<GetCommitmentsOutput>, AppError> {
    let state_lock = state.read().unwrap();

    let session = state_lock.sessions.get(&args.session_id).ok_or(AppError(
        StatusCode::NOT_FOUND,
        eyre!("session ID not found").into(),
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
                        .map(|(id, c)| (id.clone(), c[i as usize].clone()))
                        .collect()
                })
                .collect(),
        })),
        _ => Err(AppError(
            StatusCode::INTERNAL_SERVER_ERROR,
            eyre!("incompatible session state").into(),
        )),
    }
}

/// Implement the send_signing_package API
#[tracing::instrument(ret, err(Debug), skip(state,user), fields(user.username = %user.username))]
pub(crate) async fn send_signing_package(
    State(state): State<SharedState>,
    user: User,
    Json(args): Json<SendSigningPackageArgs>,
) -> Result<(), AppError> {
    let mut state_lock = state.write().unwrap();

    let session = state_lock
        .sessions
        .get_mut(&args.session_id)
        .ok_or(AppError(
            StatusCode::NOT_FOUND,
            eyre!("session ID not found").into(),
        ))?;

    match &mut session.state {
        SessionState::CommitmentsReady { commitments } => {
            if args.signing_package.len() != session.message_count as usize {
                return Err(AppError(
                    StatusCode::INTERNAL_SERVER_ERROR,
                    eyre!("wrong number of inputs").into(),
                ));
            }
            if args.randomizer.len() != session.message_count as usize
                && !args.randomizer.is_empty()
            {
                return Err(AppError(
                    StatusCode::INTERNAL_SERVER_ERROR,
                    eyre!("wrong number of inputs").into(),
                ));
            }
            session.state = SessionState::WaitingForSignatureShares {
                identifiers: commitments.keys().cloned().collect(),
                signing_package: args.signing_package,
                signature_shares: Default::default(),
                randomizer: args.randomizer,
                aux_msg: args.aux_msg,
            };
        }
        _ => {
            return Err(AppError(
                StatusCode::INTERNAL_SERVER_ERROR,
                eyre!("incompatible session state").into(),
            ));
        }
    }
    Ok(())
}

/// Implement the get_signing_package API
#[tracing::instrument(ret, err(Debug), skip(state,user), fields(user.username = %user.username))]
pub(crate) async fn get_signing_package(
    State(state): State<SharedState>,
    user: User,
    Json(args): Json<GetSigningPackageArgs>,
) -> Result<Json<GetSigningPackageOutput>, AppError> {
    let state_lock = state.read().unwrap();

    let session = state_lock.sessions.get(&args.session_id).ok_or(AppError(
        StatusCode::NOT_FOUND,
        eyre!("session ID not found").into(),
    ))?;

    match &session.state {
        SessionState::WaitingForSignatureShares {
            identifiers: _,
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
            eyre!("incompatible session state").into(),
        )),
    }
}

/// Implement the send_signature_share API
// TODO: get identifier from channel rather from arguments
#[tracing::instrument(ret, err(Debug), skip(state,user), fields(user.username = %user.username))]
pub(crate) async fn send_signature_share(
    State(state): State<SharedState>,
    user: User,
    Json(args): Json<SendSignatureShareArgs>,
) -> Result<(), AppError> {
    let mut state_lock = state.write().unwrap();

    let session = state_lock
        .sessions
        .get_mut(&args.session_id)
        .ok_or(AppError(
            StatusCode::NOT_FOUND,
            eyre!("session ID not found").into(),
        ))?;

    match &mut session.state {
        SessionState::WaitingForSignatureShares {
            identifiers,
            signing_package: _,
            signature_shares,
            randomizer: _,
            aux_msg: _,
        } => {
            if !identifiers.contains(&args.identifier) {
                return Err(AppError(
                    StatusCode::NOT_FOUND,
                    eyre!("invalid identifier").into(),
                ));
            }
            if args.signature_share.len() != session.message_count as usize {
                return Err(AppError(
                    StatusCode::INTERNAL_SERVER_ERROR,
                    eyre!("wrong number of signature shares").into(),
                ));
            }
            // Currently ignoring the possibility of overwriting previous values
            // (it seems better to ignore overwrites, which could be caused by
            // poor networking connectivity leading to retries)
            signature_shares.insert(args.identifier, args.signature_share);
            // If complete, advance to next state
            if signature_shares.keys().cloned().collect::<HashSet<_>>() == *identifiers {
                session.state = SessionState::SignatureSharesReady {
                    signature_shares: signature_shares.clone(),
                };
            }
        }
        _ => {
            return Err(AppError(
                StatusCode::INTERNAL_SERVER_ERROR,
                eyre!("incompatible session state").into(),
            ));
        }
    }
    Ok(())
}

/// Implement the get_signature_shares API
#[tracing::instrument(ret, err(Debug), skip(state,user), fields(user.username = %user.username))]
pub(crate) async fn get_signature_shares(
    State(state): State<SharedState>,
    user: User,
    Json(args): Json<GetSignatureSharesArgs>,
) -> Result<Json<GetSignatureSharesOutput>, AppError> {
    let state_lock = state.read().unwrap();

    let session = state_lock.sessions.get(&args.session_id).ok_or(AppError(
        StatusCode::NOT_FOUND,
        eyre!("session ID not found").into(),
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
                            .map(|(id, s)| (id.clone(), s[i as usize].clone()))
                            .collect()
                    })
                    .collect(),
            }))
        }
        _ => Err(AppError(
            StatusCode::INTERNAL_SERVER_ERROR,
            eyre!("incompatible session state").into(),
        )),
    }
}

/// Implement the close_session API.
#[tracing::instrument(ret, err(Debug), skip(state,user), fields(user.username = %user.username))]
pub(crate) async fn close_session(
    State(state): State<SharedState>,
    user: User,
    Json(args): Json<CloseSessionArgs>,
) -> Result<Json<()>, AppError> {
    let mut state = state.write().unwrap();

    for username in state
        .sessions
        .get(&args.session_id)
        .ok_or(AppError(
            StatusCode::INTERNAL_SERVER_ERROR,
            eyre!("invalid session ID").into(),
        ))?
        .usernames
        .clone()
    {
        if let Some(v) = state.sessions_by_username.get_mut(&username) {
            v.remove(&args.session_id);
        }
    }
    state.sessions.remove(&args.session_id);
    Ok(Json(()))
}
